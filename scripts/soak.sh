#!/bin/sh
# Garrison under steady load for a while: signed event batches into the
# receiver, the collector on its timer, and every five minutes a sample of the
# services' memory and restarts, the stored events and the database sizes.
#
#   [HOST=vm] [DISTRO=debian-13] [SOAK_MINUTES=120] [SOAK_RATE=40] \
#       scripts/soak.sh dist/previous-x86_64.tar.gz dist/garrison-<version>-x86_64.tar.gz
#
# Only the second archive is soaked; the first is installed and upgraded from,
# as in production. SOAK_RATE is events per second; the load reaches about nine
# tenths of it. The receiver's limit is set to 200,000 events here (its default
# is a million), which the events pass after about 90 minutes at the defaults,
# so the limit is applied under load as well.
# Accepted at the end: no service restarted or logged an error, the receiver
# refused no batch, every accepted event is stored or lies in a gap the receiver
# recorded when it applied its limit, the events stayed within that limit, the
# database file stopped growing once the limit applied, the collector kept
# running and no service's memory grew by more than a fixed margin after
# warm-up. The web service only answers the health checks: its API needs a
# session. The host and its options: scripts/acceptance-lib.sh.
set -eu

previous=$1
release=$2
minutes=${SOAK_MINUTES:-120}
rate=${SOAK_RATE:-40}
per=$((rate / 2))
if [ "$per" -lt 1 ]; then
    echo "SOAK_RATE must be at least 2" >&2
    exit 2
fi
# Growth after warm-up a service may show, in KiB. The names start with soak_
# because the sourced libraries set globals of their own (vm-lib's limit).
soak_margin=65536
# The receiver's limit in this soak and how often it applies it at the latest (crates/ingest).
soak_limit=200000
soak_every=600
# Growth of the database file once the limit applies, in percent.
soak_growth=25
# shellcheck source=scripts/acceptance-lib.sh
. "$(dirname "$0")/acceptance-lib.sh"

# `verdict DESCRIPTION TEST...` passes when the test succeeds here.
verdict() {
    description=$1
    shift
    if "$@"; then
        echo "ok    $description"
    else
        echo "FAIL  $description"
        exit 1
    fi
}

start_host
install_previous
inside "printf '[ingest]\\nmax_events = %s\\n' $soak_limit >> /etc/garrison/garrison.toml"
installer '/root/release/bin/garrison install'
services "upgraded"

step "Loading the receiver with $rate events a second for $minutes minutes"
# A batch every half second; each line of /root/sent.log is
# "batch created-at HTTP-status stored".
inside_input 'cat > /root/load.sh' <<'LOAD'
key=$(cat /etc/garrison/credentials/webhook-signature-key)
end=$(( $(date +%s) + $1 * 60 )); batch=0
while [ "$(date +%s)" -lt "$end" ]; do
    batch=$((batch + 1)); now=$(date -u '+%s %Y-%m-%dT%H:%M:%SZ'); events=""
    for n in $(seq "$2"); do
        events="$events{\"id\": \"soak-$batch-$n\", \"createdAt\": \"${now#* }\", \"type\": \"auth.failed\", \"data\": {}},"
    done
    body="{\"events\": [${events%,}]}"
    signature=$(printf %s "$body" | openssl dgst -sha256 -hmac "$key" -binary | base64)
    answer=$(curl -s -m 10 -w ' %{http_code}' -H "Content-Type: application/json" \
        -H "X-Signature: $signature" --data-binary "$body" http://127.0.0.1:8094/webhook)
    stored=$(printf %s "$answer" | sed -n 's/.*"stored": *\([0-9]*\).*/\1/p')
    echo "$batch ${now% *} ${answer##* } ${stored:-0}" >> /root/sent.log
    sleep 0.5
done
LOAD
before=$(events)
collected=$(inside 'sqlite3 /var/lib/garrison/collector/status.sqlite "SELECT max(id) FROM snapshots"')
inside "systemd-run --quiet --unit=soak-load sh /root/load.sh $minutes $per"
check "the receiver accepts the load" 'grep -q " 200 " /root/sent.log'

# Resident memory in KiB and restarts of each service, then the stored events
# and the bytes of the event database (rollback journal: the web service reads it).
sample() {
    inside 'for unit in garrison-web garrison-ingest garrison-broker; do
        pid=$(systemctl show -p MainPID --value $unit.service)
        rss=$(awk "/^VmRSS/ {print \$2}" /proc/$pid/status 2>/dev/null)
        printf "%s=%s/%s " $unit "${rss:-0}" "$(systemctl show -p NRestarts --value $unit.service)"
    done
    db=/var/lib/garrison/ingest/events.sqlite
    printf "events=%s database=%s\n" "$(sqlite3 $db "SELECT count(*) FROM events")" "$(stat -c %s $db)"'
}
# `value NAME LINE` is the number after NAME= in a sample, `restarts UNIT LINE` the one after its slash.
value() { printf '%s\n' "$2" | tr ' ' '\n' | sed -n "s|^$1=\([0-9]*\).*|\1|p"; }
restarts() { printf '%s\n' "$2" | tr ' ' '\n' | sed -n "s|^$1=[0-9]*/\([0-9]*\)$|\1|p"; }

echo "      minute  web=rss/restarts ingest=... broker=... (KiB), events, database bytes"
minute=0
warm=
most_events=0
# The database's size when the limit first applied, and its largest size after.
at_limit=
largest=0
while [ "$minute" -lt "$minutes" ]; do
    sleep 300
    minute=$((minute + 5))
    line=$(sample)
    echo "      $minute  $line"
    if [ "$minute" -eq 15 ] || [ -z "$warm" ]; then
        warm=$line
    fi
    if [ "$(value events "$line")" -gt "$most_events" ]; then
        most_events=$(value events "$line")
    fi
    if [ -z "$at_limit" ] && [ "$(value events "$line")" -ge "$soak_limit" ]; then
        at_limit=$(value database "$line")
    fi
    if [ -n "$at_limit" ] && [ "$(value database "$line")" -gt "$largest" ]; then
        largest=$(value database "$line")
    fi
done
inside 'while systemctl is-active --quiet soak-load.service; do sleep 5; done'
last=$(sample)

step "After $minutes minutes"
inside_input 'cat > /root/account.sh' <<'ACCOUNT'
# "accepted kept dropped lost refused skipped windows": an accepted batch must
# be kept in full, or have its time inside the window that the receiver
# recorded for what its limit removed.
db=/var/lib/garrison/ingest/events.sqlite
sqlite3 -separator ' ' $db "SELECT substr(event_id, 6, instr(substr(event_id, 6), '-') - 1), count(*)
    FROM events WHERE event_id GLOB 'soak-*' GROUP BY 1" > /root/kept.txt
sqlite3 -separator ' ' $db "SELECT start_at, end_at FROM gaps WHERE reason LIKE 'capacity-%'" > /root/gaps.txt
awk -v per="$1" '
    FILENAME == ARGV[1] { kept[$1] = $2; next }
    FILENAME == ARGV[2] { from[++gaps] = $1; to[gaps] = $2; next }
    $3 != 200 { refused++; next }
    {
        accepted += per; have = kept[$1] + 0; stored += have; skipped += per - $4
        if (have < per) {
            covered = 0
            for (i = 1; i <= gaps; i++) if ($2 >= from[i] && $2 <= to[i]) covered = 1
            if (covered) dropped += per - have; else lost += per - have
        }
    }
    END { print accepted + 0, stored + 0, dropped + 0, lost + 0, refused + 0, skipped + 0, gaps + 0 }
' /root/kept.txt /root/gaps.txt /root/sent.log
ACCOUNT
result=$(inside "sh /root/account.sh $per")
read -r accepted stored dropped lost refused skipped gaps <<EOF
$result
EOF
echo "      $accepted events accepted ($((accepted / (minutes * 60))) a second), $stored kept," \
    "$dropped removed by the limit, $lost lost; $refused batches refused, $skipped events skipped"
verdict "the receiver refused no batch" [ "$refused" -eq 0 ]
verdict "the receiver stored every event of every batch" [ "$skipped" -eq 0 ]
verdict "no accepted event was lost: each is kept or inside the limit's recorded window" [ "$lost" -eq 0 ]
if [ $((before + accepted)) -gt $((soak_limit + rate * soak_every)) ]; then
    verdict "the receiver applied its limit of $soak_limit events under load and recorded it" [ "$gaps" -gt 0 ]
    verdict "what a limit removed is one recorded window, however often it removed ($gaps)" [ "$gaps" -le 2 ]
    verdict "the limit dropped the oldest events ($dropped)" [ "$dropped" -gt 0 ]
fi
verdict "the stored events stayed within the limit (at most $most_events)" \
    [ "$most_events" -le $((soak_limit + rate * soak_every + 1000)) ]
if [ -n "$at_limit" ]; then
    verdict "the database stopped growing once the limit applied ($at_limit -> at most $largest bytes)" \
        [ $((largest * 100)) -le $((at_limit * (100 + soak_growth))) ]
fi
now=$(inside 'sqlite3 /var/lib/garrison/collector/status.sqlite "SELECT max(id) FROM snapshots"')
verdict "the collector kept collecting ($((now - collected)) runs)" [ $((now - collected)) -ge $((minutes / 2)) ]
check "the collector's last run succeeded" \
    'test "$(systemctl show -p Result --value garrison-collect.service)" = success'
for unit in garrison-web garrison-ingest garrison-broker; do
    first=$(value $unit "$warm")
    rss=$(value $unit "$last")
    verdict "$unit did not restart" [ "$(restarts $unit "$last")" = 0 ]
    verdict "$unit stayed within $soak_margin KiB of its warm memory ($first -> $rss KiB)" \
        [ $((rss - first)) -le "$soak_margin" ]
done
errors=$(inside 'journalctl -u "garrison-*" -p err -b --no-pager -q')
if [ -n "$errors" ]; then
    printf '%s\n' "$errors" | tail -n 20
fi
verdict "no Garrison service logged an error" [ -z "$errors" ]
services "after the soak"

step "Accepted: $minutes minutes at $rate events a second without a restart, a loss or a leak"
