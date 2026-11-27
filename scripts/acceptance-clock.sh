# shellcheck shell=sh
# Sourced by scripts/acceptance-quickstart.sh: the host's clock set forty
# days ahead and put right again under the services as they run, as on a
# host that starts with a wrong clock before its time server answers. The
# receiver and the collector remove what is old by a run time of their own
# (crates/core/src/run_time.rs): no event and no sample may go, and what the
# receiver wrote of its absence by the clock ahead must not stay. A virtual
# machine only: a container has the clock of the host it runs on. It uses the
# helpers of scripts/acceptance-lib.sh.

events_db=/var/lib/garrison/ingest/events.sqlite
status_db=/var/lib/garrison/collector/status.sqlite

clock_ahead_and_back() {
    step "The clock forty days ahead, as on a host that starts before its time server answers, and back"
    # The receiver cleans up every ten minutes, and at once after a thousand
    # events: this run sends them, signed as Stalwart signs its batches.
    inside_input 'cat > /usr/local/bin/acceptance-events && chmod 755 /usr/local/bin/acceptance-events' <<'EVENTS'
#!/bin/sh
# acceptance-events NAME: a thousand events NAME-1 to NAME-1000, dated by this
# host's clock; prints how many of them the receiver stored.
key=$(cat /etc/garrison/credentials/webhook-signature-key)
at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
events=$(seq 1000 |
    sed "s/.*/{\"id\": \"$1-&\", \"createdAt\": \"$at\", \"type\": \"auth.failed\", \"data\": {}}/" | paste -sd, -)
body="{\"events\": [$events]}"
signature=$(printf %s "$body" | openssl dgst -sha256 -hmac "$key" -binary | base64)
printf %s "$body" | curl -s -m 20 -H "Content-Type: application/json" -H "X-Signature: $signature" \
    --data-binary @- http://127.0.0.1:8094/webhook | sed -n 's/.*"stored": *\([0-9]*\).*/\1/p'
EVENTS
    # Nothing sets the clock but this run.
    inside 'timedatectl set-ntp false 2>/dev/null || true
        systemctl stop chronyd.service chrony.service systemd-timesyncd.service 2>/dev/null || true'
    once "before: a collection run, so that the metric history has its samples" \
        'acceptance-run garrison-collect.service'
    # What is dated up to now, by the host's own clock, is from before.
    clock_right=$(inside 'date +%s')
    events_before=$(inside "sqlite3 $events_db 'SELECT count(*) FROM events WHERE created_at <= $clock_right'")
    samples_before=$(inside "sqlite3 $status_db 'SELECT count(*) FROM samples WHERE ts <= $clock_right'")
    echo "      before: $events_before events, $samples_before samples of the metric history"

    inside "date -s @$((clock_right + 40 * 86400)) >/dev/null"
    once "the receiver starts with the clock forty days ahead" 'systemctl restart garrison-ingest.service' \
        'curl -s -m 5 -o /dev/null http://127.0.0.1:8094/health'
    once "a thousand events arrive there, after which the receiver cleans up" \
        'test "$(acceptance-events ahead)" = 1000'
    once "a collection run at that time ends in order" 'acceptance-run garrison-collect.service'
    # The clean-up follows the batch within a moment.
    inside 'sleep 5'
    clock_kept "while the clock is ahead"
    check "by that clock the receiver was away for forty days, and the history says so for now" \
        "test \$(sqlite3 $events_db \"SELECT count(*) FROM gaps WHERE reason = 'receiver-offline'\") = 1"
    check "the receiver's journal says that its clock is ahead of its run time" \
        'journalctl -u garrison-ingest.service -b --no-pager -o cat |
            grep -q "more than ten minutes after its own run time"'
    check "the collector's journal says so of its run" \
        'journalctl -u garrison-collect.service -b --no-pager -o cat |
            grep -q "more than ten minutes after the collector.s own run time"'

    # This host's clock is the right one.
    inside "date -s @$(date +%s) >/dev/null"
    once "the clock is put right, and a thousand events arrive, after which the receiver cleans up" \
        'test "$(acceptance-events back)" = 1000'
    once "a collection run at the right time ends in order" 'acceptance-run garrison-collect.service'
    inside 'sleep 5'
    clock_kept "after the clock is put right"
    check "the start at the clock ahead left no window of lost events" \
        "test \$(sqlite3 $events_db \"SELECT count(*) FROM gaps WHERE reason = 'receiver-offline'\") = 0"
    check "the receiver's journal says that the clock is back" \
        'journalctl -u garrison-ingest.service -b --no-pager -o cat |
            grep -q "The clock is back within ten minutes of the receiver.s run time"'
    check "the collector's journal says so too" \
        'journalctl -u garrison-collect.service -b --no-pager -o cat |
            grep -q "The clock is back within ten minutes of the collector.s run time"'
    check "every service runs" \
        'systemctl is-active --quiet garrison-web.service garrison-ingest.service garrison-broker.socket'
}

# clock_kept WHEN: every event and every sample from before the clock went
# ahead is there.
clock_kept() {
    check "no event from before went $1" \
        "kept=\$(sqlite3 $events_db 'SELECT count(*) FROM events WHERE created_at <= $clock_right') &&
            echo \"\$kept of $events_before events\" && test \$kept -ge $events_before"
    check "no sample of the metric history went $1" \
        "kept=\$(sqlite3 $status_db 'SELECT count(*) FROM samples WHERE ts <= $clock_right') &&
            echo \"\$kept of $samples_before samples\" && test \$kept -ge $samples_before"
}
