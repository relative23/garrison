#!/bin/sh
# Install, upgrade and roll back Garrison on a disposable host with
# systemd and polkit, and check every step.
#
#   [DISTRO=debian-13] [CLAMAV=1] scripts/acceptance.sh \
#       dist/previous-x86_64.tar.gz dist/garrison-<version>-x86_64.tar.gz
#
# The first archive is the release running before the upgrade, the second
# the one under test; their versions must differ. The host and its options:
# scripts/acceptance-lib.sh. The installer's failure paths:
# scripts/acceptance-failures.sh.
set -eu

previous=$1
release=$2
# shellcheck source=scripts/acceptance-lib.sh
. "$(dirname "$0")/acceptance-lib.sh"

start_host
install_previous

step "Detecting what the host runs"
check "detect names the distribution" "/root/release/bin/garrison detect | head -n 1 | grep -q '$expected'"
# Its provider entries, in place of the configured ones, must pass check-config.
check "the provider entries detect prints pass check-config" '
    { sed "/^\[\[providers\]\]/,\$d" /etc/garrison/garrison.toml
      /root/release/bin/garrison detect --format toml; } > /root/detected.toml &&
    /root/release/bin/garrison --config /root/detected.toml check-config'
if [ -n "${CLAMAV:-}" ]; then
    check "detect finds the ClamAV configuration" \
        "/root/release/bin/garrison detect | grep -q 'configuration $clamd_config'"
fi

services previous
before=$(events)
old=$(inside 'cat /root/previous/VERSION')
new=$(inside 'cat /root/release/VERSION')

step "Upgrading to the release under test"
upgrade=$(mktemp)
if ! installer '/root/release/bin/garrison install' >"$upgrade" 2>&1; then
    cat "$upgrade"
    echo "FAIL  the upgrade to the release under test"
    exit 1
fi
cat "$upgrade"
names "current is the release under test" current "$new"
names "previous is the release it upgraded from" previous "$old"
check "the event history survived the upgrade" "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -ge $before"
services upgraded
# Laid out like Stalwart's host: the interface under /admin/, the root leads there.
check "the root leads to the interface" 'curl -s -D - -o /dev/null http://127.0.0.1:8091/ | tr -d "\r" | grep -q -i "^location: /admin/$"'
check "the interface answers under /admin/" 'curl -sf http://127.0.0.1:8091/admin/ | grep -q "<title>Garrison</title>"'
# One maintenance action, as the web service would ask for it: the broker
# checks the token with the stub, starts the unit through polkit and records
# the job. Jobs settle for 30 seconds, so it is submitted once and then polled.
inside 'printf "%s\n" "{\"op\": \"submit\", \"token\": \"acceptance-token-0123456789abcdef\", \"action\": \"run_check\", \"requestId\": \"$(cat /proc/sys/kernel/random/uuid)\", \"confirmation\": \"RUN CHECK\"}" |
        timeout 10 runuser -u garrison -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock |
        sed -n "s/.*\"id\":\"\([0-9a-f]\{32\}\)\".*/\1/p" > /root/job-id'
check "upgraded: a configured action runs through the broker and polkit" '
    printf "%s\n" "{\"op\": \"job\", \"token\": \"acceptance-token-0123456789abcdef\", \"id\": \"$(cat /root/job-id)\"}" |
        timeout 10 runuser -u garrison -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock |
        grep -q "\"status\":\"succeeded\""'
# The rule lets the broker's user do what the actions name and nothing
# else: not another operation on the action's unit, not another unit. The
# refusal must be polkit's (systemd's default asks for an administrator, and
# --no-ask-password turns that into a refusal), not a unit that is missing.
check "polkit lets the broker's user start the action's unit" \
    'runuser -u garrison-broker -- /usr/bin/systemctl --no-ask-password start acceptance-check.service'
inside 'systemctl show -p MainPID --value garrison-web.service > /root/web-pid'
for refused in "stop acceptance-check.service" "restart garrison-web.service"; do
    check "polkit refuses the broker's user: systemctl $refused" "
        ! runuser -u garrison-broker -- /usr/bin/systemctl --no-ask-password $refused 2>/root/polkit.log &&
            grep -q 'Interactive authentication required' /root/polkit.log"
done
check "garrison-web.service ran on through the refused restart" \
    'test "$(systemctl show -p MainPID --value garrison-web.service)" = "$(cat /root/web-pid)"'
# The socket's group lets the collector and the receiver connect; the broker
# answers only the web service's user, and closes the others' connections
# unanswered. A user outside the group cannot connect at all.
asked='{"op": "catalog", "token": "acceptance-token-0123456789abcdef"}'
check "the broker answers no other user of the group garrison, and says so" "
    test -z \"\$(printf '%s\n' '$asked' |
        timeout 10 runuser -u garrison-collector -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock 2>/dev/null)\" &&
    journalctl -u garrison-broker.service --no-pager | grep -q 'Rejected a broker connection from an unexpected user'"
check "a user outside the group garrison cannot reach the broker" "
    printf '%s\n' '$asked' |
        timeout 10 runuser -u nobody -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock 2>&1 |
        grep -q 'Permission denied'"

step "The collector's files where setup made none"
# Where Stalwart's exporter is another's, setup writes no metrics credential,
# and only a list of Spamhaus' Data Query Service needs a key. The collector's
# unit loads both, and systemd starts no unit whose credential file is missing.
credentials=/etc/garrison/credentials
inside "rm -f $credentials/metrics-credential $credentials/spamhaus-dqs-key"
check "systemd starts no collection run whose credential file is missing" "
    ! systemctl start garrison-collect.service 2>/dev/null &&
        systemctl status garrison-collect.service --no-pager 2>&1 |
            grep -E -q -i '243/CREDENTIALS|set up credentials'"
again=$(mktemp)
if ! installer '/root/release/bin/garrison install' >"$again" 2>&1; then
    cat "$again"
    echo "FAIL  the installer runs again"
    exit 1
fi
rm -f "$again"
# From here on every run reads the files the installer kept; a run of the
# timer's from before may still end within the second before.
since=$(inside 'sleep 1 && date +%s')
check "after the installer, a collection run starts" 'systemctl start garrison-collect.service'
check "the installer keeps both files, empty and root's alone" "
    for name in metrics-credential spamhaus-dqs-key; do
        test -f $credentials/\$name && test ! -s $credentials/\$name &&
            test \"\$(stat -c %U:%a $credentials/\$name)\" = root:600 || exit 1
    done"
check "the collector reads an empty metrics credential as none" \
    "! journalctl -u garrison-collect.service --since @$since --no-pager |
        grep -q 'no scrape credential'"
# doctor names a missing file with a command that makes it.
inside "rm -f $credentials/metrics-credential"
check "doctor names the missing metrics credential" \
    "garrison doctor > /root/doctor.log 2>&1; grep -q 'FAIL  metrics-credential is missing' /root/doctor.log"
inside "sed -n '/FAIL  metrics-credential is missing/{n;s/^.*: //;p;}' /root/doctor.log > /root/doctor-fix.sh &&
    grep -q /etc/garrison/credentials/metrics-credential /root/doctor-fix.sh && sh -e /root/doctor-fix.sh"
check "the file doctor's command makes lets a collection run start" 'systemctl start garrison-collect.service'
check "doctor finds both empty files in order where nothing reads them" "
    garrison doctor > /root/doctor.log 2>&1;
    ! grep -E -q 'FAIL  .*(metrics-credential|spamhaus-dqs-key)' /root/doctor.log &&
        grep -q 'ok    metrics-credential is empty' /root/doctor.log &&
        grep -q 'ok    spamhaus-dqs-key is empty' /root/doctor.log"

step "Key files that are there but empty"
# An empty key file is no key, as a missing one is not, but systemd starts
# the unit with it: each service says so with what makes the key, doctor
# fails the file, and the collector's journal says it once, not in every run.
# The stand-in for Stalwart cannot run setup, so a copy puts each key back.
keys='collector-native-key broker-native-key webhook-signature-key'
made='run .garrison stalwart setup., which makes it'
inside "for key in $keys; do cp -p $credentials/\$key /root/\$key.kept && : > $credentials/\$key; done"
since=$(inside 'sleep 1 && date +%s')
run_collector='systemctl reset-failed garrison-collect.service; systemctl start garrison-collect.service'
check "with an empty key file collection runs start" "$run_collector && $run_collector"
check "the collector's journal says once that its key file is empty, and what makes a key" "
    test \"\$(journalctl -u garrison-collect.service --since @$since --no-pager | grep -c \
        'The collector has no API key for Stalwart: Protected file is empty: /run/credentials/garrison-collect.service/collector-native-key; $made')\" = 1"
check "doctor fails each empty key file with the setup that makes it" "
    garrison doctor > /root/doctor.log 2>&1;
    for key in $keys; do
        grep -A 1 \"FAIL  \$key is empty, so \" /root/doctor.log | grep -q 'Run .garrison stalwart setup., which makes it' || exit 1
    done"
check "the receiver does not start with an empty signature key, and says why" "
    ! systemctl restart garrison-ingest.service 2>/dev/null &&
        journalctl -u garrison-ingest.service --since @$since --no-pager | grep -q \
            'signature key: Protected file is empty: /run/credentials/garrison-ingest.service/webhook-signature-key; $made'"
catalog_ask='printf "%s\n" "{\"op\": \"catalog\", \"token\": \"acceptance-token-0123456789abcdef\"}" |
    timeout 10 runuser -u garrison -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock'
check "the broker checks no rights with an empty key, and its journal says why" "
    systemctl restart garrison-broker.service && $catalog_ask | grep -q 'not set up to check access rights' &&
        journalctl -u garrison-broker.service --since @$since --no-pager | grep -q \
            \"the broker's API key: Protected file is empty: /run/credentials/garrison-broker.service/broker-native-key; $made\""
inside "for key in $keys; do cp -p /root/\$key.kept $credentials/\$key; done && systemctl restart garrison-broker.service"
check "with the keys back the receiver, which systemd starts again meanwhile, runs" '
    for attempt in $(seq 20); do systemctl is-active --quiet garrison-ingest.service && exit 0; sleep 1; done; exit 1'
check "with the keys back the collector's journal says once that it has its key again" "
    $run_collector && $run_collector &&
        test \"\$(journalctl -u garrison-collect.service --since @$since --no-pager |
            grep -c 'The collector has an API key for Stalwart again')\" = 1"
check "doctor finds the key files in order again" "
    garrison doctor > /root/doctor.log 2>&1;
    for key in $keys; do grep -q \"ok    \$key is private\" /root/doctor.log || exit 1; done"
services "with the key files back"
# The step started the broker and the receiver on purpose more often than
# systemd allows in ten seconds, which would count against the steps after it.
inside 'systemctl reset-failed garrison-broker.service garrison-ingest.service'

step "The key of Spamhaus' Data Query Service from its file"
# A stand-in resolver on 127.0.0.1:5353 that knows the mail host, answers no
# name of the service and logs every question; it asks nothing of anyone.
# The key is made up for the run: no real key, and no question to Spamhaus.
case $distro in
    debian-* | ubuntu-*) resolver='apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive
        apt-get install -y -q --no-install-recommends dnsmasq-base >/dev/null' ;;
    opensuse-*) resolver='zypper -n -q install dnsmasq >/dev/null' ;;
    *) resolver='dnf -y -q install dnsmasq >/dev/null' ;;
esac
inside "$resolver && systemd-run --quiet --unit=acceptance-dns dnsmasq --keep-in-foreground --user=root \
    --no-resolv --no-hosts --listen-address=127.0.0.1 --port=5353 --bind-interfaces \
    --log-queries --log-facility=- --host-record=mail.example.test,192.0.2.25 \
    --local=/example.test/ --local=/dq.spamhaus.net/"
key=garrisonacceptancenotakey
inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.before-dqs &&
    printf "\n[[providers]]\ntype = \"reputation\"\nresolver = \"127.0.0.1:5353\"\nhosts = [\"mail.example.test\"]\nlists = [\"zen.dq.spamhaus.net\"]\nlists_ipv6 = []\n" \
        >> /etc/garrison/garrison.toml'
check "check-config refuses a list written without its key while collector.dqs_key is unset" \
    '! garrison check-config >/root/check.log 2>&1 && grep -q "written without its key" /root/check.log'
inside 'printf "\n[collector]\ndqs_key = \"credential:spamhaus-dqs-key\"\n" >> /etc/garrison/garrison.toml'
check "check-config takes it with collector.dqs_key" 'garrison check-config >/dev/null'
# One collection run each; a check repeats only its look at what the run left.
collect='systemctl reset-failed garrison-collect.service; systemctl start garrison-collect.service'
# The card's words where a check fails, and the resolver's questions.
card='sqlite3 /var/lib/garrison/collector/status.sqlite "SELECT document FROM snapshots ORDER BY id DESC LIMIT 1" |
    tee /root/latest.json | tr "[]" "\n\n" | grep -E "Data Query|could be asked|dq\.spamhaus" | head -n 4'
asked="journalctl -u acceptance-dns --no-pager | grep 'query\[' | tail -n 6"
check "with an empty key file a collection run starts" "$collect"
check "with an empty key file the list is not asked, and the card says why" "
    $card; $asked; grep -q 'spamhaus-dqs-key is empty' /root/latest.json &&
        ! journalctl -u acceptance-dns --no-pager | grep -q 'query\[.*dq\.spamhaus\.net'"
inside "printf '%s\n' $key > $credentials/spamhaus-dqs-key"
check "with a key in the file a collection run starts" "$collect"
check "with a key in the file the list is asked with it" "
    $card; $asked; journalctl -u acceptance-dns --no-pager | grep -q 'query\[A\] .*\.$key\.zen\.dq\.spamhaus\.net' &&
        ! grep -q 'spamhaus-dqs-key is empty' /root/latest.json"
check "the key is nowhere but in the question" "
    ! grep -a -q $key /var/lib/garrison/collector/status.sqlite* &&
        ! journalctl -u garrison-collect.service --no-pager | grep -q $key"
inside "systemctl stop acceptance-dns && : > $credentials/spamhaus-dqs-key &&
    cp -p /root/garrison.toml.before-dqs /etc/garrison/garrison.toml"

step "The kernels that the restart card compares"
# A kernel newer than the one that runs, as an update installs one: on the
# RHEL family, which writes no /run/reboot-required, only that shows that a
# restart is due. Its folder in /lib/modules with its modules.dep is all the
# check reads of a kernel; the step removes it again. The card is read from
# the newest snapshot.
inside_input 'cat > /root/restart-card.sh' <<'SQL'
sqlite3 /var/lib/garrison/collector/status.sqlite "SELECT value FROM snapshots,
    json_each(document, '\$.observations') WHERE snapshots.id = (SELECT max(id) FROM snapshots)
    AND json_extract(value, '\$.id') = 'host.restart'" > /root/restart.json
cat /root/restart.json
SQL
# It is of the running kernel's flavor, as the check compares only those:
# the name from the first hyphen before a letter (-amd64, -generic), or else
# from the last plus (+debug). In a container that is the host's kernel.
flavor=$(inside 'uname -r' | awk '{
    if (match($0, /-[A-Za-z]/)) print substr($0, RSTART)
    else if (match($0, /[+][^+]*$/)) print substr($0, RSTART)
}')
newer=99.0.0$flavor
inside "mkdir -p /lib/modules/$newer && : > /lib/modules/$newer/modules.dep"
check "with a newer kernel installed a collection run starts" "$collect"
check "the restart card names the newer kernel and says that a restart is due" "
    sh /root/restart-card.sh && grep -q '$newer' /root/restart.json &&
        grep -q '\"state\":\"warning\"' /root/restart.json"
# A unit that hides the kernels, as an operator's own drop-in may, leaves
# the card Unknown with the reason, never in order.
dropin=/etc/systemd/system/garrison-collect.service.d
inside "mkdir -p $dropin && printf '[Service]\nProtectKernelModules=true\n' > $dropin/kernels.conf &&
    systemctl daemon-reload"
check "with the kernels hidden a collection run starts" "$collect"
check "with the kernels hidden the restart card says that it cannot read them" "
    sh /root/restart-card.sh &&
        grep -q 'The installed kernels in /lib/modules could not be read' /root/restart.json &&
        grep -q '\"state\":\"unknown\"' /root/restart.json"
inside "rm $dropin/kernels.conf && rm -r /lib/modules/$newer && systemctl daemon-reload"
check "without the newer kernel a collection run starts" "$collect"
check "the restart card no longer names the newer kernel" \
    "sh /root/restart-card.sh && ! grep -q '$newer' /root/restart.json"

step "Making room in a full audit, as operations.md says"
# The audit as it stands an hour later, filled up: the jobs so far have
# settled, and records of a finished check make up the 1000.
inside_input 'cat > /root/fill-audit.sql' <<'SQL'
UPDATE jobs SET created_at = created_at - 3600, started_at = started_at - 3600,
                finished_at = finished_at - 3600;
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1000)
INSERT INTO jobs(id, action_id, actor, actor_email, request_id, status, created_at,
                 started_at, finished_at, message, may_still_run)
SELECT lower(hex(randomblob(16))), 'run_check', 'acceptance', 'acceptance@example.test',
       lower(hex(randomblob(16))), 'succeeded', strftime('%s', 'now') - 3600,
       strftime('%s', 'now') - 3600, strftime('%s', 'now') - 3600, 'Filled for the test', 0
FROM n LIMIT (SELECT 1000 - count(*) FROM jobs);
SQL
inside 'systemctl stop garrison-broker.socket garrison-broker.service &&
    runuser -u garrison-broker -- sqlite3 /var/lib/garrison/broker/jobs.sqlite < /root/fill-audit.sql &&
    systemctl start garrison-broker.socket'
submit='printf "%s\n" "{\"op\": \"submit\", \"token\": \"acceptance-token-0123456789abcdef\", \"action\": \"run_check\", \"requestId\": \"$(cat /proc/sys/kernel/random/uuid)\", \"confirmation\": \"RUN CHECK\"}" |
    timeout 10 runuser -u garrison -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock'
check "an action is refused while the audit holds 1000 records" "$submit | grep -q 'Audit capacity reached'"
inside 'systemctl stop garrison-broker.socket garrison-broker.service &&
    mkdir -p /root/old-audit &&
    for file in /var/lib/garrison/broker/jobs.sqlite /var/lib/garrison/broker/jobs.sqlite-wal /var/lib/garrison/broker/jobs.sqlite-shm; do
        if [ -e "$file" ]; then mv "$file" /root/old-audit/; fi
    done &&
    systemctl start garrison-broker.socket'
inside "$submit | sed -n 's/.*\"id\":\"\\([0-9a-f]\\{32\\}\\)\".*/\\1/p' > /root/job-id"
check "with the audit moved away, the action runs and a new audit holds it" '
    printf "%s\n" "{\"op\": \"job\", \"token\": \"acceptance-token-0123456789abcdef\", \"id\": \"$(cat /root/job-id)\"}" |
        timeout 10 runuser -u garrison -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock |
        grep -q "\"status\":\"succeeded\""'
check "the moved audit keeps its records" \
    'test "$(sqlite3 /root/old-audit/jobs.sqlite "SELECT count(*) FROM jobs")" -ge 1000'

step "Choosing modules"
inside '/opt/garrison/current/bin/garrison --config /etc/garrison/garrison.toml modules --set dns_tls --adopt --yes'
# Garrison's own units are not all configured here, so detect adds them.
check "modules adds the provider entries detect found" 'grep -q "^# Added by .garrison modules." /etc/garrison/garrison.toml'
catalog='printf "%s\n" "{\"op\": \"catalog\", \"token\": \"acceptance-token-0123456789abcdef\"}" |
    timeout 10 runuser -u garrison -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock'
check "without the maintenance module the broker offers no action" "$catalog | grep -E -q '\"actions\": ?\\[\\]'"
# A previous release that refuses the setting must not be switched to: the
# rollback stops before it changes anything, even with --restore-state.
if inside '/root/previous/bin/garrison --config /etc/garrison/garrison.toml check-config' >/dev/null 2>&1; then
    echo "skip  the previous release loads the modules setting, so no rollback is refused"
else
    answer=$(mktemp)
    if installer '/opt/garrison/current/bin/garrison install --rollback --restore-state' >"$answer" 2>&1 ||
        ! grep -q "cannot load /etc/garrison/garrison.toml" "$answer"; then
        cat "$answer"
        echo "FAIL  a rollback to a release that cannot load the configuration is refused"
        exit 1
    fi
    echo "ok    a rollback to a release that cannot load the configuration is refused"
    rm -f "$answer"
    names "current is still the release under test" current "$new"
    names "previous is still the release before it" previous "$old"
fi
services "kept with modules chosen"
inside 'mv /etc/garrison/garrison.toml.previous /etc/garrison/garrison.toml &&
        systemctl try-restart garrison-broker.service garrison-web.service'
check "with every module back the broker offers its action again" "$catalog | grep -q '\"run_check\"'"

step "Rolling back to the previous release"
answer=$(mktemp)
refused=
if installer '/opt/garrison/current/bin/garrison install --rollback' >"$answer" 2>&1; then
    names "current is the previous release" current "$old"
    names "previous is the release it rolled back from" previous "$new"
    services "rolled back"
else
    # Across a schema change the previous release cannot read the data, so the
    # rollback must stop before it changes anything and name --restore-state.
    if ! grep -q -- "--restore-state" "$answer"; then
        cat "$answer"
        echo "FAIL  a refused rollback names --restore-state"
        exit 1
    fi
    echo "ok    a rollback across a schema change is refused"
    refused=1
    names "current is still the release under test" current "$new"
    names "previous is still the release before it" previous "$old"
    services "kept after the refused rollback"
fi
rm -f "$answer"
# The upgrade's last line names the rollback that works: --restore-state
# exactly when a schema changed and the plain rollback is refused. The
# collection run of "services upgraded" has migrated every database by now.
if grep -q -- "install --rollback --restore-state" "$upgrade"; then named=1; else named=; fi
if [ "$named" != "$refused" ]; then
    echo "FAIL  the upgrade names the rollback that works (--restore-state named: ${named:-no}, plain rollback refused: ${refused:-no})"
    exit 1
fi
echo "ok    the upgrade named the rollback that works"
rm -f "$upgrade"

step "Upgrading again, then rolling back with the pre-upgrade state"
# After a refused rollback this reinstalls the running release, which must keep
# the state from before the first upgrade as the one to restore.
if [ -n "$refused" ]; then expected=$before; else expected=$(events); fi
again=$(mktemp)
if ! installer '/root/release/bin/garrison install' >"$again" 2>&1; then
    cat "$again"
    echo "FAIL  upgrading again"
    exit 1
fi
cat "$again"
# A reinstall keeps the previous release, which still cannot read the data.
if [ -n "$refused" ]; then
    if ! grep -q -- "install --rollback --restore-state" "$again"; then
        echo "FAIL  after the reinstall the last line still names --restore-state"
        exit 1
    fi
    echo "ok    after the reinstall the last line still names --restore-state"
fi
rm -f "$again"
names "current is the release under test" current "$new"
# Also where the run reinstalled the release that ran: a rollback goes to
# `previous`, and one that named the running release would return to nothing.
names "previous is the release before it" previous "$old"
services "upgraded again"

step "Restoring a backup of the state"
installer '/opt/garrison/current/bin/garrison backup --to /root/kept-state' >/dev/null
kept=$(events)
# The checks store another batch: the history moves on after the backup.
services "after the backup"
check "more was recorded since the backup" \
    "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -gt $kept"
answer=$(mktemp)
if installer '/opt/garrison/current/bin/garrison restore --from /root/no-backup' >"$answer" 2>&1 ||
    ! grep -q "nothing was changed" "$answer"; then
    cat "$answer"
    echo "FAIL  a directory that is no backup is refused, and nothing changes"
    exit 1
fi
rm -f "$answer"
echo "ok    a directory that is no backup is refused, and nothing changes"
installer '/opt/garrison/current/bin/garrison restore --from /root/kept-state'
check "the events are those of the backup" \
    "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -eq $kept"
check "the state from before the restore was kept" 'ls -d /var/backups/garrison/pre-restore-* >/dev/null'
check "the databases belong to their services again" \
    'test "$(stat -c %U /var/lib/garrison/ingest/events.sqlite)" = garrison-ingest &&
        test "$(stat -c %U /var/lib/garrison/collector/status.sqlite)" = garrison-collector'
services "after the restore"
installer '/opt/garrison/current/bin/garrison install --rollback --restore-state'
names "current is the previous release" current "$old"
names "previous is the release it rolled back from" previous "$new"
# Every batch stored after that state must be gone again.
check "the events are those from before the upgrade" "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -eq $expected"
services "restored"

step "Accepted: install, upgrade, a restored backup, rollback and state restore all passed"
