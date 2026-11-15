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

step "Upgrading to the release under test"
upgrade=$(mktemp)
if ! installer '/root/release/bin/garrison install' >"$upgrade" 2>&1; then
    cat "$upgrade"
    echo "FAIL  the upgrade to the release under test"
    exit 1
fi
cat "$upgrade"
check "current points at the new release" 'readlink /opt/garrison/current | grep -q "$(cat /root/release/VERSION)"'
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
# Where Stalwart's exporter is another's, setup writes no metrics credential.
# The collector's unit loads it, and systemd starts no unit whose credential
# file is missing.
credentials=/etc/garrison/credentials
inside "rm -f $credentials/metrics-credential"
check "systemd starts no collection run whose credential file is missing" "
    ! systemctl start garrison-collect.service 2>/dev/null &&
        systemctl status garrison-collect.service --no-pager 2>&1 |
            grep -E -q -i '243/CREDENTIALS|set up credentials'"
since=$(inside 'date +%s')
again=$(mktemp)
if ! installer '/root/release/bin/garrison install' >"$again" 2>&1; then
    cat "$again"
    echo "FAIL  the installer runs again"
    exit 1
fi
rm -f "$again"
check "after the installer, a collection run starts" 'systemctl start garrison-collect.service'
check "the installer keeps the file, empty and root's alone" "
    test -f $credentials/metrics-credential && test ! -s $credentials/metrics-credential &&
        test \"\$(stat -c %U:%a $credentials/metrics-credential)\" = root:600"
check "the collector reads an empty metrics credential as none" \
    "! journalctl -u garrison-collect.service --since @$since --no-pager |
        grep -q 'metrics credential is unavailable'"
# doctor names a missing file with a command that makes it.
inside "rm -f $credentials/metrics-credential"
check "doctor names the missing metrics credential" \
    "garrison doctor > /root/doctor.log 2>&1; grep -q 'FAIL  metrics-credential is missing' /root/doctor.log"
inside "sed -n '/FAIL  metrics-credential is missing/{n;s/^.*: //;p;}' /root/doctor.log > /root/doctor-fix.sh &&
    grep -q /etc/garrison/credentials/metrics-credential /root/doctor-fix.sh && sh -e /root/doctor-fix.sh"
check "the file doctor's command makes lets a collection run start" 'systemctl start garrison-collect.service'
check "doctor finds the empty file in order where nothing reads it" "
    garrison doctor > /root/doctor.log 2>&1;
    ! grep -q 'FAIL  .*metrics-credential' /root/doctor.log &&
        grep -q 'ok    metrics-credential is empty' /root/doctor.log"

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
    check "current still points at the release under test" 'readlink /opt/garrison/current | grep -q "$(cat /root/release/VERSION)"'
fi
services "kept with modules chosen"
inside 'mv /etc/garrison/garrison.toml.previous /etc/garrison/garrison.toml &&
        systemctl try-restart garrison-broker.service garrison-web.service'
check "with every module back the broker offers its action again" "$catalog | grep -q '\"run_check\"'"

step "Rolling back to the previous release"
answer=$(mktemp)
refused=
if installer '/opt/garrison/current/bin/garrison install --rollback' >"$answer" 2>&1; then
    check "current points at the previous release" 'readlink /opt/garrison/current | grep -q "$(cat /root/previous/VERSION)"'
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
    check "current still points at the release under test" 'readlink /opt/garrison/current | grep -q "$(cat /root/release/VERSION)"'
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
# Every batch stored after that state must be gone again.
check "the events are those from before the upgrade" "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -eq $expected"
services "restored"

step "Accepted: install, upgrade, a restored backup, rollback and state restore all passed"
