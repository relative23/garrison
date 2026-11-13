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
installer '/opt/garrison/current/bin/garrison install --rollback --restore-state'
# Every batch stored after that state must be gone again.
check "the events are those from before the upgrade" "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -eq $expected"
services "restored"

step "Accepted: install, upgrade, rollback and state restore all passed"
