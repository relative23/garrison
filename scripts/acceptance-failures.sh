#!/bin/sh
# The installer's failure paths on a disposable host: a refusal changes
# nothing, a failure after the services stopped ends with a running Garrison,
# a release that migrated a database before it failed leaves the old one a
# state it can read, and an installer killed at any point, early or as it
# backs up, waits for the services to settle or switches back, leaves
# nothing a later run cannot finish. The installer passes on what
# check-config warns of, names a file it could not write, refuses a secret
# its unit would not hand over, and a policy or a check's path that a unit
# hides, which doctor names, and follows a policy kept elsewhere, but
# leaves a folder named as the policy as it is. Beside
# the installer: a collector that stops is reported, a collection run beside
# one under way collects nothing, setup after a rotation that failed
# restarts the services that hold the old secrets, and root's other
# commands take what they find on the host as it is (a test restore's
# leftovers, links beside the access policy, a folder made for it, actions
# added and taken out).
#
#   [DISTRO=debian-13] [SCENARIOS="refusals failed_start"] \
#       scripts/acceptance-failures.sh \
#       dist/previous-x86_64.tar.gz dist/garrison-<version>-x86_64.tar.gz
#
# The archives are those of scripts/acceptance.sh. SCENARIOS picks some of
# the scenarios below (all by default). The host and its options:
# scripts/acceptance-lib.sh.
set -eu

previous=$1
release=$2
# shellcheck source=scripts/acceptance-lib.sh
. "$(dirname "$0")/acceptance-lib.sh"

# The command must fail and say `message`.
refused() {
    answer=$(mktemp)
    if inside "umask 077 && $2" >"$answer" 2>&1; then
        cat "$answer"
        echo "FAIL  $1: the installer succeeded"
        exit 1
    fi
    if ! grep -q -F -- "$3" "$answer"; then
        cat "$answer"
        echo "FAIL  $1: the answer does not say \"$3\""
        exit 1
    fi
    rm -f "$answer"
    echo "ok    $1"
}

# The command must succeed and say `message`. It runs once: it changes things.
says() {
    answer=$(mktemp)
    if ! inside "umask 077 && $2" >"$answer" 2>&1 || ! grep -q -F -- "$3" "$answer"; then
        cat "$answer"
        echo "FAIL  $1: the answer does not say \"$3\""
        exit 1
    fi
    rm -f "$answer"
    echo "ok    $1"
}

# `current` is release $2, and Garrison runs.
running() {
    check "$1: current is $2" "test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$2'"
    services "$1"
}

# The release under test is current, after an upgrade if need be.
upgraded() {
    if ! inside "test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$new'"; then
        installer '/root/release/bin/garrison install'
    fi
}

# The scenarios of the configuration the installer checks.
# shellcheck source=scripts/acceptance-failures-config.sh
. "$(dirname "$0")/acceptance-failures-config.sh"
# The scenarios of root's commands beside the installer.
# shellcheck source=scripts/acceptance-failures-commands.sh
. "$(dirname "$0")/acceptance-failures-commands.sh"

scenario_refusals() {
    step "Refusals change nothing"
    # Not in /tmp, which the container mounts noexec. The list of checksums is
    # unreadable to others, so the root check must come first.
    inside 'cp -r /root/release /srv/unprivileged && chmod -R a+rX /srv/unprivileged &&
        chmod 600 /srv/unprivileged/SHA256SUMS'
    refused "the installer needs root" \
        'runuser -u nobody -- /srv/unprivileged/bin/garrison install' "Run as root."
    inside 'mv /etc/polkit-1/rules.d /etc/polkit-1/rules.d.away'
    refused "the installer needs polkit" '/root/release/bin/garrison install' "polkit is required"
    inside 'mv /etc/polkit-1/rules.d.away /etc/polkit-1/rules.d'
    # polkit 0.105, as some long-term releases still ship it, ignores rules files;
    # Ubuntu 22.04's has no rules.d either, and the answer names the version.
    inside 'mv /usr/bin/pkaction /usr/bin/pkaction.away &&
        printf "#!/bin/sh\necho \"pkaction version 0.105\"\n" > /usr/bin/pkaction &&
        chmod 755 /usr/bin/pkaction && mv /etc/polkit-1/rules.d /etc/polkit-1/rules.d.away'
    refused "the installer names a polkit without JavaScript rules" '/root/release/bin/garrison install' \
        "polkit 0.105 has no JavaScript rules"
    inside 'mv /usr/bin/pkaction.away /usr/bin/pkaction && mv /etc/polkit-1/rules.d.away /etc/polkit-1/rules.d'
    inside 'cp -a /root/release /root/tampered && printf x >> /root/tampered/static/index.html'
    refused "a changed file is refused" '/root/tampered/bin/garrison install' \
        "Checksum mismatch for static/index.html"
    check "a refused release is not unpacked" "test ! -e '/opt/garrison/releases/$new'"
    backups=$(inside 'ls /var/backups/garrison | wc -l')
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.good &&
        printf "\nunknown_setting = 1\n" >> /etc/garrison/garrison.toml'
    refused "a configuration the release refuses stops the upgrade" \
        '/root/release/bin/garrison install' "the running release was not touched"
    # A script that keeps only standard error finds the reason there.
    check "the installer names the refused setting on standard error" \
        'umask 077 && /root/release/bin/garrison install 2>&1 >/dev/null | grep -q unknown_setting'
    inside 'cp -p /root/garrison.toml.good /etc/garrison/garrison.toml'
    check "the refused upgrade backed nothing up" "test \$(ls /var/backups/garrison | wc -l) -eq $backups"
    # Too little room for the backup: a small file system over the backups.
    inside 'mount -t tmpfs -o size=8m garrison-full /var/backups/garrison'
    refused "an upgrade without room for the backup is refused" '/root/release/bin/garrison install' \
        "MiB free and the installation needs"
    inside 'umount /var/backups/garrison'
    check "the refused upgrade backed nothing up either" "test \$(ls /var/backups/garrison | wc -l) -eq $backups"
    inside 'mv /var/backups/garrison /var/backups/garrison.away && touch /var/backups/garrison'
    refused "a failed backup stops the upgrade" '/root/release/bin/garrison install' "backup failed"
    inside 'rm /var/backups/garrison && mv /var/backups/garrison.away /var/backups/garrison'
    running "after the refusals" "$old"
}

scenario_base_hidden() {
    step "A release base that a link puts under /home, which the units hide, is refused before anything changes"
    upgraded
    # The disk under /home that /opt/garrison is linked to, as a RHEL host's
    # large partition is.
    inside 'mv /opt/garrison /home/garrison && ln -s /home/garrison /opt/garrison'
    pid=$(inside 'systemctl show -p MainPID --value garrison-web.service')
    refused "an installer whose release base leads under /home is refused" \
        '/root/release/bin/garrison install' "/opt/garrison leads to /home/garrison, which lies under /home"
    check "and nothing stopped" "test \"\$(systemctl show -p MainPID --value garrison-web.service)\" = '$pid'"
    inside 'rm /opt/garrison && mv /home/garrison /opt/garrison'
    running "after the base under /home" "$new"
}

scenario_failed_start() {
    step "A release that does not start is switched back"
    # The web service of this copy exits right after it starts.
    inside 'cp -a /root/release /root/broken && cd /root/broken &&
        printf "%s+broken\n" "$(cat VERSION)" > VERSION &&
        sed -i "s|^ExecStart=/opt/garrison/current/bin/garrison web$|ExecStart=/opt/garrison/current/bin/garrison --config /etc/garrison/absent.toml web|" \
            deploy/systemd/garrison-web.service &&
        grep -q absent.toml deploy/systemd/garrison-web.service &&
        find . -type f ! -name SHA256SUMS | sed "s|^\./||" | sort | xargs sha256sum > SHA256SUMS'
    current=$(inside 'basename "$(readlink -f /opt/garrison/current)"')
    refused "a release whose web service fails is switched back" \
        '/root/broken/bin/garrison install' "the previous release is running"
    running "after the failed start" "$current"
}

scenario_crash_loop() {
    step "A release whose service starts and keeps falling over is switched back"
    # The web service of this copy starts, and systemd ends it after three
    # seconds every time and starts it again: never steady for the installer.
    inside 'cp -a /root/release /root/unsteady && cd /root/unsteady &&
        printf "%s+unsteady\n" "$(cat VERSION)" > VERSION &&
        sed -i "s|^\[Service\]$|[Service]\nRuntimeMaxSec=3s|" deploy/systemd/garrison-web.service &&
        grep -q "^RuntimeMaxSec=3s$" deploy/systemd/garrison-web.service &&
        find . -type f ! -name SHA256SUMS | sed "s|^\./||" | sort | xargs sha256sum > SHA256SUMS'
    current=$(inside 'basename "$(readlink -f /opt/garrison/current)"')
    refused "a release whose web service keeps restarting is switched back" \
        '/root/unsteady/bin/garrison install' "the previous release is running"
    running "after the unsteady release" "$current"
}

# The schema of the status database, which a migration raises.
status_schema() { inside 'sqlite3 /var/lib/garrison/collector/status.sqlite "PRAGMA user_version"'; }

# What a release with a migration does when it first opens a database: it
# raises the schema, and the release before cannot read it any more. The web
# service of this copy, /root/migrating, migrates before it starts, as root,
# and systemd ends it after three seconds every time: started, then failed.
migrating_release() {
    inside_input 'cat > /usr/local/bin/acceptance-migrate && chmod 755 /usr/local/bin/acceptance-migrate' <<'MIGRATE'
#!/bin/sh
exec sqlite3 /var/lib/garrison/collector/status.sqlite 'PRAGMA user_version = 99'
MIGRATE
    inside 'rm -rf /root/migrating && cp -a /root/release /root/migrating && cd /root/migrating &&
        printf "%s+migrating\n" "$(cat VERSION)" > VERSION &&
        sed -i "s|^\[Service\]$|[Service]\nRuntimeMaxSec=3s\nExecStartPre=+/usr/local/bin/acceptance-migrate|" \
            deploy/systemd/garrison-web.service &&
        grep -q "^ExecStartPre=+/usr/local/bin/acceptance-migrate$" deploy/systemd/garrison-web.service &&
        find . -type f ! -name SHA256SUMS | sed "s|^\./||" | sort | xargs sha256sum > SHA256SUMS'
}

scenario_migrated_then_failed() {
    step "A release that migrated a database and then failed is switched back with the state from before"
    migrating_release
    check "a collection run wrote the status database" 'systemctl start garrison-collect.service'
    current=$(inside 'basename "$(readlink -f /opt/garrison/current)"')
    earlier=$(inside 'readlink -f /opt/garrison/previous 2>/dev/null || true')
    schema=$(status_schema)
    before=$(events)
    refused "a release that migrated and then kept falling over is switched back" \
        '/root/migrating/bin/garrison install' "the previous release is running"
    check "the migrated database is the one from before again" \
        "test '$schema' = \"\$(sqlite3 /var/lib/garrison/collector/status.sqlite 'PRAGMA user_version')\""
    check "the other databases kept their data" \
        "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -ge $before"
    check "previous is what it was before the upgrade" \
        "test \"\$(readlink -f /opt/garrison/previous 2>/dev/null || true)\" = '$earlier'"
    # The old writers work: among the checks, a collection run of the old
    # release on the database that went back, and its self-check.
    running "after the failed upgrade with a migration" "$current"

    step "Where the release that ran does not start either, a second attempt returns to it"
    # A start that fails for both releases, for as long as the flag is there.
    inside 'mkdir -p /etc/systemd/system/garrison-web.service.d &&
        printf "[Service]\nExecStartPre=+/bin/sh -c \"! test -e /run/garrison-acceptance-fail\"\n" \
            > /etc/systemd/system/garrison-web.service.d/acceptance-fail.conf &&
        systemctl daemon-reload && touch /run/garrison-acceptance-fail'
    refused "the installer says that neither release started, and what returns to the old one" \
        '/root/migrating/bin/garrison install' "install --rollback --restore-state"
    check "the migrated database went back all the same" \
        "test '$schema' = \"\$(sqlite3 /var/lib/garrison/collector/status.sqlite 'PRAGMA user_version')\""
    check "previous names the release to return to" \
        "test \"\$(basename \"\$(readlink -f /opt/garrison/previous)\")\" = '$current'"
    check "nothing of a release that is not current keeps running" \
        '! systemctl is-active --quiet garrison-web.service garrison-ingest.service garrison-collect.timer'
    inside 'rm /run/garrison-acceptance-fail /etc/systemd/system/garrison-web.service.d/acceptance-fail.conf &&
        rmdir /etc/systemd/system/garrison-web.service.d && systemctl daemon-reload'
    installer '/opt/garrison/current/bin/garrison install --rollback --restore-state'
    running "after the second attempt" "$current"
}

scenario_switch_back_room() {
    step "A switch back whose copy does not fit beside its database puts none back and says why"
    upgraded
    migrating_release
    # The status database grows to some 5 MiB on a file system of 8 MiB:
    # its copy from before the upgrade does not fit beside it.
    inside 'systemctl stop garrison-collect.timer garrison-collect.service &&
        sqlite3 /var/lib/garrison/collector/status.sqlite "CREATE TABLE IF NOT EXISTS padding(x);
            WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 5000)
            INSERT INTO padding SELECT randomblob(1000) FROM n;" &&
        cp -a /var/lib/garrison/collector /root/collector-room &&
        mount -t tmpfs -o size=8m garrison-room /var/lib/garrison/collector &&
        cp -a /root/collector-room/. /var/lib/garrison/collector/ && rm -r /root/collector-room &&
        systemctl start garrison-collect.timer'
    if inside 'umask 077 && /root/migrating/bin/garrison install > /root/switch-room.log 2>&1'; then
        inside 'cat /root/switch-room.log' || true
        echo "FAIL  the upgrade to a release that migrated and fell over fails"
        exit 1
    fi
    check "the switch back says where a copy does not fit, not that the old release failed" \
        '{ grep -q "the copies from before the upgrade need" /root/switch-room.log &&
            ! grep -q "did not start either" /root/switch-room.log; } || { cat /root/switch-room.log; false; }'
    check "and puts nothing back" \
        "test \"\$(sqlite3 -readonly /var/lib/garrison/collector/status.sqlite 'PRAGMA user_version')\" = 99"
    # With room again, what the answer names returns to the release that ran.
    inside 'systemctl stop garrison-collect.timer garrison-collect.service;
        cp -a /var/lib/garrison/collector /root/collector-room && umount /var/lib/garrison/collector &&
        cp -a /root/collector-room/. /var/lib/garrison/collector/ && rm -r /root/collector-room /root/switch-room.log'
    installer '/opt/garrison/current/bin/garrison install --rollback --restore-state'
    running "after the switch back that had no room" "$new"
}

scenario_concurrent() {
    step "Two installers at once"
    inside 'cd /root; umask 077
        { /root/release/bin/garrison install > one.log 2>&1; echo $? > one.status; } &
        { /root/release/bin/garrison install > two.log 2>&1; echo $? > two.status; } &
        wait'
    check "of two installers at once one runs and one is refused" \
        'cd /root && test "$(sort one.status two.status | tr "\n" " ")" = "0 1 " &&
            grep -q "already running" one.log two.log'
    running "after two installers at once" "$new"
}

# Installers, rollbacks and restores killed at any point, then one more run.
# shellcheck source=scripts/acceptance-failures-unfinished.sh
. "$(dirname "$0")/acceptance-failures-unfinished.sh"

scenario_reinstall() {
    step "Reinstalling the running release keeps the state to restore"
    upgraded
    inside 'readlink /var/backups/garrison/last-pre-upgrade > /root/last-before'
    installer '/root/release/bin/garrison install'
    check "a reinstall keeps last-pre-upgrade" \
        'test "$(readlink /var/backups/garrison/last-pre-upgrade)" = "$(cat /root/last-before)"'
    names "a reinstall keeps the previous release" previous "$old"
    # Without a previous release there is no rollback to name.
    inside 'mv /opt/garrison/previous /root/previous.link'
    installer '/root/release/bin/garrison install > /root/reinstall.log 2>&1'
    check "a reinstall without a previous release names no rollback" \
        "{ ! grep -q 'Roll back with' /root/reinstall.log && grep -q -F 'Garrison $new is running.' /root/reinstall.log; } ||
            { cat /root/reinstall.log; false; }"
    inside 'mv /root/previous.link /opt/garrison/previous && rm /root/reinstall.log'
    running "after the reinstall" "$new"
}

scenario_rollback_without_state() {
    step "A rollback that cannot restore the state stops before anything changes"
    upgraded
    inside 'mv /var/backups/garrison/last-pre-upgrade /root/last-pre-upgrade.away'
    refused "a rollback without the state from before the upgrade is refused" \
        '/opt/garrison/current/bin/garrison install --rollback --restore-state' "last-pre-upgrade"
    inside 'mv /root/last-pre-upgrade.away /var/backups/garrison/last-pre-upgrade'
    running "after the refused rollback" "$new"
}

scenario_stopped_collector() {
    step "A collector that stops is reported, also where the configuration no longer loads"
    upgraded
    ntfy_stand_in
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.kept &&
        printf "\n[notifications]\nntfy_url = \"https://localhost:8443/acceptance\"\n" >> /etc/garrison/garrison.toml &&
        cp -p /etc/garrison/garrison.toml /root/garrison.toml.topic'
    check "the configuration with a topic is accepted" '/opt/garrison/current/bin/garrison check-config'
    check "a collection run leaves the topic for the watch" \
        'systemctl start garrison-collect.service &&
            sqlite3 /var/lib/garrison/collector/status.sqlite \
                "SELECT value FROM memory WHERE key = '"'"'notify.channel'"'"'" | grep -q localhost:8443'
    check "the watch finds the collector running and says nothing" \
        'systemctl start garrison-watch.service && ! grep -q "collector" /root/ntfy-bodies'
    # The collector stops: no timer, the last run an hour old, and a
    # configuration that no release loads.
    inside 'systemctl stop garrison-collect.timer garrison-collect.service &&
        sqlite3 /var/lib/garrison/collector/status.sqlite \
            "UPDATE snapshots SET collected_at = collected_at - 3600" &&
        echo "nonsense = 1" >> /etc/garrison/garrison.toml'
    check "the collector refuses the configuration" '! /opt/garrison/current/bin/garrison check-config'
    check "the watch tells the topic that the collector has stopped" \
        'systemctl start garrison-watch.service &&
            grep -q "the collector has stopped" /root/ntfy-bodies &&
            test -e /var/lib/garrison/watch/collector-stopped'
    check "a second look tells nothing more" \
        'systemctl start garrison-watch.service &&
            test "$(grep -c "the collector has stopped" /root/ntfy-bodies)" = 1'
    inside 'cat /root/garrison.toml.topic > /etc/garrison/garrison.toml &&
        systemctl start garrison-collect.timer garrison-collect.service'
    check "the watch tells the topic that the collector runs again" \
        'systemctl start garrison-watch.service &&
            grep -q "the collector runs again" /root/ntfy-bodies &&
            test ! -e /var/lib/garrison/watch/collector-stopped'
    inside 'cat /root/garrison.toml.kept > /etc/garrison/garrison.toml &&
        rm -r /etc/systemd/system/garrison-collect.service.d /etc/systemd/system/garrison-watch.service.d &&
        systemctl daemon-reload && systemctl stop acceptance-ntfy && systemctl start garrison-collect.service'
    check "without a topic the run takes it back from the watch" \
        'test -z "$(sqlite3 /var/lib/garrison/collector/status.sqlite \
            "SELECT value FROM memory WHERE key = '"'"'notify.channel'"'"'")"'
    running "after the stopped collector" "$new"
}

# Stalwart takes the new keys of a rotation that stops at their check: the
# run restarts the services that hold the secrets all the same, the old
# keys go, and it names the run that finishes it.
scenario_rotation() {
    step "Setting up again after a rotation that failed"
    upgraded
    setup='/opt/garrison/current/bin/garrison stalwart setup --skip-metrics --admin-credential /root/stalwart-admin.json'
    inside 'umask 077 && printf "{\"apiKey\": \"stand-in-administrator\"}" > /root/stalwart-admin.json'
    says "a rotation restarts the services that hold the secrets" "$setup --rotate" \
        "restarted with the new secrets"
    inside 'cp /root/stand-in-keys /root/keys-before-rotation && touch /root/stand-in-refuses'
    if inside "umask 077 && $setup --rotate > /root/rotation.log 2>&1"; then
        inside 'cat /root/rotation.log' || true
        echo "FAIL  a rotation whose keys Stalwart refuses stops"
        exit 1
    fi
    echo "ok    a rotation whose keys Stalwart refuses stops"
    check "the failed rotation restarted the services that hold the secrets" \
        'grep -q -F "garrison-ingest and garrison-broker restarted with the new secrets." /root/rotation.log'
    check "the failed rotation removed the keys that new ones replaced" \
        'for id in $(cut -d " " -f 1 /root/keys-before-rotation); do ! grep -q "^$id " /root/stand-in-keys || exit 1; done'
    check "the failed rotation names the run that finishes it" \
        'grep -q -F "Run \`garrison stalwart setup --rotate\` again once this is mended." /root/rotation.log'
    inside 'rm /root/stand-in-refuses /root/keys-before-rotation /root/rotation.log'
    says "setup again once Stalwart takes the keys" "$setup" "Settings reloaded."
    check "the receiver holds the signature key of its file" \
        'test "$(cat /run/credentials/garrison-ingest.service/webhook-signature-key)" = \
            "$(cat /etc/garrison/credentials/webhook-signature-key)"'
    # The broker runs since the checks before asked it. Started anew it
    # would read the file; one that setup left running holds the old key.
    check "the broker holds the native key of its file" \
        'systemctl is-active --quiet garrison-broker.service &&
            test "$(cat /run/credentials/garrison-broker.service/broker-native-key)" = \
                "$(cat /etc/garrison/credentials/broker-native-key)"'
    inside 'rm /root/stalwart-admin.json'
    running "after the rotation" "$new"
}

scenario_milter_asked() {
    step "The installer does not stop a macro filter that Stalwart still asks"
    upgraded
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.milter &&
        printf "\n[milter]\n" >> /etc/garrison/garrison.toml'
    installer '/root/release/bin/garrison install'
    check "the filter runs with the [milter] section" 'systemctl is-active --quiet garrison-milter.service'
    # An entry of Stalwart's at the filter's port that setup did not note,
    # and the section gone.
    inside 'printf "%s" "{\"id\": \"m1\", \"host\": \"127.0.0.1\", \"port\": 8096, \"enable\": true}" \
            > /root/stand-in-milters && cat /root/garrison.toml.milter > /etc/garrison/garrison.toml'
    says "the next installer run says why the filter keeps running" '/root/release/bin/garrison install' \
        "keeps running: Stalwart asks its milter entry m1 at 127.0.0.1:8096"
    check "and the filter runs on" 'systemctl is-active --quiet garrison-milter.service'
    inside 'rm /root/stand-in-milters'
    installer '/root/release/bin/garrison install'
    check "once nothing asks it, the next run stops it" '! systemctl is-active --quiet garrison-milter.service'
    running "after the filter Stalwart asked" "$new"
}

scenario_milter_sandbox() {
    step "The macro filter's unit writes nowhere: no /tmp of its own, not the host's shared memory"
    upgraded
    # Tried within the unit before its service starts, as the filter itself
    # would; it needs no [milter] section for that.
    inside_input 'mkdir -p /etc/systemd/system/garrison-milter.service.d &&
        cat > /etc/systemd/system/garrison-milter.service.d/acceptance-probe.conf && systemctl daemon-reload' <<'PROBE'
[Service]
ExecStartPre=/bin/sh -c 'for place in /dev/shm /dev/mqueue /tmp /var/tmp; do if : > "$$place/garrison-milter-probe" 2>/dev/null; then echo "writable $$place"; fi; done'
PROBE
    inside 'systemctl start garrison-milter.service >/dev/null 2>&1; systemctl stop garrison-milter.service;
        systemctl reset-failed garrison-milter.service' || true
    check "the filter's unit writes in none of those places" \
        '! journalctl -u garrison-milter.service --no-pager | grep "writable /" && test ! -e /dev/shm/garrison-milter-probe'
    inside 'rm -r /etc/systemd/system/garrison-milter.service.d && systemctl daemon-reload'
    running "after the filter's unit" "$new"
}

scenario_collect_beside() {
    step "A collection run beside one under way collects nothing"
    upgraded
    newest='sqlite3 /var/lib/garrison/collector/status.sqlite "SELECT max(id) FROM snapshots"'
    inside 'systemctl stop garrison-collect.timer && systemctl start garrison-collect.service'
    before=$(inside "$newest")
    # A run by hand under way holds the collector's state directory.
    inside 'systemd-run --quiet --unit=acceptance-collecting flock /var/lib/garrison/collector sleep 300'
    check "a run beside it ends as a success and says why" \
        'systemctl start garrison-collect.service &&
            test "$(systemctl show -p Result --value garrison-collect.service)" = success &&
            journalctl -u garrison-collect.service -n 20 --no-pager | grep -q "Another collection run is under way"'
    check "and stores no snapshot" "test \"\$($newest)\" = '$before'"
    inside 'systemctl stop acceptance-collecting'
    check "once that run is over, the next one stores its snapshot" \
        "systemctl start garrison-collect.service && test \"\$($newest)\" -gt '$before'"
    inside 'systemctl start garrison-collect.timer'
    running "after the run beside one" "$new"
}

start_host
install_previous
old=$(inside 'cat /root/previous/VERSION')
new=$(inside 'cat /root/release/VERSION')
running "installed" "$old"
for scenario in ${SCENARIOS:-refusals hidden_policy hidden_check base_hidden failed_start crash_loop migrated_then_failed \
    switch_back_room concurrent \
    upgrade_killed switch_back_failed_early upgrade_resumed rollback_killed restore_killed upgrade_came_up restore_came_up \
    rollback_state_killed rollback_came_up \
    restore_refused restore_refused_config restore_policy \
    restore_policy_link restore_room rollback_after_restore elsewhere_unloadable elsewhere_purge rollback_refused \
    rollback_refused_config rollback_room \
    interrupted killed_late reinstall rollback_without_state stopped_collector warnings unloaded policy_elsewhere \
    policy_foreign unwritten \
    rotation milter_asked milter_sandbox collect_beside restore_leftovers access_links access_folder access_actions}; do
    "scenario_$scenario"
done

step "Accepted: every failure path ended with a running Garrison"
