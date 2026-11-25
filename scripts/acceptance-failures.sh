#!/bin/sh
# The installer's failure paths on a disposable host: a refusal changes
# nothing, a failure after the services stopped ends with a running Garrison,
# a release that migrated a database before it failed leaves the old one a
# state it can read, and an installer killed at any point, early or as it
# backs up, waits for the services to settle or switches back, leaves
# nothing a later run cannot go on from; a run where everything is as
# installed changes nothing. The installer passes on what
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
# shellcheck source=scripts/acceptance-ntfy.sh
. "$(dirname "$0")/acceptance-ntfy.sh"

# The command must fail and say one of the states `3` (their names, apart by
# spaces). Its answer stays in /root/answer for the checks after it.
refused() {
    if inside "umask 077 && { $2; } > /root/answer 2>&1"; then
        inside 'cat /root/answer' || true
        echo "FAIL  $1: the installer succeeded"
        exit 1
    fi
    if ! inside "acceptance-state /root/answer $3"; then
        inside 'cat /root/answer' || true
        echo "FAIL  $1: the answer does not say $3"
        exit 1
    fi
    echo "ok    $1"
}

# The command must succeed and say one of the states `3`. It runs once: it
# changes things.
says() {
    if ! inside "umask 077 && { $2; } > /root/answer 2>&1" || ! inside "acceptance-state /root/answer $3"; then
        inside 'cat /root/answer' || true
        echo "FAIL  $1: the answer does not say $3"
        exit 1
    fi
    echo "ok    $1"
}

# As `says`, for `3` as it is written, such as a state's name in its
# brackets; the answer is read here.
says_words() {
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
        'runuser -u nobody -- /srv/unprivileged/bin/garrison install' install-not-root
    inside 'mv /etc/polkit-1/rules.d /etc/polkit-1/rules.d.away'
    refused "the installer needs polkit" '/root/release/bin/garrison install' install-no-polkit
    inside 'mv /etc/polkit-1/rules.d.away /etc/polkit-1/rules.d'
    # polkit 0.105, as some long-term releases still ship it, ignores rules files;
    # Ubuntu 22.04's has no rules.d either, and the answer names the version.
    inside 'mv /usr/bin/pkaction /usr/bin/pkaction.away &&
        printf "#!/bin/sh\necho \"pkaction version 0.105\"\n" > /usr/bin/pkaction &&
        chmod 755 /usr/bin/pkaction && mv /etc/polkit-1/rules.d /etc/polkit-1/rules.d.away'
    refused "the installer names a polkit without JavaScript rules" '/root/release/bin/garrison install' \
        install-old-polkit
    inside 'mv /usr/bin/pkaction.away /usr/bin/pkaction && mv /etc/polkit-1/rules.d.away /etc/polkit-1/rules.d'
    inside 'cp -a /root/release /root/tampered && printf x >> /root/tampered/static/index.html'
    refused "a changed file is refused" '/root/tampered/bin/garrison install' install-checksum-mismatch
    check "and named" 'grep -q -F static/index.html /root/answer'
    check "a refused release is not unpacked" "test ! -e '/opt/garrison/releases/$new'"
    backups=$(inside 'ls /var/backups/garrison | wc -l')
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.good &&
        printf "\nunknown_setting = 1\n" >> /etc/garrison/garrison.toml'
    refused "a configuration the release refuses stops the upgrade" \
        '/root/release/bin/garrison install' install-config-refused
    # A script that keeps only standard error finds the reason there.
    once "the installer names the refused setting on standard error" \
        'umask 077 && /root/release/bin/garrison install 2>&1 >/dev/null | grep -q unknown_setting'
    # The section of the macro filter that releases up to 0.2 had.
    inside 'cp -p /root/garrison.toml.good /etc/garrison/garrison.toml &&
        printf "\n[milter]\n" >> /etc/garrison/garrison.toml'
    refused "the macro filter's section stops the upgrade" \
        '/root/release/bin/garrison install' install-config-refused
    check "and the answer says how the release installed switches the filter off" \
        'grep -q -F "[milter] is no longer a section" /root/answer && grep -q -F "garrison stalwart setup" /root/answer'
    inside 'cp -p /root/garrison.toml.good /etc/garrison/garrison.toml'
    # That filter still running, which Stalwart then asks about every
    # message: a unit of its name stands in for it, as a drop-in of the
    # release's own unit where it has one.
    inside 'mkdir -p /etc/systemd/system/garrison-milter.service.d &&
        printf "[Service]\nExecStart=\nExecStart=/bin/sleep infinity\n" \
            > /etc/systemd/system/garrison-milter.service.d/acceptance.conf &&
        { test -e /etc/systemd/system/garrison-milter.service ||
            printf "[Service]\nExecStart=/bin/sleep infinity\n" > /run/systemd/system/garrison-milter.service; } &&
        systemctl daemon-reload && systemctl start garrison-milter.service'
    refused "a macro filter that still runs stops the upgrade" \
        '/root/release/bin/garrison install' install-macro-filter-runs
    check "and it runs on" 'systemctl is-active --quiet garrison-milter.service'
    inside 'systemctl stop garrison-milter.service; rm -r /etc/systemd/system/garrison-milter.service.d &&
        rm -f /run/systemd/system/garrison-milter.service && systemctl daemon-reload'
    check "the refused upgrade backed nothing up" "test \$(ls /var/backups/garrison | wc -l) -eq $backups"
    # Too little room for the backup: a small file system over the backups.
    inside 'mount -t tmpfs -o size=8m garrison-full /var/backups/garrison'
    refused "an upgrade without room for the backup is refused" '/root/release/bin/garrison install' \
        install-no-room
    inside 'umount /var/backups/garrison'
    check "the refused upgrade backed nothing up either" "test \$(ls /var/backups/garrison | wc -l) -eq $backups"
    inside 'mv /var/backups/garrison /var/backups/garrison.away && touch /var/backups/garrison'
    refused "a failed backup stops the upgrade" '/root/release/bin/garrison install' install-backup-failed
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
        '/root/release/bin/garrison install' install-base-hidden
    check "and names where it leads" 'grep -q -F /home/garrison /root/answer'
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
        '/root/broken/bin/garrison install' install-switched-back
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
        '/root/unsteady/bin/garrison install' install-switched-back
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
    once "a collection run wrote the status database" 'acceptance-run garrison-collect.service'
    current=$(inside 'basename "$(readlink -f /opt/garrison/current)"')
    earlier=$(inside 'readlink -f /opt/garrison/previous 2>/dev/null || true')
    schema=$(status_schema)
    before=$(events)
    refused "a release that migrated and then kept falling over is switched back" \
        '/root/migrating/bin/garrison install' install-switched-back
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
        '/root/migrating/bin/garrison install' install-previous-failed
    check "and names the rollback that returns to it" 'grep -q -F "install --rollback --restore-state" /root/answer'
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
        '{ acceptance-state /root/switch-room.log install-switch-back-failed &&
            acceptance-state /root/switch-room.log install-copies-no-room &&
            ! acceptance-state /root/switch-room.log install-previous-failed; } ||
            { cat /root/switch-room.log; false; }'
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
    # A secret file the run that holds the lock makes again, and then
    # starts the services: it holds the lock while the other one asks.
    inside 'rm /etc/garrison/credentials/ntfy-token'
    inside 'cd /root; umask 077
        { /root/release/bin/garrison install > one.log 2>&1; echo $? > one.status; } &
        { /root/release/bin/garrison install > two.log 2>&1; echo $? > two.status; } &
        wait'
    check "of two installers at once one runs and one is refused" \
        'cd /root && test "$(sort one.status two.status | tr "\n" " ")" = "0 1 " &&
            { acceptance-state one.log install-busy || acceptance-state two.log install-busy; }'
    running "after two installers at once" "$new"
}

# Installers, rollbacks and restores killed at any point, then one more run.
# shellcheck source=scripts/acceptance-failures-unfinished.sh
. "$(dirname "$0")/acceptance-failures-unfinished.sh"

scenario_reinstall() {
    step "Installing the release that runs as installed changes nothing and keeps the state to restore"
    upgraded
    inside 'readlink /var/backups/garrison/last-pre-upgrade > /root/last-before'
    backups=$(inside 'ls /var/backups/garrison | wc -l')
    pid=$(inside 'systemctl show -p MainPID --value garrison-web.service')
    says "a reinstall of the release that runs as installed says that it changed nothing" \
        '/root/release/bin/garrison install' install-as-installed
    check "and stops nothing and copies nothing" "
        test \"\$(systemctl show -p MainPID --value garrison-web.service)\" = '$pid' &&
            test \$(ls /var/backups/garrison | wc -l) -eq $backups"
    check "a reinstall keeps last-pre-upgrade" \
        'test "$(readlink /var/backups/garrison/last-pre-upgrade)" = "$(cat /root/last-before)"'
    names "a reinstall keeps the previous release" previous "$old"
    # Without a previous release there is no rollback to name.
    inside 'mv /opt/garrison/previous /root/previous.link'
    installer '/root/release/bin/garrison install > /root/reinstall.log 2>&1'
    check "a reinstall without a previous release names no rollback" \
        "{ ! grep -q -F 'install --rollback' /root/reinstall.log &&
            acceptance-state /root/reinstall.log install-running install-as-installed; } ||
            { cat /root/reinstall.log; false; }"
    inside 'mv /root/previous.link /opt/garrison/previous && rm /root/reinstall.log'
    running "after the reinstall" "$new"
}

scenario_rollback_without_state() {
    step "A rollback that cannot restore the state stops before anything changes"
    upgraded
    inside 'mv /var/backups/garrison/last-pre-upgrade /root/last-pre-upgrade.away'
    refused "a rollback without the state from before the upgrade is refused" \
        '/opt/garrison/current/bin/garrison install --rollback --restore-state' install-no-state
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
    once "a collection run leaves the topic for the watch" \
        'acceptance-run garrison-collect.service &&
            sqlite3 /var/lib/garrison/collector/status.sqlite \
                "SELECT value FROM memory WHERE key = '"'"'notify.channel'"'"'" | grep -q localhost:8443'
    once "the watch finds the collector running and says nothing" \
        'acceptance-run garrison-watch.service && ! grep -q "collector" /root/ntfy-bodies'
    # The collector stops: no timer, the last run an hour old, and a
    # configuration that no release loads.
    inside 'systemctl stop garrison-collect.timer garrison-collect.service &&
        sqlite3 /var/lib/garrison/collector/status.sqlite \
            "UPDATE snapshots SET collected_at = collected_at - 3600" &&
        echo "nonsense = 1" >> /etc/garrison/garrison.toml'
    check "the collector refuses the configuration" '! /opt/garrison/current/bin/garrison check-config'
    once "the watch tells the topic that the collector has stopped" 'acceptance-run garrison-watch.service' \
        'grep -q "the collector has stopped" /root/ntfy-bodies &&
            test -e /var/lib/garrison/watch/collector-stopped'
    once "a second look tells nothing more" 'acceptance-run garrison-watch.service' \
        'test "$(grep -c "the collector has stopped" /root/ntfy-bodies)" = 1'
    inside 'cat /root/garrison.toml.topic > /etc/garrison/garrison.toml &&
        systemctl start garrison-collect.timer garrison-collect.service'
    once "the watch tells the topic that the collector runs again" 'acceptance-run garrison-watch.service' \
        'grep -q "the collector runs again" /root/ntfy-bodies &&
            test ! -e /var/lib/garrison/watch/collector-stopped'
    inside 'cat /root/garrison.toml.kept > /etc/garrison/garrison.toml &&
        rm -r /etc/systemd/system/garrison-collect.service.d /etc/systemd/system/garrison-watch.service.d &&
        systemctl daemon-reload && systemctl stop acceptance-ntfy && acceptance-run garrison-collect.service'
    check "without a topic the run takes it back from the watch" \
        'test -z "$(sqlite3 /var/lib/garrison/collector/status.sqlite \
            "SELECT value FROM memory WHERE key = '"'"'notify.channel'"'"'")"'
    running "after the stopped collector" "$new"
}

# The scenarios of setup beside Stalwart.
# shellcheck source=scripts/acceptance-failures-stalwart.sh
. "$(dirname "$0")/acceptance-failures-stalwart.sh"

scenario_collect_beside() {
    step "A collection run beside one under way collects nothing"
    upgraded
    newest='sqlite3 /var/lib/garrison/collector/status.sqlite "SELECT max(id) FROM snapshots"'
    inside 'systemctl stop garrison-collect.timer && acceptance-run garrison-collect.service'
    before=$(inside "$newest")
    # A run by hand under way holds the collector's state directory.
    inside 'systemd-run --quiet --unit=acceptance-collecting flock /var/lib/garrison/collector sleep 300'
    once "a run beside it ends as a success and says why" \
        'acceptance-run garrison-collect.service &&
            test "$(systemctl show -p Result --value garrison-collect.service)" = success' \
        'journalctl -u garrison-collect.service -n 20 --no-pager > /root/collect.log &&
            acceptance-state /root/collect.log collect-busy'
    check "and stores no snapshot" "test \"\$($newest)\" = '$before'"
    inside 'systemctl stop acceptance-collecting'
    once "once that run is over, the next one stores its snapshot" \
        "acceptance-run garrison-collect.service && test \"\$($newest)\" -gt '$before'"
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
    rotation collect_beside restore_leftovers access_links access_folder access_actions}; do
    "scenario_$scenario"
done

step "Accepted: every failure path ended with a running Garrison"
