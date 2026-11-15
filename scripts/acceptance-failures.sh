#!/bin/sh
# The installer's failure paths on a disposable host: a refusal changes
# nothing, a failure after the services stopped ends with a running Garrison,
# a release that migrated a database before it failed leaves the old one a
# state it can read, and an installer killed at any point, early or as it
# backs up, waits for the services to settle or switches back, leaves
# nothing a later run cannot finish. The installer passes on what
# check-config warns of, names a file it could not write, refuses a secret
# its unit would not hand over and follows a policy kept elsewhere, but
# leaves a folder named as the policy as it is. Beside
# the installer: a collector that stops is reported, a collection run beside
# one under way collects nothing, and setup after a rotation that failed
# restarts the services that hold the old secrets.
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

scenario_migrated_then_failed() {
    step "A release that migrated a database and then failed is switched back with the state from before"
    # What a release with a migration does when it first opens a database:
    # it raises the schema, and the release before cannot read it any more.
    inside_input 'cat > /usr/local/bin/acceptance-migrate && chmod 755 /usr/local/bin/acceptance-migrate' <<'MIGRATE'
#!/bin/sh
exec sqlite3 /var/lib/garrison/collector/status.sqlite 'PRAGMA user_version = 99'
MIGRATE
    # The web service of this copy migrates before it starts, as root, and
    # systemd ends it after three seconds every time: started, then failed.
    inside 'cp -a /root/release /root/migrating && cd /root/migrating &&
        printf "%s+migrating\n" "$(cat VERSION)" > VERSION &&
        sed -i "s|^\[Service\]$|[Service]\nRuntimeMaxSec=3s\nExecStartPre=+/usr/local/bin/acceptance-migrate|" \
            deploy/systemd/garrison-web.service &&
        grep -q "^ExecStartPre=+/usr/local/bin/acceptance-migrate$" deploy/systemd/garrison-web.service &&
        find . -type f ! -name SHA256SUMS | sed "s|^\./||" | sort | xargs sha256sum > SHA256SUMS'
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

scenario_interrupted() {
    step "Installers killed at any point, then one more run"
    before=$(events)
    # From the first checks to the start of the services, both ways round.
    for delay in 0.1 0.3 0.5 0.7 0.9 1.1 1.4 1.7 2.0 2.4 2.8 3.2; do
        for target in previous release; do
            inside "umask 077 && timeout -s KILL $delay /root/$target/bin/garrison install >/dev/null 2>&1" || true
        done
    done
    installer '/root/release/bin/garrison install'
    running "after killed installers" "$new"
    check "no event was lost" "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -ge $before"
    check "previous names an installed release" 'test -x "$(readlink -f /opt/garrison/previous)/bin/garrison"'
    check "the state to restore is complete" 'test -d "$(readlink -f /var/backups/garrison/last-pre-upgrade)/etc"'
    check "no partly unpacked release is left" '! ls -A /opt/garrison/releases | grep -q "^\."'
    # Each killed upgrade may have left a backup; the last run removes the old ones.
    check "at most three releases are kept" 'test "$(ls /opt/garrison/releases | wc -l)" -le 3'
    check "at most four installer backups are kept" \
        'test "$(ls -d /var/backups/garrison/pre-* | wc -l)" -le 4'
}

# The installer run as `1` in the background, killed as SIGKILL kills it
# once its output says `2` and the shell command `3` has returned, before it
# said `4`, the end of what it was doing. What it started runs on, as it
# would after a lost terminal; the next run must finish all the same.
killed_once() {
    if ! inside "umask 077 && rm -f /root/late.log && { $1 > /root/late.log 2>&1 & echo \$! > /root/late.pid; } &&
        for i in \$(seq 1800); do grep -q -F '$2' /root/late.log && break; sleep 0.1; done &&
        grep -q -F '$2' /root/late.log && { $3; } && kill -KILL \$(cat /root/late.pid) &&
        ! grep -q -F '$4' /root/late.log"; then
        inside 'cat /root/late.log' || true
        echo "FAIL  the installer was not killed after it said \"$2\" and before \"$4\""
        exit 1
    fi
}

# Returns once the installer has waited a second for no command of its own:
# the eight seconds in which it watches the services settle.
settling='p=$(cat /root/late.pid); quiet=0
    for i in $(seq 900); do
        if [ -s /proc/$p/task/$p/children ]; then quiet=0; else quiet=$((quiet + 1)); fi
        [ "$quiet" -ge 10 ] && break
        sleep 0.1
    done
    [ "$quiet" -ge 10 ] && test -d /proc/$p'

scenario_killed_late() {
    step "Installers killed as they back up, while the services settle and as they switch back"
    upgraded
    before=$(events)
    # A reinstall backs up and settles as an upgrade does.
    for when in "as the backup begins:true" "during the backup:sleep 0.5" "while the services settle:$settling"; do
        killed_once '/root/release/bin/garrison install' 'Backing up the running state' "${when#*:}" ' is running. Roll back with'
        installer '/root/release/bin/garrison install'
        running "after a kill ${when%%:*}" "$new"
    done
    # A release whose web service does not start, as in failed_start: the
    # installer switches back to the release that ran, and is killed doing so.
    inside 'rm -rf /root/falling && cp -a /root/release /root/falling && cd /root/falling &&
        printf "%s+falling\n" "$(cat VERSION)" > VERSION &&
        sed -i "s|^ExecStart=/opt/garrison/current/bin/garrison web$|ExecStart=/opt/garrison/current/bin/garrison --config /etc/garrison/absent.toml web|" \
            deploy/systemd/garrison-web.service &&
        grep -q absent.toml deploy/systemd/garrison-web.service &&
        find . -type f ! -name SHA256SUMS | sed "s|^\./||" | sort | xargs sha256sum > SHA256SUMS'
    for pause in 0 1; do
        killed_once '/root/falling/bin/garrison install' 'switching back to the previous release' "sleep $pause" \
            'the previous release is running'
        installer '/root/release/bin/garrison install'
        running "after a kill $pause s into the switch back" "$new"
    done
    check "no event was lost" "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -ge $before"
    check "no partly unpacked release is left" '! ls -A /opt/garrison/releases | grep -q "^\."'
    check "the state to restore is complete" 'test -d "$(readlink -f /var/backups/garrison/last-pre-upgrade)/etc"'
}

scenario_reinstall() {
    step "Reinstalling the running release keeps the state to restore"
    upgraded
    inside 'readlink /var/backups/garrison/last-pre-upgrade > /root/last-before'
    installer '/root/release/bin/garrison install'
    check "a reinstall keeps last-pre-upgrade" \
        'test "$(readlink /var/backups/garrison/last-pre-upgrade)" = "$(cat /root/last-before)"'
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

scenario_warnings() {
    step "The installer and doctor say what check-config warns of"
    upgraded
    says "the installer passes check-config's warnings on as it starts the services" \
        '/root/release/bin/garrison install' \
        "Warning: deployment.public_origin https://admin.example.test is a placeholder"
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.warnings &&
        sed -i "s|^schema = 1\$|schema = 1\ncredentials_directory = \"/etc/garrison/elsewhere\"|" \
            /etc/garrison/garrison.toml'
    says "doctor warns of a setting the units do not follow" \
        '/opt/garrison/current/bin/garrison doctor || true' \
        "warn  credentials_directory is /etc/garrison/elsewhere, but the units load every credential"
    inside 'cat /root/garrison.toml.warnings > /etc/garrison/garrison.toml'
    running "after the warnings" "$new"
}

scenario_unloaded() {
    step "A secret its unit would not hand over stops the upgrade"
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.unloaded &&
        cp -p /etc/garrison/credentials/collector-native-key /etc/garrison/credentials/my-key &&
        printf "\n[collector]\nnative_key = \"credential:my-key\"\n" >> /etc/garrison/garrison.toml'
    check "the collector's unit hands it no credential of another name" \
        'systemctl start garrison-collect.service &&
            journalctl -u garrison-collect.service -n 30 --no-pager | grep -q "The collector API key is unavailable"'
    refused "the installer refuses a secret under a name its unit does not load" \
        '/root/release/bin/garrison install' \
        "garrison-collect.service loads this secret only as credential:collector-native-key"
    inside 'sed -i "s|^native_key = \"credential:my-key\"\$|native_key = \"/etc/garrison/credentials/my-key\"|" \
        /etc/garrison/garrison.toml'
    refused "the installer refuses a secret named by its path" '/root/release/bin/garrison install' \
        "collector.native_key names the file /etc/garrison/credentials/my-key"
    inside 'cat /root/garrison.toml.unloaded > /etc/garrison/garrison.toml &&
        rm /etc/garrison/credentials/my-key'
    services "after the refused secrets"
}

scenario_policy_elsewhere() {
    step "A policy kept where garrison.toml names it"
    upgraded
    catalog='printf "%s\n" "{\"op\": \"catalog\", \"token\": \"acceptance-token-0123456789abcdef\"}" |
        timeout 10 runuser -u garrison -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock'
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.policy && mkdir -p /etc/garrison-policy &&
        mv /etc/garrison/access-policy.json /etc/garrison-policy/access.json &&
        chmod 644 /etc/garrison-policy/access.json &&
        printf "\n[broker]\npolicy = \"/etc/garrison-policy/access.json\"\n" >> /etc/garrison/garrison.toml'
    says "the installer starts Garrison with the policy where garrison.toml names it" \
        '/root/release/bin/garrison install' "is running"
    check "the installer makes that policy root's, readable for the broker's group alone" \
        'test "$(stat -c "%U %G %a" /etc/garrison-policy/access.json)" = "root garrison-broker 640"'
    check "the broker grants by that policy" "$catalog | grep -q run_check"
    check "doctor finds that policy private" \
        '/opt/garrison/current/bin/garrison doctor | grep -q "ok    the access policy is private (640)"'
    # A folder named as the policy is none: the installer leaves it as it is
    # and refuses, and a purge would not take it.
    inside 'mkdir -p /srv/policy-folder/mail && echo kept > /srv/policy-folder/mail/inbox &&
        chmod 755 /srv/policy-folder &&
        sed -i "s|^policy = \"/etc/garrison-policy/access.json\"\$|policy = \"/srv/policy-folder\"|" \
            /etc/garrison/garrison.toml'
    refused "the installer refuses a policy that is a folder" '/root/release/bin/garrison install' \
        "Access policy not usable"
    check "and leaves that folder as it was" \
        'test "$(stat -c "%U %a" /srv/policy-folder)" = "root 755" && test -s /srv/policy-folder/mail/inbox'
    check "a purge would not remove it" \
        '/opt/garrison/current/bin/garrison uninstall --purge --dry-run > /root/purge-plan.log 2>&1 &&
            grep -q "Would remove /var/lib/garrison$" /root/purge-plan.log &&
            ! grep -q /srv/policy-folder /root/purge-plan.log'
    inside 'rm -r /srv/policy-folder /root/purge-plan.log'
    inside 'mv /etc/garrison-policy/access.json /etc/garrison/access-policy.json && rmdir /etc/garrison-policy &&
        cat /root/garrison.toml.policy > /etc/garrison/garrison.toml'
    installer '/root/release/bin/garrison install'
    running "after the policy elsewhere" "$new"
}

scenario_unwritten() {
    step "A file the installer could not write from the configuration is named"
    upgraded
    # A configuration that does not load, and no policy yet: not configured.
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.unwritten &&
        mv /etc/garrison/access-policy.json /root/access-policy.away &&
        sed -i "s|^schema = 1\$|schema = 1\nnonsense = 1|" /etc/garrison/garrison.toml'
    says "the installer names the polkit rule it could not write" '/root/release/bin/garrison install' \
        "/etc/polkit-1/rules.d/50-garrison.rules was not written, since"
    inside 'mv /root/access-policy.away /etc/garrison/access-policy.json &&
        cat /root/garrison.toml.unwritten > /etc/garrison/garrison.toml'
    installer '/root/release/bin/garrison install'
    running "after the unwritten file" "$new"
}

# Stalwart takes the new keys of a rotation that stops at their check, the
# old ones go all the same, and the services still hold the old secrets.
scenario_rotation() {
    step "Setting up again after a rotation that failed"
    upgraded
    setup='/opt/garrison/current/bin/garrison stalwart setup --skip-metrics --admin-credential /root/stalwart-admin.json'
    inside 'umask 077 && printf "{\"apiKey\": \"stand-in-administrator\"}" > /root/stalwart-admin.json'
    says "a rotation restarts the services that hold the secrets" "$setup --rotate" \
        "restarted with the new secrets"
    inside 'touch /root/stand-in-refuses'
    refused "a rotation whose keys Stalwart refuses stops" "$setup --rotate" \
        "The API keys that new ones replaced were removed"
    inside 'rm /root/stand-in-refuses'
    says "setup again restarts the services that still hold the replaced secrets" "$setup" \
        "restarted with the new secrets"
    check "the receiver holds the signature key of its file" \
        'test "$(cat /run/credentials/garrison-ingest.service/webhook-signature-key)" = \
            "$(cat /etc/garrison/credentials/webhook-signature-key)"'
    inside 'rm /root/stalwart-admin.json'
    running "after the rotation" "$new"
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
for scenario in ${SCENARIOS:-refusals failed_start crash_loop migrated_then_failed concurrent interrupted killed_late reinstall \
    rollback_without_state stopped_collector warnings unloaded policy_elsewhere unwritten rotation collect_beside}; do
    "scenario_$scenario"
done

step "Accepted: every failure path ended with a running Garrison"
