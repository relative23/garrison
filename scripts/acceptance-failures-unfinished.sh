# shellcheck shell=sh
# Sourced by scripts/acceptance-failures.sh: installers, rollbacks and
# restores killed at any point, then the same command again. They use that
# script's helpers and its `old` and `new`.
# shellcheck disable=SC2154

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
    # Whichever of the two ran before the last installer, the other one is
    # what a rollback returns to.
    names "previous is the other release" previous "$old"
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
    # A reinstall backs up and settles as an upgrade does. The backup a
    # killed installer started runs on, into the folder it named.
    for when in "as the backup begins:true" "during the backup:sleep 0.5" "while the services settle:$settling"; do
        killed_once '/root/release/bin/garrison install' 'Backing up the running state' "${when#*:}" ' is running. Roll back with'
        if ! installer '/root/release/bin/garrison install > /root/next.log 2>&1'; then
            inside 'cat /root/next.log' || true
            echo "FAIL  the installer after a kill ${when%%:*} succeeds"
            exit 1
        fi
        check "after a kill ${when%%:*}, the next run backs up into a folder of its own" \
            'folder() { sed -n "s|^==> Backing up the running state to ||p" "$1"; }
            test -n "$(folder /root/late.log)" && test "$(folder /root/late.log)" != "$(folder /root/next.log)" ||
                { echo "killed: $(folder /root/late.log), next: $(folder /root/next.log)"; false; }'
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
    earlier=$(inside 'readlink -f /opt/garrison/previous 2>/dev/null || true')
    for pause in 0 1; do
        killed_once '/root/falling/bin/garrison install' 'switching back to the previous release' "sleep $pause" \
            'the previous release is running'
        installer '/root/release/bin/garrison install'
        running "after a kill $pause s into the switch back" "$new"
        # Neither the release that fell nor the one that ran: the release
        # before, which a rollback returns to.
        check "after a kill $pause s into the switch back, previous is what it was before" \
            "test \"\$(readlink -f /opt/garrison/previous 2>/dev/null || true)\" = '$earlier'"
    done
    check "no event was lost" "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -ge $before"
    check "no partly unpacked release is left" '! ls -A /opt/garrison/releases | grep -q "^\."'
    check "the state to restore is complete" 'test -d "$(readlink -f /var/backups/garrison/last-pre-upgrade)/etc"'
}

# The command `1` run in the background, killed with its children as SIGKILL
# kills them once the shell condition `2` holds and `3` more seconds have
# passed, before it said `4`. Its children go too: `garrison upgrade` waits
# for the installer it started.
killed_at() {
    if ! inside "umask 077 && rm -f /root/late.log && { $1 > /root/late.log 2>&1 & echo \$! > /root/late.pid; } &&
        for i in \$(seq 1800); do { $2; } && break; sleep 0.1; done && { $2; } && sleep $3 &&
        p=\$(cat /root/late.pid) && kill -KILL \$(cat /proc/\$p/task/\$p/children 2>/dev/null) \$p &&
        ! grep -q -F '$4' /root/late.log"; then
        inside 'cat /root/late.log' || true
        echo "FAIL  the command was not killed once \"$2\" held and before it said \"$4\""
        exit 1
    fi
}

# A shell condition: `current` names release $1.
current_is() {
    printf '%s' "test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$1'"
}

# What `previous` resolves to, or nothing.
previous_now() { inside 'readlink -f /opt/garrison/previous 2>/dev/null || true'; }

# A copy of the release under test whose web service never comes up: its
# start waits until the start timeout ends it, as a service that never
# reports ready does.
hanging_release() {
    inside 'rm -rf /root/hanging && cp -a /root/release /root/hanging && cd /root/hanging &&
        printf "%s+hanging\n" "$(cat VERSION)" > VERSION &&
        sed -i "s|^\[Service\]$|[Service]\nExecStartPre=/bin/sleep 300|; s|^TimeoutStartSec=30$|TimeoutStartSec=10|" \
            deploy/systemd/garrison-web.service &&
        grep -q "^ExecStartPre=/bin/sleep 300$" deploy/systemd/garrison-web.service &&
        grep -q "^TimeoutStartSec=10$" deploy/systemd/garrison-web.service &&
        find . -type f ! -name SHA256SUMS | sed "s|^\./||" | sort | xargs sha256sum > SHA256SUMS'
    inside 'cat /root/hanging/VERSION'
}

scenario_upgrade_killed() {
    step "An upgrade killed once current named the new release, which does not start, then one more run"
    upgraded
    hanging=$(hanging_release)
    earlier=$(previous_now)
    killed_at '/root/hanging/bin/garrison install' "$(current_is "$hanging")" 2 'did not start'
    check "the killed upgrade had switched current" \
        "test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$hanging'"
    refused "the next run switches back to the release that ran" '/root/hanging/bin/garrison install' \
        "the previous release is running"
    running "after the killed upgrade" "$new"
    check "previous is what it was before the upgrade" "test \"\$(readlink -f /opt/garrison/previous 2>/dev/null || true)\" = '$earlier'"
    check "nothing is left unfinished" 'test ! -e /opt/garrison/unfinished.json'
}

scenario_upgrade_resumed() {
    step "An upgrade with garrison upgrade killed once current named the new release, then garrison upgrade again"
    # The release before the one under test runs again, installed from its
    # archive: only `garrison upgrade` refuses a release that is not newer.
    installer '/root/previous/bin/garrison install'
    archive=$(basename "$release")
    copy_in "$release" "/root/$archive"
    copy_in "$release.minisig" "/root/$archive.minisig"
    last=$(inside 'readlink -f /var/backups/garrison/last-pre-upgrade')
    killed_at "garrison upgrade /root/$archive" "$(current_is "$new")" 2 ' is running. Roll back with'
    check "the killed upgrade had switched current" \
        "test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$new'"
    says "garrison upgrade again finishes the upgrade it began" "garrison upgrade /root/$archive" \
        "Garrison $new is running. Roll back with: garrison install --rollback"
    running "after the killed garrison upgrade" "$new"
    check "previous names the release the upgrade began from" \
        "test \"\$(basename \"\$(readlink -f /opt/garrison/previous)\")\" = '$old'"
    check "the state to restore is the one from before the upgrade, not a copy made since" \
        "test \"\$(readlink -f /var/backups/garrison/last-pre-upgrade)\" != '$last' &&
            test \"\$(ls -d /var/backups/garrison/pre-upgrade-* | sort | tail -n 1)\" = \"\$(readlink -f /var/backups/garrison/last-pre-upgrade)\""
    inside "rm /root/$archive /root/$archive.minisig"
}

scenario_rollback_killed() {
    step "Rollbacks killed once they switched the links, then the same rollback again"
    for with in '' ' --restore-state'; do
        upgraded
        killed_at "/opt/garrison/current/bin/garrison install --rollback$with" "$(current_is "$old")" 2 'Rolled back to'
        says "running the rollback$with again finishes it" \
            "/opt/garrison/current/bin/garrison install --rollback$with" "Rolled back to $old."
        running "after the killed rollback$with" "$old"
        check "previous names the release the rollback$with left" \
            "test \"\$(basename \"\$(readlink -f /opt/garrison/previous)\")\" = '$new'"
        check "nothing is left unfinished" 'test ! -e /opt/garrison/unfinished.json'
    done
    upgraded
}

scenario_restore_killed() {
    step "A restore killed as it puts the state back, then the same restore again"
    upgraded
    installer '/opt/garrison/current/bin/garrison backup --to /root/kept-for-restore' >/dev/null
    # The checks store another batch: the state moves on after the backup.
    services "after the backup to restore"
    before=$(events)
    killed_at '/opt/garrison/current/bin/garrison restore --from /root/kept-for-restore' \
        'grep -q -F "Restoring Garrison state from" /root/late.log' 0 'Restored the state'
    first=$(inside 'ls -d /var/backups/garrison/pre-restore-* | sort | tail -n 1')
    # A copy made within the same second would take the first one's name.
    inside 'sleep 1.1'
    says "running the restore again finishes it and names the copy from before the first run" \
        '/opt/garrison/current/bin/garrison restore --from /root/kept-for-restore' "The state from before is in $first."
    check "that copy holds the state from before the first run" \
        "test \$(sqlite3 $first/ingest/events.sqlite 'SELECT count(*) FROM events') -eq $before"
    check "the next run made no copy of what the first had put back" \
        "test \"\$(ls -d /var/backups/garrison/pre-restore-* | sort | tail -n 1)\" = '$first'"
    running "after the killed restore" "$new"
    inside 'rm -r /root/kept-for-restore'
}

# A copy of the release under test under another version, which comes up.
another_release() {
    inside 'rm -rf /root/again && cp -a /root/release /root/again && cd /root/again &&
        printf "%s+again\n" "$(cat VERSION)" > VERSION &&
        find . -type f ! -name SHA256SUMS | sed "s|^\./||" | sort | xargs sha256sum > SHA256SUMS'
    inside 'cat /root/again/VERSION'
}

scenario_upgrade_came_up() {
    step "An upgrade killed once its new release came up, which then records, then another release's installer"
    upgraded
    # The upgrade's backup lists the status database as absent.
    inside 'systemctl stop garrison-collect.timer garrison-collect.service &&
        mv /var/lib/garrison/collector/status.sqlite /root/status.away'
    again=$(another_release)
    killed_at '/root/again/bin/garrison install' \
        "$(current_is "$again") && systemctl is-active --quiet garrison-web.service" 0 ' is running. Roll back with'
    check "the release of the killed upgrade runs and collects" \
        'systemctl is-active --quiet garrison-collect.timer && systemctl start garrison-collect.service &&
            systemctl start garrison-collect.service'
    first=$(inside 'sqlite3 -readonly /var/lib/garrison/collector/status.sqlite "SELECT min(collected_at) FROM snapshots"')
    if ! installer '/root/release/bin/garrison install > /root/came-up.log 2>&1'; then
        inside 'cat /root/came-up.log' || true
        echo "FAIL  the next installer after the upgrade that came up succeeds"
        exit 1
    fi
    check "what the release of the killed upgrade recorded stays" \
        "test \"\$(sqlite3 -readonly /var/lib/garrison/collector/status.sqlite 'SELECT min(collected_at) FROM snapshots')\" = '$first' ||
            { cat /root/came-up.log; false; }"
    check "the next installer says that it acts on nothing of that upgrade" \
        'grep -q "but Garrison was started since" /root/came-up.log && ! grep -q "Switching back" /root/came-up.log'
    names "it upgraded from the release that came up" previous "$again"
    running "after the upgrade that came up" "$new"
    # The links as the other scenarios take them: the release before, then this one.
    inside 'rm -r /root/status.away /root/again'
    installer '/root/previous/bin/garrison install'
    upgraded
}

# A signed batch of one event whose id is `1`, stored by the receiver.
stored_event() {
    inside_input 'cat > /usr/local/bin/acceptance-event && chmod 755 /usr/local/bin/acceptance-event' <<'EVENT'
#!/bin/sh
key=$(cat /etc/garrison/credentials/webhook-signature-key)
body="{\"events\": [{\"id\": \"$1\", \"createdAt\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"type\": \"auth.failed\", \"data\": {}}]}"
signature=$(printf %s "$body" | openssl dgst -sha256 -hmac "$key" -binary | base64)
curl -s -H "Content-Type: application/json" -H "X-Signature: $signature" \
    --data-binary "$body" http://127.0.0.1:8094/webhook | grep -q "\"stored\":1"
EVENT
    check "the receiver stores the event $1" "/usr/local/bin/acceptance-event $1"
}

# Whether the event history holds the event `1` as often as `2` says.
event_count() {
    printf '%s' "test \"\$(sqlite3 -readonly /var/lib/garrison/ingest/events.sqlite \
        \"SELECT count(*) FROM events WHERE event_id = '$1'\")\" $2"
}

scenario_rollback_state_killed() {
    step "A rollback with the state from before the upgrade killed as it puts it back, then what the next command names"
    upgraded
    # Recorded since the upgrade: the state from before it does not hold it.
    stored_event rolled-away-event
    killed_at '/opt/garrison/current/bin/garrison install --rollback --restore-state' \
        'grep -q -F "Restoring Garrison state from" /root/late.log' 0 'Rolled back to'
    refused "the next command names the rollback with the state" '/root/release/bin/garrison install' \
        "install --rollback --restore-state\` to finish it"
    says "the command it names finishes the rollback with the state" \
        "/opt/garrison/releases/$new/bin/garrison install --rollback --restore-state" "Rolled back to $old."
    check "the state from before the upgrade is back in full" "$(event_count rolled-away-event '= 0')"
    running "after the rollback killed as it put the state back" "$old"
    upgraded
}

scenario_rollback_came_up() {
    step "A rollback with the state from before the upgrade killed once its release came up, then its first line's command"
    upgraded
    killed_at '/opt/garrison/current/bin/garrison install --rollback --restore-state' \
        "$(current_is "$old") && systemctl is-active --quiet garrison-web.service" 0 'Rolled back to'
    # The release it went back to runs and records on the state that went back.
    stored_event rolled-back-event
    says "the command of its first line finishes the rollback" \
        "/opt/garrison/releases/$new/bin/garrison install --rollback --restore-state" "Rolled back to $old."
    check "what was recorded once it came up stays" "$(event_count rolled-back-event '-ge 1')"
    running "after the rollback that came up" "$old"
    upgraded
}

scenario_restore_came_up() {
    step "A restore killed once Garrison came up on the state it put back, which then records, then the same restore again"
    upgraded
    installer '/opt/garrison/current/bin/garrison backup --to /root/came-up-state' >/dev/null
    killed_at '/opt/garrison/current/bin/garrison restore --from /root/came-up-state' \
        'grep -q -F "Restoring Garrison state from" /root/late.log && systemctl is-active --quiet garrison-web.service' \
        0 'Restored the state'
    # Garrison runs on the state that went back and records what no copy holds.
    stored_event came-up-event
    if ! installer '/opt/garrison/current/bin/garrison restore --from /root/came-up-state > /root/came-up.log 2>&1'; then
        inside 'cat /root/came-up.log' || true
        echo "FAIL  the same restore again finishes"
        exit 1
    fi
    echo "ok    the same restore again finishes"
    check "and keeps a copy of what was recorded since the first run" \
        'newest=$(ls -d /var/backups/garrison/pre-restore-* | sort | tail -n 1) &&
            test "$(sqlite3 -readonly "$newest/ingest/events.sqlite" \
                "SELECT count(*) FROM events WHERE event_id = '"'came-up-event'"'")" -ge 1 ||
                { cat /root/came-up.log; false; }'
    running "after the restore that came up" "$new"
    inside 'rm -r /root/came-up-state'
}
