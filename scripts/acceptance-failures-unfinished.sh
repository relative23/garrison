# shellcheck shell=sh
# Sourced by scripts/acceptance-failures.sh: installers killed at any point,
# early or as they back up, wait for the services to settle or switch back,
# then one more run. They use that script's helpers and its `old` and `new`.
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
