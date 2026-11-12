#!/bin/sh
# The installer's failure paths on a disposable host: a refusal changes
# nothing, a failure after the services stopped ends with a running Garrison,
# and an installer killed at any point leaves nothing a later run cannot
# finish. Beside the installer: a collector that stops is reported.
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

# A stand-in for ntfy on https://localhost:8443 that keeps what it is sent,
# with a certificate the collector's and the watch's units are told to trust.
ntfy_stand_in() {
    inside_input 'cat > /root/ntfy.sh' <<'NTFY'
#!/bin/sh
# One request: keep its body, answer 200.
length=0
while IFS= read -r line; do
    line=$(printf %s "$line" | tr -d '\r')
    [ -n "$line" ] || break
    case $line in [Cc]ontent-[Ll]ength:*) length=${line#*: } ;; esac
done
head -c "$length" >> /root/ntfy-bodies
echo >> /root/ntfy-bodies
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
NTFY
    inside 'cd /root && : > ntfy-bodies &&
        openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out /etc/acceptance-ca.crt \
            -days 2 -subj "/CN=Acceptance CA" 2>/dev/null &&
        openssl req -newkey rsa:2048 -nodes -keyout ntfy.key -out ntfy.csr -subj /CN=localhost 2>/dev/null &&
        printf "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n" > ntfy.ext &&
        openssl x509 -req -in ntfy.csr -CA /etc/acceptance-ca.crt -CAkey ca.key -CAcreateserial \
            -days 2 -extfile ntfy.ext -out ntfy.crt 2>/dev/null &&
        for unit in garrison-collect garrison-watch; do
            mkdir -p /etc/systemd/system/$unit.service.d &&
            printf "[Service]\nEnvironment=SSL_CERT_FILE=/etc/acceptance-ca.crt\n" \
                > /etc/systemd/system/$unit.service.d/acceptance.conf
        done &&
        systemctl daemon-reload &&
        if command -v ncat >/dev/null 2>&1; then
            systemd-run --quiet --unit=acceptance-ntfy ncat --ssl --ssl-cert /root/ntfy.crt \
                --ssl-key /root/ntfy.key -lk 127.0.0.1 8443 --sh-exec "sh /root/ntfy.sh"
        else
            systemd-run --quiet --unit=acceptance-ntfy socat \
                OPENSSL-LISTEN:8443,bind=127.0.0.1,reuseaddr,fork,cert=/root/ntfy.crt,key=/root/ntfy.key,verify=0 \
                SYSTEM:"sh /root/ntfy.sh"
        fi'
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

start_host
install_previous
old=$(inside 'cat /root/previous/VERSION')
new=$(inside 'cat /root/release/VERSION')
running "installed" "$old"
for scenario in ${SCENARIOS:-refusals failed_start crash_loop concurrent interrupted reinstall rollback_without_state \
    stopped_collector}; do
    "scenario_$scenario"
done

step "Accepted: every failure path ended with a running Garrison"
