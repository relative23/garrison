# shellcheck shell=sh
# Sourced by scripts/acceptance-failures.sh: what `garrison stalwart setup`
# and the installer leave between Garrison and Stalwart where a run fails
# or the two say different things. A rotation that failed is finished by
# the next run; the installer neither stops the macro filter while Stalwart
# still asks it nor moves it from the port Stalwart asks; the filter's unit
# writes nowhere.
# They use that script's helpers and its `new`.
# shellcheck disable=SC2154

# A rotation restarts each service with its new key before the key it
# replaces goes. One whose new key Stalwart refuses at its try stops before
# the service takes it up: the services keep their keys, which stay in
# Stalwart, and it names the run that finishes it, which replaces them.
scenario_rotation() {
    step "Setting up again after a rotation that failed"
    upgraded
    setup='/opt/garrison/current/bin/garrison stalwart setup --skip-metrics --admin-credential /root/stalwart-admin.json'
    inside 'umask 077 && printf "{\"apiKey\": \"stand-in-administrator\"}" > /root/stalwart-admin.json'
    if ! inside "umask 077 && $setup --rotate > /root/rotation.log 2>&1"; then
        inside 'cat /root/rotation.log' || true
        echo "FAIL  a rotation succeeds"
        exit 1
    fi
    check "a rotation restarts the broker with its new key" \
        'grep -q -F "garrison-broker restarted with the new secret." /root/rotation.log'
    check "a rotation restarts the receiver with its new key" \
        'grep -q -F "garrison-ingest restarted with the new secret." /root/rotation.log'
    inside 'cp /root/stand-in-keys /root/keys-before-rotation &&
        cp /etc/garrison/credentials/broker-native-key /root/broker-key-before && touch /root/stand-in-refuses'
    if inside "umask 077 && $setup --rotate > /root/rotation.log 2>&1"; then
        inside 'cat /root/rotation.log' || true
        echo "FAIL  a rotation whose keys Stalwart refuses stops"
        exit 1
    fi
    echo "ok    a rotation whose keys Stalwart refuses stops"
    check "the failed rotation leaves the broker the key it held" \
        'test "$(cat /run/credentials/garrison-broker.service/broker-native-key)" = "$(cat /root/broker-key-before)"'
    check "the failed rotation keeps the keys the services hold" \
        'for id in $(cut -d " " -f 1 /root/keys-before-rotation); do grep -q "^$id " /root/stand-in-keys || exit 1; done'
    check "the failed rotation names the run that finishes it" \
        'grep -q -F "Run \`garrison stalwart setup --rotate\` again once this is mended." /root/rotation.log'
    inside 'rm /root/stand-in-refuses /root/keys-before-rotation /root/broker-key-before /root/rotation.log'
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

scenario_milter_port() {
    step "The installer leaves the macro filter on the port Stalwart asks until setup moves it"
    upgraded
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.port &&
        printf "\n[milter]\n" >> /etc/garrison/garrison.toml'
    installer '/root/release/bin/garrison install'
    check "the filter listens on its port" 'ncat -z 127.0.0.1 8096'
    # Stalwart's entry asks that port, and the configuration names another,
    # as before `garrison stalwart setup` has moved the entry.
    inside 'printf "%s" "{\"id\": \"m1\", \"host\": \"127.0.0.1\", \"port\": 8096, \"enable\": true}" \
            > /root/stand-in-milters && printf "port = 8097\n" >> /etc/garrison/garrison.toml'
    says "the next installer run leaves the filter where Stalwart asks it, and names setup" \
        '/root/release/bin/garrison install' "\`garrison stalwart setup\` moves it to port 8097"
    check "and the filter still answers there" 'ncat -z 127.0.0.1 8096 && ! ncat -z 127.0.0.1 8097'
    inside 'rm /root/stand-in-milters'
    installer '/root/release/bin/garrison install'
    check "once nothing asks that port, the next run moves the filter" \
        'ncat -z 127.0.0.1 8097 && ! ncat -z 127.0.0.1 8096'
    inside 'cat /root/garrison.toml.port > /etc/garrison/garrison.toml'
    installer '/root/release/bin/garrison install'
    check "without the section the next run stops it" '! systemctl is-active --quiet garrison-milter.service'
    running "after the filter's port" "$new"
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
