# shellcheck shell=sh
# Sourced by scripts/acceptance-failures.sh: what `garrison stalwart setup`
# leaves between Garrison and Stalwart where a run fails: a rotation that
# failed is finished by the next run.
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
        'grep -F "[setup-restarted]" /root/rotation.log | grep -q -F garrison-broker'
    check "a rotation restarts the receiver with its new key" \
        'grep -F "[setup-restarted]" /root/rotation.log | grep -q -F garrison-ingest'
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
        'acceptance-state /root/rotation.log setup-key-untaken &&
            grep -q -F "\`garrison stalwart setup --rotate\`" /root/rotation.log'
    inside 'rm /root/stand-in-refuses /root/keys-before-rotation /root/broker-key-before /root/rotation.log'
    says "setup again once Stalwart takes the keys" "$setup" setup-reloaded
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
