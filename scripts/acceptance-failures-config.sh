# shellcheck shell=sh
# Sourced by scripts/acceptance-failures.sh: the scenarios of the
# configuration the installer checks. The installer passes on what
# check-config warns of, names a file it could not write, refuses a secret
# its unit would not hand over and follows a policy kept elsewhere, but
# leaves a folder named as the policy as it is. They use that script's
# helpers and its `old` and `new`.
# shellcheck disable=SC2154

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
