# shellcheck shell=sh
# Sourced by scripts/acceptance-failures.sh: root's commands beside the
# installer where what they do depends on root and on the host. A test
# restore takes away the copies interrupted ones left in /var/tmp, and
# nothing of other users' there. `garrison access` follows no link that
# another user put in the policy's folder, makes a missing folder the broker
# can read, leaves a way in where no role of Stalwart's qualifies, and its
# profiles follow `[[actions]]`, which the broker takes once it restarts.
# They use that script's helpers and its `new`.
# shellcheck disable=SC2154

# The broker's answer to the administrator token of the Stalwart stand-in.
catalog='printf "%s\n" "{\"op\": \"catalog\", \"token\": \"acceptance-token-0123456789abcdef\"}" |
    timeout 10 runuser -u garrison -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock'

scenario_restore_leftovers() {
    step "A test restore takes away what interrupted ones left, and nothing of others"
    upgraded
    # restic as far as the test restore asks it.
    inside_input 'cat > /usr/local/bin/restic && chmod 755 /usr/local/bin/restic' <<'RESTIC'
#!/bin/sh
for word in "$@"; do
    case $word in snapshots | stats | restore) verb=$word; break ;; esac
done
case $verb in
    snapshots) printf '[{"time":"2026-11-16T02:00:04Z","id":"0039082a"}]' ;;
    stats) printf '{"total_size":4096}' ;;
    restore)
        while [ $# -gt 0 ]; do
            case $1 in --target) target=$2 ;; --include) path=$2 ;; esac
            shift
        done
        mkdir -p "$target$(dirname "$path")" && printf 'restored' > "$target$path" ;;
esac
RESTIC
    inside 'cd /var/tmp && mkdir -m 700 garrison-restore-00000000000000c1 &&
        mkdir -p garrison-restore-00000000000000c1/var/vmail && echo "a mail" > garrison-restore-00000000000000c1/var/vmail/inbox &&
        touch -d "-2 hours" garrison-restore-00000000000000c1 &&
        mkdir -m 700 garrison-restore-00000000000000c2 && echo "a mail" > garrison-restore-00000000000000c2/inbox &&
        runuser -u nobody -- mkdir -m 700 garrison-restore-00000000000000c3 &&
        runuser -u nobody -- touch -d "-2 hours" garrison-restore-00000000000000c3 &&
        runuser -u nobody -- ln -s /etc garrison-restore-00000000000000c4'
    says "a test restore removes the copy an interrupted one left" \
        '/opt/garrison/current/bin/garrison backup-check restic --repo /srv/repo --restore /etc/hosts --report /root/restic.json' \
        "Removed /var/tmp/garrison-restore-00000000000000c1, a copy of restored data that an interrupted test restore left."
    check "and leaves a copy that has just been made, another user's folder and a link of that name" \
        'cd /var/tmp && test ! -e garrison-restore-00000000000000c1 && test -s garrison-restore-00000000000000c2/inbox &&
            test "$(stat -c %U garrison-restore-00000000000000c3)" = nobody &&
            test -L garrison-restore-00000000000000c4 && test -s /etc/hosts &&
            test -z "$(find /var/tmp -maxdepth 1 -name "garrison-restore-*" -user root -newer /root/restic.json)"'
    inside 'cd /var/tmp && rm -r garrison-restore-00000000000000c2 garrison-restore-00000000000000c3 &&
        rm garrison-restore-00000000000000c4 /usr/local/bin/restic /root/restic.json'
    running "after the test restore" "$new"
}

scenario_access_links() {
    step "garrison access follows no link that another user put beside the policy"
    upgraded
    # A policy kept in a folder that nobody, a user of its own, can write.
    inside 'mkdir -p /srv/shared && chown nobody /srv/shared &&
        cp -p /etc/garrison/access-policy.json /srv/shared/access.json &&
        sed "s|^\[deployment\]$|[broker]\npolicy = \"/srv/shared/access.json\"\n\n[deployment]|" \
            /etc/garrison/garrison.toml > /root/shared.toml && grep -q /srv/shared /root/shared.toml &&
        printf "kept\n" > /etc/acceptance-target && chmod 644 /etc/acceptance-target &&
        runuser -u nobody -- ln -s /etc/acceptance-target /srv/shared/access.json.lock'
    refused "a lock that is a link is refused" \
        '/opt/garrison/current/bin/garrison --config /root/shared.toml access deny 5' \
        "/srv/shared/access.json.lock is a link, not the lock of \`garrison access\`"
    check "and what it names is as it was" \
        'test "$(cat /etc/acceptance-target)" = kept && test "$(stat -c %a /etc/acceptance-target)" = 644 &&
            test -L /srv/shared/access.json.lock'
    # Links at every name a backup may take in the next seconds.
    inside 'rm /srv/shared/access.json.lock && now=$(date -u +%s) &&
        for second in 0 1 2 3 4 5; do
            stamp=$(date -u -d "@$((now + second))" +%Y%m%dT%H%M%S)
            runuser -u nobody -- ln -s /etc/acceptance-target "/srv/shared/access.json.$stamp.bak"
        done'
    says "a backup takes a name nothing has" \
        '/opt/garrison/current/bin/garrison --config /root/shared.toml access deny 5' "the previous file is kept as /srv/shared/access.json."
    check "and writes through no link: what they name is as it was" \
        'test "$(cat /etc/acceptance-target)" = kept && test "$(stat -c %a /etc/acceptance-target)" = 644'
    check "the policy is root's and the broker's group's, its backup root's alone" \
        'test "$(stat -c "%U %G %a" /srv/shared/access.json)" = "root garrison-broker 640" &&
            backup=$(find /srv/shared -maxdepth 1 -type f -name "access.json.*.bak") &&
            test "$(stat -c "%U %a" $backup)" = "root 600" && grep -q "\"5\"" /srv/shared/access.json'
    inside 'rm -r /srv/shared /etc/acceptance-target /root/shared.toml'
    running "after the links beside the policy" "$new"
}

scenario_access_folder() {
    step "garrison access init makes the policy's folder and leaves a way in without an administrator role"
    upgraded
    inside 'sed "s|^\[deployment\]$|[broker]\npolicy = \"/etc/garrison/policy/access.json\"\n\n[deployment]|" \
        /etc/garrison/garrison.toml > /root/folder.toml && grep -q /etc/garrison/policy /root/folder.toml'
    # The stand-in names no default administrator role.
    refused "init without an administrator role says how to bind one" \
        '/opt/garrison/current/bin/garrison --config /root/folder.toml access init' \
        "garrison access bind-role <role-id> --profile administrator"
    check "init made the folder, readable for the broker under umask 077, and the policy in it" \
        'test "$(stat -c "%U %a" /etc/garrison/policy)" = "root 755" &&
            test "$(stat -c "%U %G %a" /etc/garrison/policy/access.json)" = "root garrison-broker 640" &&
            grep -q "\"roleBindings\": {}" /etc/garrison/policy/access.json'
    check "bind-role binds the administrators' role in it" \
        '/opt/garrison/current/bin/garrison --config /root/folder.toml access bind-role e --profile administrator'
    # The stand-in's role e lacks two of the rights the default administrator
    # profile requires: a broker that reads the policy refuses its user (403),
    # one that cannot read it is not set up (503), as where the folder were
    # made under the umask alone.
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.commands &&
        cp /root/folder.toml /etc/garrison/garrison.toml && systemctl restart garrison-broker'
    check "the broker reads the policy in the folder init made" "$catalog | grep -E -q '\"status\": ?403'"
    inside 'chmod 700 /etc/garrison/policy'
    check "where that folder were the umask's 700, it could not" "$catalog | grep -E -q '\"status\": ?503'"
    inside 'cat /root/garrison.toml.commands > /etc/garrison/garrison.toml && rm -r /etc/garrison/policy /root/folder.toml &&
        systemctl restart garrison-broker'
    running "after the policy in a folder init made" "$new"
}

scenario_access_actions() {
    step "The profiles follow [[actions]]"
    upgraded
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.actions &&
        printf "\n[[actions]]\nid = \"run_other\"\ntitle = \"Run another check\"\ndescription = \"Starts the test unit.\"\nconfirmation = \"RUN OTHER\"\nunit = \"acceptance-check.service\"\noperation = \"start\"\ncooldown_seconds = 0\ntimeout_seconds = 30\noperator = true\n" \
            >> /etc/garrison/garrison.toml'
    says "update gives the administrator profile an action added later" \
        '/opt/garrison/current/bin/garrison access update' "Profile administrator: run_other added."
    check "the broker offers it once it restarts with the polkit rule written again" \
        "sh -c 'garrison polkit-rule > /etc/polkit-1/rules.d/50-garrison.rules' && systemctl restart garrison-broker &&
            $catalog | grep -q run_other"
    inside 'cat /root/garrison.toml.actions > /etc/garrison/garrison.toml'
    refused "a policy that names an action garrison.toml no longer has says what takes it out" \
        '/opt/garrison/current/bin/garrison access list' "run \`garrison access update\`, which takes it out"
    says "update takes it out" '/opt/garrison/current/bin/garrison access update' "Profile administrator: run_other taken out."
    check "and the installer's check of the configuration takes the policy again" \
        '/opt/garrison/current/bin/garrison check-config && ! grep -q run_other /etc/garrison/access-policy.json'
    inside "sh -c 'garrison polkit-rule > /etc/polkit-1/rules.d/50-garrison.rules' && systemctl restart garrison-broker &&
        rm /root/garrison.toml.actions /root/garrison.toml.commands"
    running "after the actions changed" "$new"
}
