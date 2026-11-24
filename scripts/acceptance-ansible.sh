#!/bin/sh
# The Ansible role (deploy/ansible) against a virtual machine: a first
# installation, a second run and a dry run that change nothing, an upgrade by
# version, and plays that stop on the way or find the host changed, each
# finished by the next play.
#
#   HOST=vm [DISTRO=debian-13] [ANSIBLE=ansible-playbook] [SCENARIOS="..."] \
#       scripts/acceptance-ansible.sh OUT-DIR
#
# OUT-DIR is what scripts/signed-releases.sh wrote; the role checks those
# archives against their throwaway key. The host and the stand-in for
# Stalwart: scripts/acceptance-lib.sh. SCENARIOS names the scenarios, run in
# that order after the upgrade.
set -eu

out=$(cd "$1" && pwd)
arch=${ARCH:-x86_64}
older=$(sed -n 1p "$out/versions")
newer=$(sed -n 2p "$out/versions")
previous=$out/garrison-$older-$arch.tar.gz
release=$out/garrison-$newer-$arch.tar.gz
ansible=${ANSIBLE:-ansible-playbook}
roles=$(cd "$(dirname "$0")/../deploy/ansible" && pwd)
# shellcheck source=scripts/acceptance-lib.sh
. "$(dirname "$0")/acceptance-lib.sh"
if [ "$host" != vm ]; then
    echo "acceptance-ansible.sh needs a virtual machine: HOST=vm" >&2
    exit 2
fi

start_host
work=$(mktemp -d "${TMPDIR:-/var/tmp}/garrison-ansible.XXXXXX")
trap 'cleanup; rm -rf "$work"' EXIT
mkdir "$work/archives"
cp "$out"/garrison-*-"$arch".tar.gz "$out"/garrison-*-"$arch".tar.gz.minisig "$work/archives/"
printf 'vm ansible_host=127.0.0.1 ansible_port=%s ansible_user=root ansible_ssh_private_key_file=%s ansible_ssh_common_args="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"\n' \
    "$vm_port" "$vm_dir/key" > "$work/inventory"
# The stand-in names no administrator role for `access init` to bind, so the
# play writes the policy that init writes where Stalwart names one, unless a
# scenario sets acceptance_policy to false. acceptance_config is added to the
# configuration; acceptance_ignore_errors is the play's ignore_errors.
cat > "$work/site.yml" <<EOF
- hosts: vm
  become: true
  ignore_errors: "{{ acceptance_ignore_errors }}"
  vars:
    acceptance_policy: true
    acceptance_config: ""
    acceptance_ignore_errors: false
  pre_tasks:
    - name: The unit the test action starts
      ansible.builtin.copy:
        content: "[Service]\nType=oneshot\nExecStart=/usr/bin/true\n"
        dest: /etc/systemd/system/acceptance-check.service
        mode: "0644"
    - name: The access policy, as access init writes it where Stalwart names a role
      ansible.builtin.shell: |
        mkdir -p /etc/garrison && cat > /etc/garrison/access-policy.json <<'POLICY'
        {"schemaVersion": 1, "profiles": {"administrator": {"modules": ["dashboard", "actions"],
         "actions": ["run_check"], "requiredNativePermissions": ["authenticate", "sysActionCreate", "sysRoleUpdate"]}},
         "roleBindings": {"e": "administrator"}, "subjects": {}, "deniedSubjects": []}
        POLICY
      args:
        creates: /etc/garrison/access-policy.json
      when: acceptance_policy | bool
  roles:
    - role: garrison
      vars:
        garrison_archives: "$work/archives"
        garrison_signing_key: "$(tail -n 1 "$out/test.pub")"
        garrison_public_origin: "https://admin.example.test"
        garrison_issuer: "https://mail.example.test"
        garrison_stalwart_url: "http://127.0.0.1:8099"
        garrison_stalwart_admin: {apiKey: stand-in-administrator}
        garrison_extra_config: |
          [[actions]]
          id = "run_check"
          title = "Run a check"
          description = "Starts the test unit."
          confirmation = "RUN CHECK"
          unit = "acceptance-check.service"
          operation = "start"
          cooldown_seconds = 0
          timeout_seconds = 30
          [[providers]]
          type = "host"
          [[providers]]
          type = "host-care"
          [[providers]]
          type = "senders"
          [[providers]]
          type = "mail-flow"
          [[providers]]
          type = "systemd"
          units = [{ unit = "garrison-web.service", label = "Web", modules = ["services"] }]
          [[providers]]
          type = "version-command"
          component = "systemd"
          command = ["/usr/bin/systemctl", "--version"]
          pattern = "^systemd ([0-9]+)"
          modules = ["services"]
          {{ acceptance_config }}
EOF

# `run_play VERSION [ARGUMENTS]`: the play for that release, with further
# arguments for ansible-playbook; what it printed is in $log.
plays=0
run_play() {
    plays=$((plays + 1))
    log=$work/play-$plays.log
    version=$1
    shift
    ANSIBLE_ROLES_PATH=$roles ANSIBLE_HOST_KEY_CHECKING=False \
        "$ansible" -i "$work/inventory" "$work/site.yml" -e "garrison_version=$version" "$@" > "$log" 2>&1
}

# The play succeeds; the recap's changed count goes to $changed.
play() {
    if ! run_play "$@"; then
        tail -n 40 "$log"
        echo "FAIL  the play for $1 succeeds"
        exit 1
    fi
    changed=$(sed -n 's/.*changed=\([0-9]*\).*/\1/p' "$log" | tail -n 1)
    echo "ok    the play for $1 succeeds ($changed changed)"
}

# `unchanged WHAT VERSION [ARGUMENTS]`: the play succeeds and changes nothing.
unchanged() {
    what=$1
    shift
    play "$@"
    if [ "$changed" != 0 ]; then
        awk '/^TASK /{task = $0} /^changed:/{print task}' "$log"
        echo "FAIL  $what ($changed changed)"
        exit 1
    fi
    echo "ok    $what"
}

# `stops VERSION WORDS [ARGUMENTS]`: the play fails, and what it printed
# says why in WORDS.
stops() {
    version=$1
    words=$2
    shift 2
    if run_play "$version" "$@"; then
        tail -n 40 "$log"
        echo "FAIL  the play for $version stops"
        exit 1
    fi
    if ! grep -F -q -- "$words" "$log"; then
        tail -n 40 "$log"
        echo "FAIL  the play for $version says why it stops: $words"
        exit 1
    fi
    echo "ok    the play for $version stops and says: $words"
}

# The last play said WORDS.
said() {
    if ! grep -F -q -- "$1" "$log"; then
        tail -n 40 "$log"
        echo "FAIL  the play said: $1"
        exit 1
    fi
    echo "ok    the play said: $1"
}

# No secret is in what the play printed: not the administrator that went in
# on standard input, not a key the stand-in handed out, not the webhook's key
# or the scrape credential as their files hold them.
nothing_secret() {
    for file in webhook-signature-key collector-native-key broker-native-key; do
        secret=$(inside "cat /etc/garrison/credentials/$file 2>/dev/null || true")
        if [ -n "$secret" ] && grep -F -q -- "$secret" "$log"; then
            echo "FAIL  the play shows no secret, but $file is in what it printed"
            exit 1
        fi
    done
    secret=$(inside 'sed -n '\''s/.*"secret":"\([^"]*\)".*/\1/p'\'' /etc/garrison/credentials/metrics-credential')
    if [ -n "$secret" ] && grep -F -q -- "$secret" "$log"; then
        echo "FAIL  the play shows no secret, but the scrape credential is in what it printed"
        exit 1
    fi
    if grep -E -q 'stand-in-administrator|stand-in-k[0-9]+-secret' "$log"; then
        echo "FAIL  the play shows no secret, but the administrator or a key's secret is in what it printed"
        exit 1
    fi
    echo "ok    the play shows no secret"
}

# A host without Garrison, as before its first play: purged, and without
# what the role and the scenarios left in /root.
fresh() {
    if ! inside '/opt/garrison/current/bin/garrison uninstall --purge >/dev/null &&
        rm -rf /root/garrison-* /root/stand-in-keys'; then
        echo "FAIL  Garrison is taken off the host for the next scenario"
        exit 1
    fi
}

# Setup fails at its last step, after it wrote every key file: the stand-in
# refuses the keys' sessions, as Stalwart refuses a key it does not take.
scenario_setup_refused() {
    step "A setup that fails says why and shows no secret"
    inside 'cd /etc/garrison/credentials && rm webhook-signature-key collector-native-key broker-native-key &&
        touch /root/stand-in-refuses'
    # At -vvv a task without no_log shows what went in on its standard input.
    stops "$newer" "Stalwart does not take the API key it just made" -vvv
    nothing_secret
    inside 'rm /root/stand-in-refuses'
    play "$newer"
    said "Stalwart accepts both API keys from this host"
    services "after a setup that failed"
    unchanged "a further run changes nothing" "$newer"
}

# garrison.toml keeps the policy in a folder of its own.
scenario_policy_elsewhere() {
    step "A policy kept elsewhere is found there"
    inside 'mkdir -m 755 /etc/garrison/policy && mv /etc/garrison/access-policy.json /etc/garrison/policy/access.json'
    cat > "$work/elsewhere.yml" <<'VARS'
acceptance_policy: false
acceptance_config: |
  [broker]
  policy = "/etc/garrison/policy/access.json"
VARS
    play "$newer" -e "@$work/elsewhere.yml"
    said "Stalwart accepts both API keys from this host"
    check "the installer took the policy there" \
        '/opt/garrison/current/bin/garrison check-config 2>/dev/null | grep -q "Access policy valid: /etc/garrison/policy/access.json"'
    services "with the policy kept elsewhere"
    unchanged "a further run changes nothing" "$newer" -e "@$work/elsewhere.yml"
    inside 'mv /etc/garrison/policy/access.json /etc/garrison/access-policy.json && rmdir /etc/garrison/policy'
}

# An unpacking cut short after its first files: tar writes SHA256SUMS and
# VERSION before the programs.
scenario_unpack_cut() {
    step "An unpacking cut short is done again"
    fresh
    name=garrison-$older-$arch
    copy_in "$previous" "/root/$name.tar.gz"
    inside "cd /root && chmod 600 $name.tar.gz && tar -xzf $name.tar.gz $name/SHA256SUMS $name/VERSION"
    play "$older"
    services "after an unpacking cut short"
    unchanged "a further run changes nothing" "$older"
}

# The web service fails to start, as where another program holds its port.
unstartable() {
    inside 'mkdir -p /etc/systemd/system/garrison-web.service.d &&
        printf "[Service]\nExecStartPre=/bin/false\n" > /etc/systemd/system/garrison-web.service.d/acceptance.conf &&
        systemctl daemon-reload'
}
startable() { inside 'rm -r /etc/systemd/system/garrison-web.service.d && systemctl daemon-reload'; }

# The first play stops at access init, which finds no administrator role
# to bind; the operator binds one as it says, and the next play starts
# Garrison.
scenario_unbound() {
    step "A first play that stopped at access init is finished by the next"
    fresh
    stops "$older" "garrison access bind-role" -e acceptance_policy=false
    stops "$older" "binds no role and no account" -e acceptance_policy=false
    inside '/opt/garrison/current/bin/garrison access bind-role e --profile administrator >/dev/null'
    play "$older" -e acceptance_policy=false
    services "after a first play that stopped at access init"
    unchanged "a further run changes nothing" "$older" -e acceptance_policy=false
}

# The first install stopped before its last step, which makes /etc/garrison:
# the next play installs again and goes on to access init.
scenario_first_unfinished() {
    step "A first install that did not finish is done again"
    fresh
    name=garrison-$older-$arch
    copy_in "$previous" "/root/$name.tar.gz"
    inside "cd /root && chmod 600 $name.tar.gz && tar -xzf $name.tar.gz &&
        $name/bin/garrison install </dev/null >/dev/null && rm -r /etc/garrison"
    stops "$older" "garrison access bind-role" -e acceptance_policy=false
    inside '/opt/garrison/current/bin/garrison access bind-role e --profile administrator >/dev/null'
    play "$older" -e acceptance_policy=false
    services "after a first install that did not finish"
    unchanged "a further run changes nothing" "$older" -e acceptance_policy=false
}

# The installer needs room only where it copies the state, before another
# release starts on it: a changed configuration of the running release is in
# force after one play without that room, an upgrade without it is refused
# before anything changes, and the next play, once there is room, finishes it.
scenario_no_room() {
    step "An upgrade the installer had no room for is finished by the next play"
    inside 'cp /etc/systemd/system/acceptance-check.service /etc/systemd/system/acceptance-other.service &&
        free=$(df --output=avail -B 1 /opt | tail -n 1) && fallocate -l $((free - 31457280)) /root/filled'
    cat > "$work/other.yml" <<'VARS'
acceptance_config: |
  [[actions]]
  id = "run_other"
  title = "Run another check"
  description = "Starts the other test unit."
  confirmation = "RUN OTHER"
  unit = "acceptance-other.service"
  operation = "start"
  cooldown_seconds = 0
  timeout_seconds = 30
VARS
    play "$newer" -e "@$work/other.yml"
    check "a changed configuration of the running release is in force without room for a copy" \
        'grep -q acceptance-other.service /etc/polkit-1/rules.d/50-garrison.rules'
    inside '/opt/garrison/current/bin/garrison install --rollback >/dev/null'
    names "a rollback by hand returned to $older" current "$older"
    stops "$newer" "MiB free and the installation needs" -e "@$work/other.yml"
    names "the upgrade without room left $older current" current "$older"
    check "the upgrade without room left $older running" 'systemctl is-active --quiet garrison-web.service'
    inside 'rm /root/filled'
    play "$newer" -e "@$work/other.yml"
    names "the next play finished the upgrade to $newer" current "$newer"
    services "after an upgrade that had no room"
    unchanged "a further run changes nothing" "$newer" -e "@$work/other.yml"
}

# An upgrade whose new release does not start, nor the one it switches back
# to: the installer leaves the links at the new release, and the next play,
# once the service starts again, finishes the upgrade.
scenario_upgrade_failed() {
    step "An upgrade that did not start is finished by the next play"
    inside '/opt/garrison/current/bin/garrison install --rollback >/dev/null'
    names "a rollback by hand returned to $older" current "$older"
    unstartable
    stops "$newer" "did not start"
    startable
    play "$newer"
    names "the play finished the upgrade to $newer" current "$newer"
    services "after an upgrade that did not start"
    unchanged "a further run changes nothing" "$newer"
}

# garrison.toml changed and installed by hand: the play puts the role's file
# back and installs it, so that the hand's action is gone again.
scenario_hand_changed() {
    step "A configuration changed by hand is put back into force"
    inside "cp /etc/systemd/system/acceptance-check.service /etc/systemd/system/acceptance-hand.service &&
        printf '%s\n' '[[actions]]' 'id = \"run_by_hand\"' 'title = \"Run a check by hand\"' \
            'description = \"Starts the hand test unit.\"' 'confirmation = \"RUN BY HAND\"' \
            'unit = \"acceptance-hand.service\"' 'operation = \"start\"' 'cooldown_seconds = 0' \
            'timeout_seconds = 30' >> /etc/garrison/garrison.toml &&
        /root/garrison-$newer-$arch/bin/garrison install </dev/null >/dev/null"
    check "the installer run by hand took the hand's action" \
        'grep -q acceptance-hand.service /etc/polkit-1/rules.d/50-garrison.rules'
    play "$newer"
    check "the play put the role's configuration back into force" \
        '! grep -q acceptance-hand.service /etc/polkit-1/rules.d/50-garrison.rules'
    services "after a configuration changed by hand"
    unchanged "a further run changes nothing" "$newer"
}

# The play's archive built again with one more file, as a test archive can be
# under one version: the play unpacks it and installs what it holds.
scenario_rebuilt() {
    step "An archive of the same version built again is installed"
    name=garrison-$newer-$arch
    rm -rf "$work/rebuilt" && mkdir "$work/rebuilt" && tar -xzf "$release" -C "$work/rebuilt"
    echo rebuilt > "$work/rebuilt/$name/docs/acceptance-rebuilt.txt"
    (cd "$work/rebuilt/$name" && sha256sum docs/acceptance-rebuilt.txt >> SHA256SUMS)
    tar -czf "$work/archives/$name.tar.gz" -C "$work/rebuilt" "$name"
    minisign -S -s "$out/test.key" -m "$work/archives/$name.tar.gz" -t "garrison $newer $arch" \
        </dev/null >/dev/null
    play "$newer"
    check "the play installed the archive built again" \
        'test -f /opt/garrison/current/share/docs/acceptance-rebuilt.txt'
    services "after an archive built again"
    unchanged "a further run changes nothing" "$newer"
}

# A play that goes on past a failed task, as one with ignore_errors does to
# reach the other hosts: the next play runs again the installer whose start
# failed, and Garrison runs.
scenario_ignored() {
    step "An installer that failed under ignore_errors runs again in the next play"
    edit='{"acceptance_config": "# changed by a play under ignore_errors"}'
    unstartable
    play "$newer" -e "$edit" -e '{"acceptance_ignore_errors": true}'
    said "did not start"
    startable
    play "$newer" -e "$edit"
    services "after an installer that failed under ignore_errors"
    unchanged "a further run changes nothing" "$newer" -e "$edit"
}

# The stand-in for Stalwart, which systemd-run started, once the guest
# restarted.
stand_in_again() {
    inside 'if command -v ncat >/dev/null 2>&1; then
            systemd-run --quiet --unit=acceptance-stalwart ncat -lk 127.0.0.1 8099 --sh-exec "sh /root/stalwart-stub.sh"
        else
            systemd-run --quiet --unit=acceptance-stalwart \
                socat TCP-LISTEN:8099,bind=127.0.0.1,reuseaddr,fork SYSTEM:"sh /root/stalwart-stub.sh"
        fi'
}

# The guest restarts at once, as after a power cut, while the play's second
# install runs: the role's configuration is written and an installer runs.
scenario_restart() {
    step "A play cut by a restart is finished by the next"
    fresh
    ANSIBLE_ROLES_PATH=$roles ANSIBLE_HOST_KEY_CHECKING=False timeout 900 \
        "$ansible" -i "$work/inventory" "$work/site.yml" -e "garrison_version=$older" > "$work/cut.log" 2>&1 &
    cut=$!
    attempt=0
    until inside 'grep -qs "Written by the Ansible role" /etc/garrison/garrison.toml &&
        pgrep -f "bin/garrison[ ]install" >/dev/null'; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 600 ] || ! kill -0 "$cut" 2>/dev/null; then
            tail -n 40 "$work/cut.log"
            echo "FAIL  the play's second install is caught running"
            exit 1
        fi
        sleep 0.2
    done
    inside 'nohup systemctl reboot --force --force >/dev/null 2>&1 &' || true
    sleep 10
    vm_wait || exit 1
    # Its connection went with the guest; the shell's notice of the signal is
    # no check.
    { kill "$cut"; wait "$cut"; } 2>/dev/null || true
    echo "ok    the guest restarted while the play's second install ran"
    stand_in_again
    play "$older"
    services "after a play cut by a restart"
    unchanged "a further run changes nothing" "$older"
}

step "The play and the role are valid"
if ! ANSIBLE_ROLES_PATH=$roles "$ansible" --syntax-check -i "$work/inventory" "$work/site.yml" > "$work/syntax.log" 2>&1; then
    cat "$work/syntax.log"
    echo "FAIL  ansible-playbook --syntax-check passes"
    exit 1
fi
echo "ok    ansible-playbook --syntax-check passes"

step "The role installs and starts Garrison"
play "$older"
check "the role installed $older" "test \"\$(cat /opt/garrison/current/VERSION)\" = '$older'"
services "installed by the role"

step "A second run changes nothing"
unchanged "a second run changes nothing" "$older"
unchanged "a dry run changes nothing" "$older" --check

step "A new version upgrades"
play "$newer"
check "the role upgraded to $newer" "test \"\$(cat /opt/garrison/current/VERSION)\" = '$newer'"
services "upgraded by the role"

all="setup_refused policy_elsewhere no_room upgrade_failed hand_changed rebuilt ignored
    unbound unpack_cut first_unfinished restart"
for scenario in ${SCENARIOS:-$all}; do
    "scenario_$scenario"
done

step "Accepted: the role installs, keeps and upgrades Garrison, and finishes plays that stopped"
