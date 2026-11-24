#!/bin/sh
# The Ansible role (deploy/ansible) against a virtual machine: a first
# installation, a second run that changes nothing, an upgrade by version, and
# plays that stop on the way, each finished by the next play.
#
#   HOST=vm [DISTRO=debian-13] [ANSIBLE=ansible-playbook] [SCENARIOS="..."] \
#       scripts/acceptance-ansible.sh OUT-DIR
#
# OUT-DIR is what scripts/signed-releases.sh wrote; the role checks those
# archives against their throwaway key. The host and the stand-in for
# Stalwart: scripts/acceptance-lib.sh. SCENARIOS names the plays that stop on
# the way, run in that order after the upgrade.
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
# Setup reads the account that each /get answer names, as Stalwart 1.1.0's
# answers do; where the stand-in leaves it out, it is added.
inside 'grep -q accountId /root/stalwart-stub.sh ||
    sed -i '\''s/{\\"list\\": \[/{\\"accountId\\": \\"b\\", \\"list\\": [/'\'' /root/stalwart-stub.sh'
# The stand-in names no administrator role for `access init` to bind, so the
# play writes the policy that init writes where Stalwart names one, unless a
# scenario sets acceptance_policy to false. acceptance_config is added to the
# configuration.
cat > "$work/site.yml" <<EOF
- hosts: vm
  become: true
  vars:
    acceptance_policy: true
    acceptance_config: ""
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

# Setup fails at its last step, after it wrote every key file: the stand-in
# refuses the keys' sessions, as Stalwart refuses a key it does not take.
scenario_setup_refused() {
    step "A setup that fails says why and shows no secret"
    inside 'cd /etc/garrison/credentials && rm webhook-signature-key collector-native-key broker-native-key &&
        touch /root/stand-in-refuses'
    stops "$newer" "Stalwart does not take the API key it just made"
    nothing_secret
    inside 'rm /root/stand-in-refuses'
    play "$newer"
    services "after a setup that failed"
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

step "A new version upgrades"
play "$newer"
check "the role upgraded to $newer" "test \"\$(cat /opt/garrison/current/VERSION)\" = '$newer'"
services "upgraded by the role"

for scenario in ${SCENARIOS:-setup_refused}; do
    "scenario_$scenario"
done

step "Accepted: the role installs, keeps and upgrades Garrison, and finishes plays that stopped"
