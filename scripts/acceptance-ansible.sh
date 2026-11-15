#!/bin/sh
# The Ansible role (deploy/ansible) against a virtual machine: a first
# installation, a second run that changes nothing, and an upgrade by version.
#
#   HOST=vm [DISTRO=debian-13] [ANSIBLE=ansible-playbook] \
#       scripts/acceptance-ansible.sh OUT-DIR
#
# OUT-DIR is what scripts/signed-releases.sh wrote; the role checks those
# archives against their throwaway key. The host: scripts/acceptance-lib.sh.
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
# The stand-in for Stalwart cannot run `stalwart setup` or `access init`, so the
# play gives the host what those would write, as the container acceptance does.
cat > "$work/site.yml" <<EOF
- hosts: vm
  become: true
  pre_tasks:
    - name: Credentials and access policy, as setup and access init would write them
      ansible.builtin.shell: |
        mkdir -p -m 700 /etc/garrison/credentials && cd /etc/garrison/credentials &&
        for key in webhook-signature-key collector-native-key broker-native-key metrics-credential; do
            test -e \$key || { head -c 32 /dev/urandom | base64 | tr -d "=+/" > \$key; chmod 600 \$key; }
        done
        printf "[Service]\nType=oneshot\nExecStart=/usr/bin/true\n" > /etc/systemd/system/acceptance-check.service
        test -e /etc/garrison/access-policy.json || cat > /etc/garrison/access-policy.json <<'POLICY'
        {"schemaVersion": 1, "profiles": {"administrator": {"modules": ["dashboard", "actions"],
         "actions": ["run_check"], "requiredNativePermissions": ["authenticate", "sysActionCreate", "sysRoleUpdate"]}},
         "roleBindings": {"e": "administrator"}, "subjects": {}, "deniedSubjects": []}
        POLICY
      args:
        creates: /etc/garrison/access-policy.json
  roles:
    - role: garrison
      vars:
        garrison_archives: "$work/archives"
        garrison_signing_key: "$(tail -n 1 "$out/test.pub")"
        garrison_public_origin: "https://admin.example.test"
        garrison_issuer: "https://mail.example.test"
        garrison_stalwart_url: "http://127.0.0.1:8099"
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
EOF

# `play VERSION` runs the play for that release; the recap's changed count goes to $changed.
play() {
    log=$work/play-$1.log
    if ! ANSIBLE_ROLES_PATH=$roles ANSIBLE_HOST_KEY_CHECKING=False \
        "$ansible" -i "$work/inventory" "$work/site.yml" -e "garrison_version=$1" > "$log" 2>&1; then
        tail -n 30 "$log"
        echo "FAIL  the play for $1 succeeds"
        exit 1
    fi
    changed=$(sed -n 's/.*changed=\([0-9]*\).*/\1/p' "$log" | tail -n 1)
    echo "ok    the play for $1 succeeds ($changed changed)"
}

step "The role installs and starts Garrison"
play "$older"
check "the role installed $older" "test \"\$(cat /opt/garrison/current/VERSION)\" = '$older'"
services "installed by the role"

step "A second run changes nothing"
play "$older"
if [ "$changed" != 0 ]; then
    grep -E '^changed:' "$work/play-$older.log" || true
    echo "FAIL  a second run changes nothing ($changed changed)"
    exit 1
fi
echo "ok    a second run changes nothing"

step "A new version upgrades"
play "$newer"
check "the role upgraded to $newer" "test \"\$(cat /opt/garrison/current/VERSION)\" = '$newer'"
services "upgraded by the role"

step "Accepted: the role installs, keeps and upgrades Garrison"
