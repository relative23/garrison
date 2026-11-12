# shellcheck shell=sh
# Shared by scripts/acceptance.sh and scripts/acceptance-failures.sh: a
# disposable host with systemd and polkit, a stand-in for Stalwart, the
# configuration both start from and the checks of a running Garrison. The
# sourcing script sets `previous` and `release` (the two archives) and reads
# `expected` and `clamd_config`.
# shellcheck disable=SC2034,SC2154
#
# DISTRO is almalinux-10 (the default) or debian-13 in a container. HOST=vm
# runs in a virtual machine instead (scripts/vm-lib.sh), where DISTRO may also
# be debian-12, ubuntu-22.04, ubuntu-24.04, ubuntu-26.04, almalinux-9, rocky-9,
# rocky-10, centos-stream-10, fedora-44, amazonlinux-2023 or
# opensuse-leap-16.0, and ARCH=aarch64 emulates an ARM host. CLAMAV=1 installs
# ClamAV without starting it, for `detect` to find. UPDATE=1 first brings the
# host to the distribution's current packages, and restarts a virtual machine
# into them: the host as a server that is kept up to date has it, where the
# image alone is the host as it was published.
# Containers and virtual machines have 2 GiB of memory, need network access for
# packages, are removed at the end (unless KEEP=1) and touch nothing on this
# host. Containers must match the archives' architecture: the units' sandboxing
# (network namespaces, seccomp, W^X) does not work under qemu-user.

name=garrison-acceptance-$$
builder=garrison-acceptance-build-$$
host=${HOST:-container}
distro=${DISTRO:-almalinux-10}
# The tools the checks use, on a fresh host of each package manager. Ubuntu
# 22.04 calls polkit policykit-1; curl-minimal is enough on the RHEL family;
# Fedora ships script(1) on its own; openSUSE Leap 16 has socat but no ncat.
apt_tools='export DEBIAN_FRONTEND=noninteractive && apt-get update -q >/dev/null &&
    { apt-get install -y -q --no-install-recommends polkitd >/dev/null 2>&1 ||
      apt-get install -y -q --no-install-recommends policykit-1 >/dev/null; } &&
    apt-get install -y -q --no-install-recommends ncat openssl sqlite3 curl >/dev/null'
dnf_tools='dnf -y -q install nmap-ncat openssl polkit sqlite >/dev/null'
zypper_tools='zypper -n -q install socat openssl polkit sqlite3 curl >/dev/null'
# policy-rc.d keeps the packages from starting their services, so freshclam
# downloads no signatures.
apt_clamav='printf "#!/bin/sh\nexit 101\n" > /usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d &&
    apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y -q --no-install-recommends clamav-daemon clamav-milter >/dev/null'
epel_clamav='dnf -y -q install epel-release >/dev/null &&
    dnf -y -q install clamd clamav-milter clamav-update >/dev/null'
apt_clamd="/etc/clamav/clamd.conf (distribution default)"
unit_clamd="/etc/clamd.d/scan.conf (from the unit)"
case $distro in
    almalinux-10)
        image=almalinux/10-init:latest
        expected="AlmaLinux 10"
        packages=$dnf_tools
        clamav=$epel_clamav
        clamd_config=$unit_clamd ;;
    debian-13)
        image=garrison-acceptance:debian-13
        expected="Debian GNU/Linux 13"
        packages=true
        clamav=$apt_clamav
        clamd_config=$apt_clamd ;;
    # Virtual machines only.
    debian-12) expected="Debian GNU/Linux 12" packages=$apt_tools clamav=$apt_clamav clamd_config=$apt_clamd ;;
    ubuntu-*) expected="Ubuntu ${distro#ubuntu-}" packages=$apt_tools clamav=$apt_clamav clamd_config=$apt_clamd ;;
    almalinux-9) expected="AlmaLinux 9" packages=$dnf_tools clamav=$epel_clamav clamd_config=$unit_clamd ;;
    rocky-*) expected="Rocky Linux ${distro#rocky-}" packages=$dnf_tools clamav=$epel_clamav clamd_config=$unit_clamd ;;
    centos-stream-*)
        expected="CentOS Stream ${distro#centos-stream-}" packages=$dnf_tools clamav=$epel_clamav
        clamd_config=$unit_clamd ;;
    amazonlinux-*)
        expected="Amazon Linux ${distro#amazonlinux-}" packages=$dnf_tools clamd_config=$unit_clamd
        clamav='dnf -y -q install clamd clamav-update >/dev/null' ;;
    fedora-*)
        expected="Fedora Linux ${distro#fedora-}" clamd_config=$unit_clamd
        packages="$dnf_tools && dnf -y -q install util-linux-script >/dev/null"
        clamav='dnf -y -q install clamd clamav-milter clamav-update >/dev/null' ;;
    opensuse-leap-*)
        expected="openSUSE Leap ${distro#opensuse-leap-}" packages=$zypper_tools
        clamav='zypper -n -q install clamav >/dev/null' clamd_config="/etc/clamd.conf (distribution default)" ;;
    *)
        echo "Unknown DISTRO $distro" >&2
        exit 2 ;;
esac
if [ "$host" = vm ]; then
    # A cloud image has none of the tools that the container images bring.
    case $distro in
        debian-13) packages=$apt_tools ;;
    esac
    # shellcheck source=scripts/vm-lib.sh
    . "$(dirname "$0")/vm-lib.sh"
elif [ -z "${image:-}" ]; then
    echo "$distro runs only in a virtual machine (HOST=vm)" >&2
    exit 2
fi

# KEEP=1 leaves the container running for a look inside; remove it afterwards.
cleanup() {
    if [ "$host" = vm ]; then
        if [ -n "${KEEP:-}" ] && [ -n "$vm_dir" ]; then
            echo "Kept: ssh -i $vm_dir/key -p $vm_port root@127.0.0.1; kill \$(cat $vm_dir/qemu.pid)"
        else
            vm_stop
        fi
        return
    fi
    docker rm -f "$builder" >/dev/null 2>&1 || true
    if [ -n "${KEEP:-}" ]; then
        echo "Kept: docker exec -it $name bash; docker rm -f $name"
    else
        docker rm -f "$name" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
inside() {
    if [ "$host" = vm ]; then
        vm_ssh -n "sh -c $(vm_quote "$1")"
    else
        docker exec "$name" sh -c "$1"
    fi
}
# Like inside, with standard input passed through.
inside_input() {
    if [ "$host" = vm ]; then
        vm_ssh "sh -c $(vm_quote "$1")"
    else
        docker exec -i "$name" sh -c "$1"
    fi
}
copy_in() {
    if [ "$host" = vm ]; then
        vm_copy "$1" "$2"
    else
        docker cp "$1" "$name:$2"
    fi
}
# The installer, from a hardened root shell: its files must not depend on the umask.
installer() { inside "umask 077 && $1"; }
# A service is active before it listens, so each check gets 20 attempts.
check() {
    attempt=1
    until inside "$2" >/dev/null 2>&1; do
        if [ "$attempt" -ge 20 ]; then
            echo "FAIL  $1"
            inside "$2" 2>&1 | tail -n 20 || true
            inside "journalctl -u 'garrison-*' --no-pager -n 40" || true
            exit 1
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    echo "ok    $1"
}

# UPDATE=1: every package the distribution has an update for, before anything
# else is installed. A virtual machine restarts into what it got, a new
# kernel among it; a container has the kernel of this host.
update_host() {
    [ -n "${UPDATE:-}" ] || return 0
    step "Updating $distro to its current packages"
    case $distro in
        debian-* | ubuntu-*)
            # Ubuntu's needrestart is left out: the machine restarts anyway.
            updated='export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 && apt-get update -q >/dev/null &&
                apt-get -y -q -o Dpkg::Options::=--force-confold dist-upgrade >/dev/null' ;;
        opensuse-*) updated='zypper -n -q refresh >/dev/null && zypper -n -q update >/dev/null' ;;
        # Amazon Linux stays on the release of its image unless told otherwise.
        amazonlinux-*) updated='dnf -y -q upgrade --releasever=latest >/dev/null' ;;
        *) updated='dnf -y -q upgrade --refresh >/dev/null' ;;
    esac
    if ! inside "$updated"; then
        echo "FAIL  $distro takes its updates"
        exit 1
    fi
    echo "ok    $distro has its current packages"
    if [ "$host" = vm ]; then
        vm_reboot || exit 1
        echo "ok    restarted with the kernel $(inside 'uname -r')"
    fi
}

# A host with systemd and polkit, and the two releases unpacked in /root.
start_host() {
    if [ "$host" = vm ]; then
        step "Booting $distro ($vm_arch) in a virtual machine"
        vm_boot "$distro" || exit 1
        update_host
        inside "$packages && systemctl start polkit"
    else
        start_container
    fi
    finish_host
}

start_container() {
    # Debian publishes no image with systemd, so one is made from the official
    # image in a container with the same memory limit, and kept for the next run.
    if [ "$distro" = debian-13 ] && ! docker image inspect "$image" >/dev/null 2>&1; then
        step "Building $image from debian:trixie"
        docker run -d --rm --name "$builder" --memory=2g --memory-swap=2g \
            debian:trixie sleep infinity >/dev/null
        docker exec "$builder" sh -c 'apt-get update -q >/dev/null &&
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
                systemd systemd-sysv dbus polkitd ca-certificates curl ncat openssl sqlite3 >/dev/null &&
            rm -rf /var/lib/apt/lists/*'
        docker commit "$builder" "$image" >/dev/null
        docker rm -f "$builder" >/dev/null
    fi

    step "Starting $image with systemd"
    docker run -d --rm --name "$name" --privileged --memory=2g --memory-swap=2g \
        --tmpfs /run --tmpfs /tmp "$image" /sbin/init >/dev/null
    # Until systemd is up even its bus is missing, which also ends in status 1.
    inside 'for attempt in $(seq 90); do
        case $(systemctl is-system-running 2>/dev/null) in running|degraded) exit 0 ;; esac
        sleep 1
    done
    exit 1'
    # Hosts share mounts by default; Docker's /run does not, and systemd needs it
    # to hand LoadCredential= files to the services.
    inside 'mount --make-rshared /'
    update_host
    inside "$packages && systemctl start polkit"
}

# ClamAV if asked, the Stalwart stand-in and the two releases.
finish_host() {
    if [ -n "${CLAMAV:-}" ]; then
        step "Installing ClamAV without starting it"
        inside "$clamav"
    fi
    # A stand-in for Stalwart that knows one administrator token: subject 1, native
    # account b, role e. Any other token is invalid, as in production. With it the
    # broker authorizes a request as usual, so an action runs through polkit and
    # systemctl for real.
    inside_input 'cat > /root/stalwart-stub.sh' <<'STUB'
read -r method path rest
length=0
authorization=
while IFS= read -r line; do
    line=$(printf %s "$line" | tr -d '\r')
    [ -z "$line" ] && break
    case "$line" in
        [Cc]ontent-[Ll]ength:*) length=$(printf %s "${line#*:}" | tr -d ' ') ;;
        [Aa]uthorization:*) authorization=$(printf %s "${line#*:}" | sed 's/^ *//') ;;
    esac
done
body=$(head -c "$length")
answer=
status="200 OK"
respond() { answer="{\"methodResponses\": [[\"$1\", {\"list\": [$2], \"notFound\": []}, \"0\"]]}"; }
case "$method $path" in
    "GET /auth/userinfo")
        if [ "$authorization" = "Bearer acceptance-token-0123456789abcdef" ]; then
            answer='{"sub": "1", "email": "admin@example.test"}'
        else
            status="401 Unauthorized"
        fi ;;
    "POST /jmap/")
        case "$body" in
            *x:Account/get*) respond x:Account/get '{"id": "b", "@type": "User", "memberTenantId": null,
                "roles": {"@type": "Custom", "roleIds": {"e": true}}, "permissions": {"@type": "Inherit"}}' ;;
            *x:Authentication/get*) respond x:Authentication/get \
                '{"id": "singleton", "defaultAdminRoleIds": {}, "defaultUserRoleIds": {}}' ;;
            *x:Role/get*) respond x:Role/get '{"id": "e", "roleIds": {}, "memberTenantId": null, "disabledPermissions": {},
                "enabledPermissions": {"authenticate": true, "sysActionCreate": true, "sysRoleUpdate": true}}' ;;
        esac ;;
esac
printf 'HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' "$status" "${#answer}" "$answer"
STUB
    inside 'if command -v ncat >/dev/null 2>&1; then
            systemd-run --quiet --unit=acceptance-stalwart ncat -lk 127.0.0.1 8099 --sh-exec "sh /root/stalwart-stub.sh"
        else
            systemd-run --quiet --unit=acceptance-stalwart \
                socat TCP-LISTEN:8099,bind=127.0.0.1,reuseaddr,fork SYSTEM:"sh /root/stalwart-stub.sh"
        fi'
    # The checks talk to the broker's socket through this, as its peer would.
    inside_input 'cat > /usr/local/bin/acceptance-connect && chmod 755 /usr/local/bin/acceptance-connect' <<'CONNECT'
#!/bin/sh
# Standard input to the Unix socket $1, its answer to standard output.
if command -v ncat >/dev/null 2>&1; then
    exec ncat -U "$1"
fi
exec socat -t 10 - "UNIX-CONNECT:$1"
CONNECT
    copy_in "$previous" /root/previous.tar.gz
    copy_in "$release" /root/release.tar.gz
    inside 'cd /root && mkdir previous release &&
            tar -xzf previous.tar.gz -C previous --strip-components=1 &&
            tar -xzf release.tar.gz -C release --strip-components=1'
}

# The previous release, installed, configured and running.
install_previous() {
    step "Installing the previous release at a terminal, then its configuration"
    # At a terminal the first install lets the operator choose the modules and
    # offers what detect found; Enter takes every default. A hang ends in the
    # timeout, and the modules line shows that the terminal path ran.
    if ! inside "umask 077 && printf '\\n\\n\\n' |
        timeout 120 script -q -e -c '/root/previous/bin/garrison install' /dev/null \
        > /root/first-install.log 2>&1"; then
        inside 'cat /root/first-install.log' || true
        echo "FAIL  the first install at a terminal finishes"
        exit 1
    fi
    echo "ok    the first install at a terminal finishes"
    check "the first install at a terminal writes the chosen modules" \
        'grep -q "^modules = \\[" /etc/garrison/garrison.toml'
    inside 'cat > /etc/garrison/garrison.toml <<EOF
schema = 1
[deployment]
public_origin = "https://admin.example.test"
issuer = "https://mail.example.test"
stalwart_url = "http://127.0.0.1:8099"
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
printf "[Service]\nType=oneshot\nExecStart=/usr/bin/true\n" > /etc/systemd/system/acceptance-check.service
cd /etc/garrison/credentials &&
# Every LoadCredential= file of the units must exist, even if unused here.
for key in webhook-signature-key collector-native-key broker-native-key metrics-credential; do
    head -c 32 /dev/urandom | base64 | tr -d "=+/" > $key; chmod 600 $key
done
cat > /etc/garrison/access-policy.json <<EOF
{"schemaVersion": 1, "profiles": {"viewer": {"modules": ["dashboard"], "actions": [],
 "requiredNativePermissions": ["authenticate", "sysAccountGet"]},
 "administrator": {"modules": ["dashboard", "actions"], "actions": ["run_check"],
 "requiredNativePermissions": ["authenticate", "sysActionCreate", "sysRoleUpdate"]}},
 "roleBindings": {"v": "viewer", "e": "administrator"}, "subjects": {}, "deniedSubjects": []}
EOF'
    installer '/root/previous/bin/garrison install'
}

services() {
    # One unit per check: `systemctl is-active a b` succeeds when any one is active.
    for unit in garrison-web.service garrison-ingest.service garrison-broker.socket \
        garrison-collect.timer garrison-watch.timer; do
        check "$1: $unit is active" "systemctl is-active --quiet $unit"
    done
    # The link in the search path, which sudo must find too where there is one.
    check "$1: garrison is in the search path" \
        'test "$(readlink /usr/bin/garrison)" = /opt/garrison/current/bin/garrison &&
            garrison --version | grep -q "^garrison " &&
            { ! command -v sudo >/dev/null 2>&1 || sudo -n garrison --version >/dev/null; }'
    check "$1: web answers without a session" \
        'curl -s http://127.0.0.1:8091/api/session | grep -E -q "\"session\": ?null|Sign-in required"'
    check "$1: ingest answers" 'curl -sf http://127.0.0.1:8094/health'
    check "$1: a signed batch is stored" '
        key=$(cat /etc/garrison/credentials/webhook-signature-key)
        body="{\"events\": [{\"id\": \"$(date +%s%N)\", \"createdAt\": \"2026-10-29T10:00:00Z\", \"type\": \"auth.failed\", \"data\": {}}]}"
        signature=$(printf %s "$body" | openssl dgst -sha256 -hmac "$key" -binary | base64)
        curl -s -H "Content-Type: application/json" -H "X-Signature: $signature" \
            --data-binary "$body" http://127.0.0.1:8094/webhook | grep -q "\"stored\":1"'
    check "$1: one collection run succeeds" 'systemctl start garrison-collect.service'
    # The host care checks run their commands inside the collector's sandbox.
    # Where the package manager is one they read, its answer must be known.
    check "$1: the host care and sender checks answer from the collector's sandbox" '
        document=$(sqlite3 /var/lib/garrison/collector/status.sqlite "SELECT document FROM snapshots ORDER BY id DESC LIMIT 1")
        for id in host.updates host.restart host.clock host.disk-forecast host.firewall senders.accounts flow.spam flow.tls; do
            printf %s "$document" | grep -q "\"id\":\"$id\"" || exit 1
        done
        if [ -x /usr/bin/apt-get ] || { [ -x /usr/bin/dnf ] && [ ! -x /usr/bin/dnf5 ]; }; then
            printf %s "$document" | grep -o "\"id\":\"host.updates\"[^}]*\"state\":\"[a-z]*\"" | grep -q -E "\"state\":\"(ok|warning)\"" || exit 1
        fi'
    # In its own sandbox the watch reads the collector's database.
    check "$1: the watch over the collector finds it running" \
        'systemctl start garrison-watch.service &&
            journalctl -u garrison-watch.service -n 5 --no-pager | grep -q "The collector runs"'
    # A version command runs inside the collector's sandbox and still answers.
    check "$1: the collector's version command reports a version" \
        'sqlite3 /var/lib/garrison/collector/status.sqlite "SELECT document FROM snapshots ORDER BY id DESC LIMIT 1" |
            grep -q "\"version\":\"[0-9]"'
    # The web service's user is the broker's only peer; an invalid token is 401
    # (or 503 without Stalwart), never a crash or a dropped connection. A broker
    # that keeps failing leaves the socket's connection open, hence the timeout.
    check "$1: the broker starts on its socket and answers its peer" '
        printf "%s\n" "{\"op\": \"catalog\", \"token\": \"tttttttttttttttttttt\"}" |
            timeout 10 runuser -u garrison -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock |
            grep -E -q "\"status\": ?(401|503)"'
    check "$1: self-check passes" '/opt/garrison/current/bin/garrison --config /etc/garrison/garrison.toml self-check'
}

events() { inside 'sqlite3 /var/lib/garrison/ingest/events.sqlite "SELECT count(*) FROM events"'; }
