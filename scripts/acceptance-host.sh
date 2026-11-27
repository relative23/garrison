#!/bin/sh
# What only a real host shows: Garrison under the distribution's mandatory
# access control as shipped (SELinux enforcing on the RHEL family, AppArmor
# elsewhere), behind nginx with TLS, back after a reboot, upgraded there, and
# reading a place under /home that a drop-in shows the collector.
#
#   HOST=vm DISTRO=almalinux-10 [ARCH=aarch64] scripts/acceptance-host.sh \
#       dist/previous-x86_64.tar.gz dist/garrison-<version>-x86_64.tar.gz
#
# The archives are those of scripts/acceptance.sh. The host and its options:
# scripts/acceptance-lib.sh.
set -eu

previous=$1
release=$2
# shellcheck source=scripts/acceptance-lib.sh
. "$(dirname "$0")/acceptance-lib.sh"
if [ "$host" != vm ]; then
    echo "acceptance-host.sh needs a virtual machine: HOST=vm" >&2
    exit 2
fi
case $distro in
    debian-* | ubuntu-*) nginx='DEBIAN_FRONTEND=noninteractive apt-get install -y -q nginx >/dev/null' ;;
    opensuse-*) nginx='zypper -n -q install nginx >/dev/null' ;;
    *) nginx='dnf -y -q install nginx >/dev/null' ;;
esac

start_host
step "Installing nginx with a certificate for both host names"
inside "$nginx && systemctl enable --now nginx"
# A certificate authority of this run, trusted by the system, signs the server
# certificate: names resolve and TLS validates as on a real host.
inside 'mkdir -p /etc/nginx/tls && cd /etc/nginx/tls &&
    openssl req -x509 -newkey rsa:2048 -nodes -days 90 -subj "/CN=Garrison acceptance CA" \
        -keyout ca.key -out ca.pem 2>/dev/null &&
    openssl req -newkey rsa:2048 -nodes -subj /CN=admin.example.test -keyout key.pem -out server.csr 2>/dev/null &&
    printf "subjectAltName=DNS:admin.example.test,DNS:mail.example.test\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > server.ext &&
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 90 \
        -extfile server.ext -out cert.pem 2>/dev/null &&
    if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null; then
        cp ca.pem /usr/local/share/ca-certificates/garrison-acceptance.crt && update-ca-certificates >/dev/null
    elif [ -d /etc/pki/ca-trust/source/anchors ]; then
        cp ca.pem /etc/pki/ca-trust/source/anchors/garrison-acceptance.pem && update-ca-trust
    else
        cp ca.pem /etc/pki/trust/anchors/garrison-acceptance.pem && update-ca-certificates >/dev/null
    fi &&
    printf "127.0.0.1 admin.example.test mail.example.test\n" >> /etc/hosts &&
    sites=$(if [ -d /etc/nginx/conf.d ]; then echo /etc/nginx/conf.d; else echo /etc/nginx/vhosts.d; fi) &&
    cat > "$sites/garrison-acceptance.conf" <<EOF
server {
    listen 443 ssl;
    server_name admin.example.test;
    ssl_certificate /etc/nginx/tls/cert.pem;
    ssl_certificate_key /etc/nginx/tls/key.pem;
    include /etc/nginx/snippets/garrison*.conf;
}
server {
    listen 443 ssl;
    server_name mail.example.test;
    ssl_certificate /etc/nginx/tls/cert.pem;
    ssl_certificate_key /etc/nginx/tls/key.pem;
    include /etc/nginx/snippets/garrison-stalwart-server*.conf;
    location / { proxy_pass http://127.0.0.1:8099; }
}
EOF'
# Under SELinux nginx reaches Stalwart only once an operator allows it
# (operations.md: httpd_can_network_relay for Stalwart's port 8080). The
# stand-in listens on 8099, which gets the type of 8080 first. Garrison's own
# port stays the business of the module the installer loads.
inside 'if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != Disabled ]; then
        command -v semanage >/dev/null 2>&1 ||
            { dnf -y -q install policycoreutils-python-utils >/dev/null 2>&1 ||
              zypper -n -q install policycoreutils-python-utils >/dev/null; }
        # The policy of Amazon Linux names the port already, with another type.
        { semanage port -a -t http_cache_port_t -p tcp 8099 2>/dev/null ||
          semanage port -m -t http_cache_port_t -p tcp 8099; } &&
            setsebool httpd_can_network_relay 1
    fi'
install_previous
services installed

# Every denial of the mandatory access control since boot that concerns
# Garrison, nginx or their ports: by process, profile, path, type, unit or port,
# never by host name (a whole journal line once matched it, for the denials of
# Ubuntu's own profiles). The kernel hands a denial to auditd while that runs
# and writes it to its own log otherwise, so both are read: ausearch reads
# only auditd's log, and finds nothing where auditd does not run. A place that
# cannot be read fails the step: no denial found is not none read.
denials() {
    inside 'kernel=$(journalctl -k -b -o cat --no-pager 2>&1) || { echo "the kernel log: $kernel"; exit 2; }
        audit=
        if systemctl is-active --quiet auditd.service; then
            audit=$(ausearch -m AVC,USER_AVC -ts boot -i 2>&1) || [ "$audit" = "<no matches>" ] ||
                { echo "the audit log: $audit"; exit 2; }
        fi
        printf "%s\n%s\n" "$kernel" "$audit" | grep -E "apparmor=\"DENIED\"|avc: +denied" |
            grep -E "comm=\"?(garrison|nginx)|profile=\"[^\"]*(garrison|nginx)|name=\"?[^ \"]*garrison|garrison_[a-z_]*_t|/(opt|etc|var/lib|run)/garrison|(dest|src)=809[14]([^0-9]|\$)|garrison-[a-z]+\.(service|socket|timer)" || true'
}
mac=$(inside 'if command -v getenforce >/dev/null 2>&1; then getenforce;
    elif aa-status --enabled 2>/dev/null; then echo AppArmor; else echo none; fi')
echo "      access control: $mac; its denials are read from the kernel log$(inside \
    'if systemctl is-active --quiet auditd.service; then echo " and from the log of auditd, which runs"; fi')"

undenied() {
    if ! found=$(denials); then
        echo "FAIL  $1: what the access control denied could not be read: $found"
        exit 1
    fi
    if [ -n "$found" ]; then
        echo "FAIL  $1: the access control denied something"
        echo "$found" | tail -n 20
        exit 1
    fi
    echo "ok    $1: no denial by $mac"
}

through_nginx() {
    check "$1: the interface answers through nginx with TLS" \
        'curl -sk --resolve admin.example.test:443:127.0.0.1 https://admin.example.test/api/session |
            grep -E -q "\"session\": ?null|Sign-in required"'
    check "$1: nginx sends HSTS for Garrison" \
        'curl -skI --resolve admin.example.test:443:127.0.0.1 https://admin.example.test/admin/ |
            grep -qi "^strict-transport-security:"'
    check "$1: the Stalwart host answers /metrics/ with 404" \
        'test "$(curl -sk -o /dev/null -w "%{http_code}" --resolve mail.example.test:443:127.0.0.1 \
            https://mail.example.test/metrics/prometheus)" = 404'
    undenied "$1"
}

step "Behind nginx"
through_nginx installed

step "garrison doctor"
inside '/opt/garrison/current/bin/garrison doctor > /root/doctor.log 2>&1 || true'
inside 'sed "s/^/      | /" /root/doctor.log'
# Doctor's lines by the names of their states, which stay as they are.
for expected in "[doctor-service-active]" "[doctor-collection-recent]" "[doctor-policy-readable]" \
    "[doctor-credential-private]" "[doctor-certificate-valid]" "[doctor-interface-answers]" \
    "[doctor-hsts-sent]" "[doctor-metrics-private]" "[doctor-sign-in-page-shown]" \
    "[doctor-events-recent]"; do
    check "doctor: $expected" "grep -qF '$expected' /root/doctor.log"
done
check "doctor: every unit of Garrison's is active" \
    '! grep -qF -e "[doctor-service-inactive]" -e "[doctor-service-unknown]" /root/doctor.log'
# The test names are reserved (.test), and the stand-in issuer answers no JSON for the sign-in client.
check "doctor: no other problem" \
    '! grep "^FAIL" /root/doctor.log | grep -vF -e "[doctor-origin-placeholder]" -e "[doctor-client-not-stalwart]" | grep -q .'

step "After a reboot"
vm_reboot
services rebooted
check "rebooted: the collector timer is scheduled" \
    'systemctl list-timers garrison-collect.timer --no-legend | grep -q garrison-collect'
through_nginx rebooted

step "Upgrading on this host"
installer '/root/release/bin/garrison install'
names "current is the release under test" current "$(inside 'cat /root/release/VERSION')"
names "previous is the release it upgraded from" previous "$(inside 'cat /root/previous/VERSION')"
services upgraded
through_nginx upgraded

step "A place under /home, shown to the collector as checks.md says"
# The collector's unit hides /home. The drop-in of checks.md shows it one
# folder there read-only at another place: here a job's receipt, and an empty
# folder of a file system mounted at /home for that file system's free space.
inside 'truncate -s 512M /var/home.img &&
    { mkfs.ext4 -q -F /var/home.img 2>/dev/null || mkfs.xfs -q /var/home.img; } &&
    mount -o loop /var/home.img /home &&
    { ! command -v restorecon >/dev/null 2>&1 || restorecon -R /home; } &&
    mkdir -p /home/backup /home/.garrison-disk /srv/garrison/backup /srv/garrison/home-disk &&
    printf "{\"date\": \"%s\", \"result\": \"passed\"}\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        > /home/backup/last-run.json &&
    chmod 644 /home/backup/last-run.json &&
    mkdir -p /etc/systemd/system/garrison-collect.service.d &&
    printf "[Service]\nBindReadOnlyPaths=%s\nBindReadOnlyPaths=%s\n" \
        /home/backup:/srv/garrison/backup /home/.garrison-disk:/srv/garrison/home-disk \
        > /etc/systemd/system/garrison-collect.service.d/home.conf &&
    systemctl daemon-reload &&
    sed -i "s|^type = \"host\"\$|&\ndisk_path = \"/srv/garrison/home-disk\"|" /etc/garrison/garrison.toml &&
    cat >> /etc/garrison/garrison.toml <<EOF
[[providers]]
type = "receipt"
id = "home-backup"
title = "Backup under /home"
path = "/srv/garrison/backup/last-run.json"
modules = ["backups"]
max_age_hours = 30
ok_when = { key = "result", equals = ["passed"] }
EOF'
inside_input 'cat > /root/card.sh' <<'SQL'
sqlite3 /var/lib/garrison/collector/status.sqlite "SELECT value FROM snapshots,
    json_each(document, '\$.observations') WHERE snapshots.id = (SELECT max(id) FROM snapshots)
    AND json_extract(value, '\$.id') = '$1'"
SQL
check "check-config takes the two places" \
    '/opt/garrison/current/bin/garrison --config /etc/garrison/garrison.toml check-config'
once "with the drop-in a collection run succeeds" \
    'acceptance-run garrison-collect.service'
check "the collector reads the receipt of /home where the drop-in shows it" \
    'sh /root/card.sh receipt.home-backup | grep "\"state\":\"ok\""'
check "the host card measures the file system mounted at /home" \
    'sh /root/card.sh host.resources | grep -F "statvfs(/srv/garrison/home-disk)" |
        grep "\"label\":\"Disk total\",\"value\":$(($(stat -f -c "%b * %S" /home)))[,}]"'
check "root sees nothing of /home at the two places" \
    'test -z "$(ls -A /srv/garrison/backup)" && test -z "$(ls -A /srv/garrison/home-disk)"'
undenied "a place under /home"

step "Accepted: Garrison runs under $mac, behind nginx, and after a reboot"
