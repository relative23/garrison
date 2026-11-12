#!/bin/sh
# What only a real host shows: Garrison under the distribution's mandatory
# access control as shipped (SELinux enforcing on the RHEL family, AppArmor
# elsewhere), behind nginx with TLS, back after a reboot, and upgraded there.
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
# Ubuntu's own profiles). Without ausearch the kernel log has both kinds.
denials() {
    inside 'if command -v ausearch >/dev/null 2>&1; then
            ausearch -m AVC,USER_AVC -ts boot -i 2>/dev/null
        else
            journalctl -k -b -o cat --no-pager 2>/dev/null | grep -E "apparmor=\"DENIED\"|avc: +denied"
        fi | grep -E "comm=\"?(garrison|nginx)|profile=\"[^\"]*(garrison|nginx)|name=\"?[^ \"]*garrison|garrison_[a-z_]*_t|/(opt|etc|var/lib|run)/garrison|(dest|src)=809[14]([^0-9]|\$)|garrison-[a-z]+\.(service|socket|timer)" || true'
}
mac=$(inside 'if command -v getenforce >/dev/null 2>&1; then getenforce;
    elif aa-status --enabled 2>/dev/null; then echo AppArmor; else echo none; fi')
echo "      access control: $mac"

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
    found=$(denials)
    if [ -n "$found" ]; then
        echo "FAIL  $1: the access control denied something"
        echo "$found" | tail -n 20
        exit 1
    fi
    echo "ok    $1: no denial by $mac"
}

step "Behind nginx"
through_nginx installed

step "garrison doctor"
inside '/opt/garrison/current/bin/garrison doctor > /root/doctor.log 2>&1 || true'
inside 'sed "s/^/      | /" /root/doctor.log'
for expected in "ok    garrison-web.service is active" "ok    the last collection run succeeded" \
    "ok    the access policy is private" "ok    webhook-signature-key is private" \
    "presents a trusted certificate" "ok    Garrison answers at https://admin.example.test" \
    "ok    nginx sends Strict-Transport-Security" "does not serve Stalwart's metrics" \
    "shows Stalwart's sign-in page" "ok    the last Stalwart event arrived"; do
    check "doctor: $expected" "grep -qF \"$expected\" /root/doctor.log"
done
# The test names are reserved (.test) and the stand-in issuer knows no clients.
check "doctor: no other problem" \
    '! grep "^FAIL" /root/doctor.log | grep -v -e "placeholder" -e "sign-in client" -e "registered client" | grep -q .'

step "After a reboot"
vm_reboot
services rebooted
check "rebooted: the collector timer is scheduled" \
    'systemctl list-timers garrison-collect.timer --no-legend | grep -q garrison-collect'
through_nginx rebooted

step "Upgrading on this host"
installer '/root/release/bin/garrison install'
services upgraded
through_nginx upgraded

step "Accepted: Garrison runs under $mac, behind nginx, and after a reboot"
