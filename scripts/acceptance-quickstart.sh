#!/bin/sh
# The quick start (docs/operator/quickstart.md) on a fresh host against a real
# Stalwart: the install at a terminal, `garrison setup` answered as an operator
# would, nginx with the server block that setup printed, `garrison doctor`
# without a problem, a mail session that arrives as events, and the sign-in
# that leads to Stalwart.
#
#   HOST=vm [DISTRO=debian-13] scripts/acceptance-quickstart.sh dist/garrison-<version>-x86_64.tar.gz
#
# Stalwart is the image the contract tests pin (xtask/src/lab.rs), run with
# Podman in the host network, as the installation guide asks; its own HTTPS
# listener is removed so that nginx has port 443, as on a host where nginx
# publishes Stalwart. The host and its options: scripts/acceptance-lib.sh.
set -eu

release=$1
previous=$1
# shellcheck source=scripts/acceptance-lib.sh
. "$(dirname "$0")/acceptance-lib.sh"
if [ "$host" != vm ]; then
    echo "acceptance-quickstart.sh needs a virtual machine: HOST=vm" >&2
    exit 2
fi
digest=$(sed -n 's/^ *@\(sha256:[0-9a-f]\{64\}\)"[;,]$/\1/p' "$(dirname "$0")/../xtask/src/lab.rs" | head -n 1)
if [ -z "$digest" ]; then
    echo "No Stalwart image digest in xtask/src/lab.rs" >&2
    exit 2
fi
case $distro in
    debian-* | ubuntu-*) tools='DEBIAN_FRONTEND=noninteractive apt-get install -y -q podman nginx python3 >/dev/null' ;;
    opensuse-*) tools='zypper -n -q install podman nginx python3 >/dev/null' ;;
    *) tools='dnf -y -q install podman nginx python3 >/dev/null' ;;
esac
garrison=/opt/garrison/current/bin/garrison

start_host
step "Stalwart $digest in the host network"
inside "$tools"
inside "podman pull -q docker.io/stalwartlabs/stalwart@$digest >/dev/null"
# Bootstrap as xtask/src/lab.rs does, then drop the HTTPS listener and print
# the administrator the bootstrap made.
inside_input 'cat > /root/stalwart-up.py' <<'PYTHON'
import base64, json, subprocess, sys, time, urllib.error, urllib.request

IMAGE = "docker.io/stalwartlabs/stalwart@" + sys.argv[1]
RECOVERY = "quickstart-recovery:Quickstart-Recovery-2026"
BOOTSTRAP = {
    "defaultHostname": "mail.example.test", "defaultDomain": "example.test",
    "requestTlsCertificate": False, "generateDkimKeys": False,
    "dataStore": {"@type": "RocksDb", "path": "/var/lib/stalwart/"},
    "blobStore": {"@type": "Default"}, "searchStore": {"@type": "Default"},
    "inMemoryStore": {"@type": "Default"}, "directory": {"@type": "Internal"},
    "dnsServer": {"@type": "Manual"},
    "tracer": {"@type": "Stdout", "enable": True, "level": "info", "ansi": False},
}

def start(*extra):
    subprocess.run(["podman", "run", "-d", "--name", "stalwart", "--network", "host", *extra,
                    "-v", "/srv/stalwart/etc:/etc/stalwart:Z", "-v", "/srv/stalwart/data:/var/lib/stalwart:Z",
                    IMAGE], check=True, stdout=subprocess.DEVNULL)
    for _ in range(120):
        try:
            urllib.request.urlopen("http://127.0.0.1:8080/", timeout=2)
            return
        except urllib.error.HTTPError:
            return
        except OSError:
            time.sleep(1)
    sys.exit("Stalwart did not answer on 127.0.0.1:8080")

def stop():
    subprocess.run(["podman", "rm", "-f", "-t", "10", "stalwart"], check=True, stdout=subprocess.DEVNULL)
    time.sleep(2)

def jmap(credentials, method, arguments):
    body = json.dumps({"using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
                       "methodCalls": [[method, arguments, "0"]]}).encode()
    request = urllib.request.Request("http://127.0.0.1:8080/jmap/", data=body, headers={
        "Content-Type": "application/json",
        "Authorization": "Basic " + base64.b64encode(credentials.encode()).decode()})
    with urllib.request.urlopen(request, timeout=30) as answer:
        response = json.load(answer)["methodResponses"][0]
    if response[0] == "error":
        sys.exit(method + ": " + json.dumps(response[1]))
    return response[1]

start("-e", "STALWART_RECOVERY_ADMIN=" + RECOVERY)
admin = jmap(RECOVERY, "x:Bootstrap/set", {"update": {"singleton": BOOTSTRAP}})["updated"]["singleton"]
credentials = admin["username"] + ":" + admin["secret"]
stop()
start()
listeners = jmap(credentials, "x:NetworkListener/get", {"ids": None})["list"]
https = [item["id"] for item in listeners if any(bind.endswith(":443") for bind in item.get("bind") or {})]
if not https:
    sys.exit("Stalwart has no listener on port 443: " + json.dumps(listeners))
answer = jmap(credentials, "x:NetworkListener/set", {"destroy": https})
if answer.get("notDestroyed"):
    sys.exit("x:NetworkListener/set: " + json.dumps(answer["notDestroyed"]))
stop()
start()
print(json.dumps({"username": admin["username"], "secret": admin["secret"]}))
PYTHON
inside "mkdir -p /srv/stalwart/etc /srv/stalwart/data && chmod 777 /srv/stalwart/etc /srv/stalwart/data &&
    umask 077 && python3 /root/stalwart-up.py $digest > /root/stalwart-admin.json"
check "port 443 is free for nginx" '! ss -Hltn "( sport = :443 )" | grep -q .'
check "Stalwart's SMTP listener answers" 'curl -s --max-time 5 telnet://127.0.0.1:25 </dev/null | grep -q "^220 "'

step "Installing the release at a terminal, as the quick start says"
# Enter takes every default the first install offers.
if ! inside "umask 077 && printf '\\n\\n\\n' |
    timeout 120 script -q -e -c '/root/release/bin/garrison install' /dev/null > /root/install.log 2>&1"; then
    inside 'cat /root/install.log' || true
    echo "FAIL  the install at a terminal finishes"
    exit 1
fi
echo "ok    the install at a terminal finishes"

step "garrison setup, answered at a terminal"
# Own address, Stalwart's address, its listener, Enter for the WebUI, then the
# administrator: the user name, and its password through systemd-ask-password.
inside 'python3 -c "import json; a = json.load(open(\"/root/stalwart-admin.json\"))
print(\"https://admin.example.test\\nhttps://mail.example.test\\nhttp://127.0.0.1:8080\\n\\n\" + a[\"username\"] + \"\\n\" + a[\"secret\"])" > /root/answers'
# The terminal echoes answers given in advance, the password among them.
inside_input 'cat > /root/masked.py' <<'PYTHON'
import json, sys
secret = json.load(open("/root/stalwart-admin.json"))["secret"]
sys.stdout.write(open(sys.argv[1], errors="replace").read().replace("\r", "").replace(secret, "<password>"))
PYTHON
if ! inside "umask 077 && timeout 300 script -q -e -c '$garrison setup' /dev/null < /root/answers > /root/setup.log 2>&1"; then
    inside 'python3 /root/masked.py /root/setup.log' || true
    echo "FAIL  garrison setup finishes"
    exit 1
fi
inside 'python3 /root/masked.py /root/setup.log | sed "s/^/      | /"'
echo "ok    garrison setup finishes"
check "setup wrote the addresses" \
    'grep -qx "public_origin = \"https://admin.example.test\"" /etc/garrison/garrison.toml &&
        grep -qx "admin_url = \"https://mail.example.test/admin/\"" /etc/garrison/garrison.toml'
check "setup found that Stalwart accepts both keys" 'grep -q "Stalwart accepts both API keys from this host" /root/setup.log'
for unit in garrison-web.service garrison-ingest.service garrison-broker.socket garrison-collect.timer \
    garrison-watch.timer; do
    check "set up: $unit is active" "systemctl is-active --quiet $unit"
done
check "set up: a collection run with the new collector key succeeds" 'systemctl start garrison-collect.service'
check "set up: self-check passes" "$garrison --config /etc/garrison/garrison.toml self-check"

step "nginx with the server block setup printed"
# The certificate where certbot would put it, signed by this run's authority.
inside 'live=/etc/letsencrypt/live/admin.example.test && mkdir -p "$live" /etc/nginx/tls && cd /etc/nginx/tls &&
    openssl req -x509 -newkey rsa:2048 -nodes -days 90 -subj "/CN=Garrison quick start CA" \
        -keyout ca.key -out ca.pem 2>/dev/null &&
    openssl req -newkey rsa:2048 -nodes -subj /CN=admin.example.test -keyout key.pem -out server.csr 2>/dev/null &&
    printf "subjectAltName=DNS:admin.example.test,DNS:mail.example.test\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > server.ext &&
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 90 \
        -extfile server.ext -out cert.pem 2>/dev/null &&
    cp cert.pem "$live/fullchain.pem" && cp key.pem "$live/privkey.pem" &&
    if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null; then
        cp ca.pem /usr/local/share/ca-certificates/quickstart.crt && update-ca-certificates >/dev/null
    elif [ -d /etc/pki/ca-trust/source/anchors ]; then
        cp ca.pem /etc/pki/ca-trust/source/anchors/quickstart.pem && update-ca-trust
    else
        cp ca.pem /etc/pki/trust/anchors/quickstart.pem && update-ca-certificates >/dev/null
    fi &&
    printf "127.0.0.1 admin.example.test mail.example.test\n" >> /etc/hosts'
# What setup printed between its two closing hints, and Stalwart's own server block.
inside 'sites=$(if [ -d /etc/nginx/conf.d ]; then echo /etc/nginx/conf.d; else echo /etc/nginx/vhosts.d; fi) &&
    tr -d "\r" < /root/setup.log | sed -n "/^Last, publish Garrison through nginx:/,/^Then check everything/p" |
        sed "1d;\$d" > "$sites/garrison.conf" &&
    grep -q "server_name admin.example.test;" "$sites/garrison.conf" &&
    cat > "$sites/stalwart.conf" <<EOF
server {
    listen 443 ssl;
    server_name mail.example.test;
    ssl_certificate /etc/nginx/tls/cert.pem;
    ssl_certificate_key /etc/nginx/tls/key.pem;
    include /etc/nginx/snippets/garrison-stalwart-server*.conf;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF'
# Under SELinux nginx may reach Stalwart's port 8080 (http_cache_port_t) only
# with this boolean, as on any such host that publishes Stalwart through nginx.
inside 'if command -v getenforce >/dev/null && [ "$(getenforce)" != Disabled ]; then
        setsebool -P httpd_can_network_relay 1; fi'
check "nginx accepts the printed server block" 'nginx -t'
inside 'systemctl enable --now nginx >/dev/null 2>&1 && systemctl reload nginx'
check "Garrison answers through nginx" \
    'curl -s https://admin.example.test/api/session | grep -E -q "\"session\": ?null|Sign-in required"'
check "Stalwart's OpenID discovery names its issuer" \
    'curl -sf https://mail.example.test/.well-known/openid-configuration | grep -q "\"issuer\": *\"https://mail.example.test"'
check "sign-in leads to Stalwart's authorization" \
    'curl -s -o /dev/null -w "%{redirect_url}" https://admin.example.test/auth/login | grep -q "^https://mail.example.test/"'

step "A mail session arrives as events"
before=$(events)
inside 'printf "From: a@example.org\r\nTo: nobody@example.test\r\nSubject: quick start\r\n\r\nHello.\r\n" > /root/mail.txt &&
    curl -s --max-time 20 smtp://127.0.0.1:25 --mail-from a@example.org --mail-rcpt nobody@example.test \
        -T /root/mail.txt >/dev/null 2>&1 || true'
check "Stalwart's events reach Garrison" \
    "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite \"SELECT count(*) FROM events WHERE type LIKE 'smtp.%'\") -gt 0 &&
        test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -gt $before"

step "garrison doctor"
inside "$garrison doctor > /root/doctor.log 2>&1 || true"
inside 'sed "s/^/      | /" /root/doctor.log'
# Doctor reports the reserved test names (.test) as placeholders; nothing else may fail.
check "doctor finds no problem but the reserved test names" \
    '! grep "^FAIL" /root/doctor.log | grep -v "is still the placeholder https://\(admin\|mail\)\.example\.test" | grep -q .'

step "The macro milter, switched on and off again"
# A document as Word writes one with macros, and one without, handed to
# Stalwart the way a stranger's server would.
inside_input 'cat > /root/document-mail.py' <<'PYTHON'
import io, smtplib, sys, zipfile
from email.message import EmailMessage

packed = io.BytesIO()
with zipfile.ZipFile(packed, "w", zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("[Content_Types].xml", "<Types/>")
    archive.writestr("word/document.xml", "<document/>")
    if sys.argv[1] == "macro":
        archive.writestr("word/vbaProject.bin", "No macro: only the name a macro project has.")
message = EmailMessage()
message["From"] = "sender@example.org"
message["To"] = "admin@example.test"
message["Subject"] = "Acceptance: " + sys.argv[1]
message.set_content("See the attachment.")
message.add_attachment(packed.getvalue(), maintype="application",
                       subtype="vnd.ms-word.document.macroEnabled.12", filename="acceptance.docm")
try:
    with smtplib.SMTP("127.0.0.1", 25, timeout=30) as smtp:
        smtp.sendmail("", ["admin@example.test"], message.as_bytes())
    print("250 accepted")
except smtplib.SMTPRecipientsRefused as error:
    print("recipient refused:", error.recipients)
except smtplib.SMTPResponseException as error:
    print(error.smtp_code, error.smtp_error.decode(errors="replace"))
PYTHON
check "before: Stalwart takes a document with a macro project" \
    'python3 /root/document-mail.py macro | tee /root/macro-before.log | grep -q "^250 accepted"'
inside 'printf "\n[milter]\n" >> /etc/garrison/garrison.toml'
check "setup starts the filter and tells Stalwart of it" \
    "$garrison stalwart setup --admin-credential /root/stalwart-admin.json > /root/milter-on.log 2>&1 &&
        grep -q 'entered the macro milter (127.0.0.1:8096)' /root/milter-on.log"
inside 'sed "s/^/      | /" /root/milter-on.log'
check "garrison-milter.service is active and enabled" \
    'systemctl is-active --quiet garrison-milter.service && systemctl is-enabled --quiet garrison-milter.service'
inside "$garrison doctor > /root/doctor-milter.log 2>&1 || true"
check "doctor: the filter answers and Stalwart knows of it" \
    'grep -q "^ok    the macro milter answers on 127.0.0.1:8096" /root/doctor-milter.log &&
        grep -q "^ok    setup told Stalwart of the macro milter" /root/doctor-milter.log'
check "a document with a macro project is refused in the filter's words" \
    'python3 /root/document-mail.py macro | tee /root/macro-on.log | grep -q "^550 .*contains macros"'
check "a document without one is taken" \
    'python3 /root/document-mail.py plain | tee /root/plain-on.log | grep -q "^250 accepted"'
check "the filter's journal names what it refused" \
    'journalctl -u garrison-milter.service --no-pager | grep -q "Refused a message with"'
check "an upgrade to the same release leaves the filter running" \
    "/root/release/bin/garrison install < /dev/null > /root/reinstall.log 2>&1 &&
        systemctl is-active --quiet garrison-milter.service &&
        python3 /root/document-mail.py macro | grep -q '^550 '"
check "uninstalling is refused while Stalwart asks the filter" \
    "! $garrison uninstall --dry-run > /root/uninstall-milter.log 2>&1 &&
        grep -q 'Stalwart still asks' /root/uninstall-milter.log"
inside 'sed -i "/^\[milter\]$/d" /etc/garrison/garrison.toml'
check "without the section setup takes the filter out and stops it" \
    "$garrison stalwart setup --admin-credential /root/stalwart-admin.json > /root/milter-off.log 2>&1 &&
        grep -q \"took the macro milter's entry out of Stalwart\" /root/milter-off.log &&
        grep -q 'stopped and disabled garrison-milter.service' /root/milter-off.log"
inside 'sed "s/^/      | /" /root/milter-off.log'
check "garrison-milter.service is stopped and disabled" \
    '! systemctl is-active --quiet garrison-milter.service && ! systemctl is-enabled --quiet garrison-milter.service'
check "afterwards Stalwart takes the document again, undeferred" \
    'python3 /root/document-mail.py macro | tee /root/macro-after.log | grep -q "^250 accepted"'

step "Accepted: the quick start sets Garrison up against Stalwart and nothing is left to fix"
