# shellcheck shell=sh
# Sourced by scripts/acceptance-failures.sh: a stand-in for ntfy on
# https://localhost:8443 that keeps what it is sent, with a certificate the
# collector's and the watch's units are told to trust. It uses the helpers of
# scripts/acceptance-lib.sh.
ntfy_stand_in() {
    inside_input 'cat > /root/ntfy.sh' <<'NTFY'
#!/bin/sh
# One request: keep its body, answer 200.
length=0
while IFS= read -r line; do
    line=$(printf %s "$line" | tr -d '\r')
    [ -n "$line" ] || break
    case $line in [Cc]ontent-[Ll]ength:*) length=${line#*: } ;; esac
done
head -c "$length" >> /root/ntfy-bodies
echo >> /root/ntfy-bodies
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
NTFY
    inside 'cd /root && : > ntfy-bodies &&
        openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out /etc/acceptance-ca.crt \
            -days 2 -subj "/CN=Acceptance CA" 2>/dev/null &&
        openssl req -newkey rsa:2048 -nodes -keyout ntfy.key -out ntfy.csr -subj /CN=localhost 2>/dev/null &&
        printf "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n" > ntfy.ext &&
        openssl x509 -req -in ntfy.csr -CA /etc/acceptance-ca.crt -CAkey ca.key -CAcreateserial \
            -days 2 -extfile ntfy.ext -out ntfy.crt 2>/dev/null &&
        for unit in garrison-collect garrison-watch; do
            mkdir -p /etc/systemd/system/$unit.service.d &&
            printf "[Service]\nEnvironment=SSL_CERT_FILE=/etc/acceptance-ca.crt\n" \
                > /etc/systemd/system/$unit.service.d/acceptance.conf
        done &&
        systemctl daemon-reload &&
        if command -v ncat >/dev/null 2>&1; then
            systemd-run --quiet --unit=acceptance-ntfy ncat --ssl --ssl-cert /root/ntfy.crt \
                --ssl-key /root/ntfy.key -lk 127.0.0.1 8443 --sh-exec "sh /root/ntfy.sh"
        else
            systemd-run --quiet --unit=acceptance-ntfy socat \
                OPENSSL-LISTEN:8443,bind=127.0.0.1,reuseaddr,fork,cert=/root/ntfy.crt,key=/root/ntfy.key,verify=0 \
                SYSTEM:"sh /root/ntfy.sh"
        fi'
}
