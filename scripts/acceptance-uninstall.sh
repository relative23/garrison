#!/bin/sh
# Uninstall and install again: a dry run changes nothing, an uninstallation
# keeps configuration and data for the next installation, and a purge leaves
# nothing of Garrison behind.
#
#   [HOST=vm] [DISTRO=debian-13] scripts/acceptance-uninstall.sh \
#       dist/previous-x86_64.tar.gz dist/garrison-<version>-x86_64.tar.gz
#
# The archives are those of scripts/acceptance.sh. The host and its options:
# scripts/acceptance-lib.sh.
set -eu

previous=$1
release=$2
# shellcheck source=scripts/acceptance-lib.sh
. "$(dirname "$0")/acceptance-lib.sh"

# Every unit, one at a time: `systemctl is-active a b` succeeds if any is active.
none_active() {
    for unit in garrison-web.service garrison-ingest.service garrison-broker.socket \
        garrison-broker.service garrison-collect.timer garrison-watch.timer; do
        check "$1: $unit is not active" "! systemctl is-active --quiet $unit"
    done
}

start_host
install_previous
services installed
before=$(events)
selinux=$(inside 'if command -v semodule >/dev/null 2>&1 && semodule -l | grep -qw garrison; then echo yes; fi')

step "A dry run changes nothing"
inside 'find /opt/garrison /etc/garrison /etc/systemd/system /etc/polkit-1/rules.d | sort > /root/before.list'
inside '/opt/garrison/current/bin/garrison uninstall --dry-run > /root/dry-run.log 2>&1'
check "a dry run lists the program" 'grep -q "Would remove /opt/garrison$" /root/dry-run.log'
check "a dry run lists the command's link" 'grep -q "Would remove /usr/bin/garrison$" /root/dry-run.log'
check "a dry run keeps the data unless purging" '! grep -q "Would remove /var/lib/garrison" /root/dry-run.log'
# Without cmp, which minimal images lack.
check "a dry run changes nothing" \
    'test "$(find /opt/garrison /etc/garrison /etc/systemd/system /etc/polkit-1/rules.d | sort)" = "$(cat /root/before.list)"'
services "after the dry run"

step "The test of nginx without Garrison's snippets changes none of them"
# A stand-in for nginx: its test takes three seconds, marked by a file in
# /run while it runs, and fails where it sees Garrison's include, as a
# server block that includes it by its name does.
inside_input 'cat > /usr/sbin/nginx && chmod 755 /usr/sbin/nginx' <<'NGINX'
#!/bin/sh
test "$1" = -t || exit 2
: > /run/acceptance-nginx-testing
sleep 3
rm -f /run/acceptance-nginx-testing
! test -e /etc/nginx/snippets/garrison.conf
NGINX
inside 'mkdir -p /etc/nginx/snippets && echo "# other" > /etc/nginx/snippets/other.conf &&
    /root/release/bin/garrison nginx --snippet > /etc/nginx/snippets/garrison.conf &&
    ls /etc/nginx/snippets > /root/snippets.before'
# The command `1` in the background until the stand-in's test runs: then
# the snippets are looked at once, as they are in that moment.
while_testing() {
    inside "umask 077 && rm -f /root/late.pid && { $1 > /root/nginx-test.log 2>&1 & echo \$! > /root/late.pid; } &&
        for i in \$(seq 100); do test -e /run/acceptance-nginx-testing && break; sleep 0.1; done &&
        test -e /run/acceptance-nginx-testing"
}
kept='test "$(ls /etc/nginx/snippets)" = "$(cat /root/snippets.before)"'
while_testing '/opt/garrison/current/bin/garrison uninstall --dry-run'
if ! inside "$kept"; then
    inside 'ls /etc/nginx/snippets' || true
    echo "FAIL  while a dry run tests nginx, Garrison's snippets stay where they are"
    exit 1
fi
echo "ok    while a dry run tests nginx, Garrison's snippets stay where they are"
check "and the dry run finds that nginx stays valid without them" \
    'grep -q "Would remove /etc/nginx/snippets/garrison.conf" /root/nginx-test.log'
while_testing '/opt/garrison/current/bin/garrison uninstall'
inside 'p=$(cat /root/late.pid) && kill -KILL $(cat /proc/$p/task/$p/children 2>/dev/null) $p &&
    for i in $(seq 300); do test -e /proc/$p || break; sleep 0.1; done'
check "an uninstallation killed while it tests nginx leaves the snippets as they were" "$kept"
check "and nothing of Garrison's was removed" 'test -d /opt/garrison && test -L /usr/bin/garrison'
inside 'rm -r /usr/sbin/nginx /etc/nginx /root/snippets.before /root/nginx-test.log /root/late.pid
    /run/acceptance-nginx-testing 2>/dev/null; true'
services "after the test of nginx"

step "Uninstalling keeps configuration and data"
installer '/opt/garrison/current/bin/garrison uninstall'
check "the program is gone" 'test ! -e /opt/garrison'
check "the command's link is gone" 'test ! -L /usr/bin/garrison && ! command -v garrison'
check "the unit files are gone" '! ls /etc/systemd/system | grep -q "^garrison-"'
check "the polkit rule is gone" 'test ! -e /etc/polkit-1/rules.d/50-garrison.rules'
none_active uninstalled
check "the configuration stays" 'test -f /etc/garrison/garrison.toml && test -f /etc/garrison/access-policy.json'
check "the credentials stay" 'test -s /etc/garrison/credentials/webhook-signature-key'
check "the data stays" 'test -s /var/lib/garrison/ingest/events.sqlite'
check "the service users stay" 'getent passwd garrison-broker >/dev/null && getent passwd garrison-milter >/dev/null'
if [ -n "$selinux" ]; then
    check "the SELinux module is gone" '! semodule -l | grep -qw garrison'
fi

step "Installing again continues with the same data"
installer '/root/release/bin/garrison install'
services reinstalled
check "the event history survived the uninstallation" \
    "test \$(sqlite3 /var/lib/garrison/ingest/events.sqlite 'SELECT count(*) FROM events') -ge $before"

step "A purge leaves nothing of Garrison behind"
# The operator's own backups, one under a name of the installer's kind.
inside 'for name in latest pre-upgrade-before-migration; do
        mkdir -p /var/backups/garrison/$name && echo mine > /var/backups/garrison/$name/note || exit 1
    done'
installer 'garrison uninstall --purge'
none_active purged
check "the command's link is gone again" 'test ! -L /usr/bin/garrison'
check "program, configuration and data are gone" \
    'for path in /opt/garrison /etc/garrison /var/lib/garrison /etc/sysusers.d/garrison.conf \
        /etc/polkit-1/rules.d/50-garrison.rules; do test ! -e "$path" || exit 1; done'
check "the users and the group are gone" \
    'for user in garrison garrison-ingest garrison-collector garrison-broker garrison-milter; do
        ! getent passwd "$user" >/dev/null || exit 1; done; ! getent group garrison'
check "the installer's backups are gone" \
    '! ls /var/backups/garrison | grep -q "^pre-[a-z]*-[0-9]\{8\}T[0-9]\{6\}$\|^last-pre-upgrade$"'
check "the backups of the operator's own stay" \
    'test -f /var/backups/garrison/latest/note && test -f /var/backups/garrison/pre-upgrade-before-migration/note'
check "systemd knows no Garrison unit" '! systemctl list-unit-files "garrison*" --no-legend | grep -q .'
if [ -n "$selinux" ]; then
    check "the SELinux module stays gone" '! semodule -l | grep -qw garrison'
fi

step "A purged host installs like a new one"
# Another program of the command's name is left alone, and the installer says so.
inside 'echo "another program" > /usr/bin/garrison'
installer '/root/release/bin/garrison install > /root/install-beside.log 2>&1'
check "another program named garrison is left alone" \
    'test "$(cat /usr/bin/garrison)" = "another program" &&
        acceptance-state /root/install-beside.log install-link-taken'
check "the first installation's steps name the include that keeps Stalwart's exporter private" \
    'acceptance-state /root/install-beside.log install-not-configured &&
        grep -q "include /etc/nginx/snippets/garrison-stalwart-server\*.conf;" /root/install-beside.log &&
        grep -q "garrison nginx" /root/install-beside.log'
inside 'rm /usr/bin/garrison'
installer '/root/release/bin/garrison install'
check "the next installation makes the link" \
    'test "$(readlink /usr/bin/garrison)" = /opt/garrison/current/bin/garrison'
check "the new installation starts from the example configuration" \
    'grep -q "garrison.example.org" /etc/garrison/garrison.toml'
check "the service users exist again" 'getent passwd garrison-broker >/dev/null'

step "A purge where polkit's rules folder is gone"
# As after `apt purge polkitd`: uninstalling needs neither polkit nor its folder.
inside 'mv /etc/polkit-1/rules.d /root/polkit-rules.away'
installer '/root/release/bin/garrison uninstall --purge > /root/purge-without-polkit.log 2>&1' ||
    { inside 'cat /root/purge-without-polkit.log'; echo "FAIL  a purge without polkit's rules folder"; exit 1; }
echo "ok    a purge without polkit's rules folder"
check "it removed the program and the configuration" 'test ! -e /opt/garrison && test ! -e /etc/garrison'
inside 'mv /root/polkit-rules.away /etc/polkit-1/rules.d && rm -f /etc/polkit-1/rules.d/50-garrison.rules'

step "Accepted: uninstalling keeps what it should and a purge leaves nothing"
