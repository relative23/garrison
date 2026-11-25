# shellcheck shell=sh
# Sourced by scripts/acceptance.sh: a status database that names a
# notification channel, and what the release under test makes of it in its
# first collection run, inside the collector's unit. A release before 0.2.0
# kept a channel's address as garrison.toml wrote it; the first run of a later
# one rebuilds the file, so that no freed page keeps it (crates/collector/src/
# store/residue.rs), and the copy must get the database's owner, group, mode
# and label without a call the unit filters. It uses the helpers of
# scripts/acceptance-lib.sh.

status=/var/lib/garrison/collector/status.sqlite

# Before the upgrade: a channel in the configuration and one collection run
# of the release that runs, whose database then names the channel. Nothing
# listens at the address; the run notes the channel all the same.
channel_before_upgrade() {
    step "A notification channel, which the status database of the release before then names"
    inside_input 'cat > /usr/local/bin/acceptance-memory && chmod 755 /usr/local/bin/acceptance-memory' <<'MEMORY'
#!/bin/sh
# acceptance-memory PATTERN: the keys of the collector's memory that are like
# PATTERN, in one line.
sqlite3 /var/lib/garrison/collector/status.sqlite \
    "SELECT coalesce(group_concat(key, ' '), '') FROM (SELECT key FROM memory WHERE key LIKE '$1' ORDER BY key)"
MEMORY
    inside_input 'cat > /usr/local/bin/acceptance-made && chmod 755 /usr/local/bin/acceptance-made' <<'MADE'
#!/bin/sh
# acceptance-made FILE: its owner, group, mode and SELinux label, in one line.
echo "$(stat -c '%U:%G %a' "$1") $(ls -Z "$1" | cut -d' ' -f1)"
MADE
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.before-channel &&
        printf "\n[notifications]\nntfy_url = \"https://localhost:8443/acceptance\"\n" >> /etc/garrison/garrison.toml'
    once "the release before collects with the channel, and its status database names it" \
        'acceptance-run garrison-collect.service' 'test "$(acceptance-memory notify.channel)" = notify.channel'
    # A release that has looked at its status database leaves nothing to rebuild.
    looked=$(inside 'acceptance-memory store.secrets-looked')
    inside "stat -c %i $status > /root/status.inode && acceptance-made $status > /root/status.made &&
        date '+%F %T' > /root/upgrade.began"
}

# After the upgrade: no collection run was ended by a signal, whichever began
# first, the timer's or this one; and where the database was one to rebuild,
# it is another file now, made as the one before.
rebuild_after_upgrade() {
    step "The first collection run of the release under test, on a status database that names a channel"
    once "a collection run of the release under test ends in order" 'acceptance-run garrison-collect.service'
    check "no collection run since the upgrade was ended by a signal" \
        '! journalctl -u garrison-collect.service --since "$(cat /root/upgrade.began)" --no-pager |
            grep -E "code=(dumped|killed)|status=31/SYS"'
    if [ -n "$looked" ]; then
        echo "skip  the release before had looked at its status database, so the one under test rebuilds nothing"
    else
        check "the status database is another file, with the owner, group, mode and label of the one before" \
            "test \"\$(stat -c %i $status)\" != \"\$(cat /root/status.inode)\" &&
                test \"\$(acceptance-made $status)\" = \"\$(cat /root/status.made)\""
        check "the store noted its look, and no rebuild that began and did not end" \
            'test "$(acceptance-memory "store.secrets-%")" = store.secrets-looked'
        check "no copy of the database is left beside it" "! ls $status-clearing* 2>/dev/null | grep -q ."
        check "the web service reads the rebuilt database" \
            "runuser -u garrison -- sqlite3 -readonly $status 'SELECT count(*) FROM snapshots' | grep -q '^[1-9]'"
    fi
    inside 'cp -p /root/garrison.toml.before-channel /etc/garrison/garrison.toml'
}
