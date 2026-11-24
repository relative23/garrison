# shellcheck shell=sh
# Sourced by scripts/acceptance-failures.sh: the scenarios of the
# configuration the installer checks. The installer passes on what
# check-config warns of, names a file it could not write, refuses a secret
# its unit would not hand over, and a policy or a check's path that a
# unit hides, and follows a policy kept elsewhere, but leaves a folder
# named as the policy as it is; a restore and a rollback check before
# anything stops what they put back. They use that script's helpers and its
# `old` and `new`.
# shellcheck disable=SC2154

scenario_warnings() {
    step "The installer and doctor say what check-config warns of"
    upgraded
    says_words "the installer passes check-config's warnings on" \
        '/root/release/bin/garrison install' \
        "Warning: deployment.public_origin https://admin.example.test is a placeholder"
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.warnings &&
        sed -i "s|^schema = 1\$|schema = 1\ncredentials_directory = \"/etc/garrison/elsewhere\"|" \
            /etc/garrison/garrison.toml'
    says_words "doctor warns of a setting the units do not follow" \
        '/opt/garrison/current/bin/garrison doctor || true' \
        "warn  credentials_directory is /etc/garrison/elsewhere, but the units load every credential"
    inside 'cat /root/garrison.toml.warnings > /etc/garrison/garrison.toml'
    running "after the warnings" "$new"
}

scenario_unloaded() {
    step "A secret its unit would not hand over stops the upgrade"
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.unloaded &&
        cp -p /etc/garrison/credentials/collector-native-key /etc/garrison/credentials/my-key &&
        printf "\n[collector]\nnative_key = \"credential:my-key\"\n" >> /etc/garrison/garrison.toml'
    check "the collector's unit hands it no credential of another name" \
        'systemctl start garrison-collect.service &&
            journalctl -u garrison-collect.service -n 30 --no-pager | grep -q "The collector has no API key for Stalwart"'
    refused_words "the installer refuses a secret under a name its unit does not load" \
        '/root/release/bin/garrison install' \
        "garrison-collect.service loads this secret only as credential:collector-native-key"
    inside 'sed -i "s|^native_key = \"credential:my-key\"\$|native_key = \"/etc/garrison/credentials/my-key\"|" \
        /etc/garrison/garrison.toml'
    refused_words "the installer refuses a secret named by its path" '/root/release/bin/garrison install' \
        "collector.native_key names the file /etc/garrison/credentials/my-key"
    inside 'cat /root/garrison.toml.unloaded > /etc/garrison/garrison.toml &&
        rm /etc/garrison/credentials/my-key'
    services "after the refused secrets"
}

scenario_policy_elsewhere() {
    step "A policy kept where garrison.toml names it"
    upgraded
    catalog='printf "%s\n" "{\"op\": \"catalog\", \"token\": \"acceptance-token-0123456789abcdef\"}" |
        timeout 10 runuser -u garrison -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock'
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.policy && mkdir -p /etc/garrison-policy &&
        mv /etc/garrison/access-policy.json /etc/garrison-policy/access.json &&
        chmod 644 /etc/garrison-policy/access.json &&
        printf "\n[broker]\npolicy = \"/etc/garrison-policy/access.json\"\n" >> /etc/garrison/garrison.toml'
    says "the installer starts Garrison with the policy where garrison.toml names it" \
        '/root/release/bin/garrison install' "install-running install-as-installed"
    check "the installer makes that policy root's, readable for the broker's group alone" \
        'test "$(stat -c "%U %G %a" /etc/garrison-policy/access.json)" = "root garrison-broker 640"'
    check "the broker grants by that policy" "$catalog | grep -q run_check"
    check "doctor finds that the broker may read that policy, and only root change it" \
        '/opt/garrison/current/bin/garrison doctor |
            grep -q -F "ok    the broker may read the access policy, which only root may change (root:garrison-broker, mode 640)"'
    # A folder named as the policy is none: the installer leaves it as it is
    # and refuses, and a purge would not take it.
    inside 'mkdir -p /srv/policy-folder/mail && echo kept > /srv/policy-folder/mail/inbox &&
        chmod 755 /srv/policy-folder &&
        sed -i "s|^policy = \"/etc/garrison-policy/access.json\"\$|policy = \"/srv/policy-folder\"|" \
            /etc/garrison/garrison.toml'
    refused_words "the installer refuses a policy that is a folder" '/root/release/bin/garrison install' \
        "Access policy not usable"
    check "and leaves that folder as it was" \
        'test "$(stat -c "%U %a" /srv/policy-folder)" = "root 755" && test -s /srv/policy-folder/mail/inbox'
    check "a purge would not remove it" \
        '/opt/garrison/current/bin/garrison uninstall --purge --dry-run > /root/purge-plan.log 2>&1 &&
            grep -q "Would remove /var/lib/garrison$" /root/purge-plan.log &&
            ! grep -q /srv/policy-folder /root/purge-plan.log'
    inside 'rm -r /srv/policy-folder /root/purge-plan.log'
    inside 'mv /etc/garrison-policy/access.json /etc/garrison/access-policy.json && rmdir /etc/garrison-policy &&
        cat /root/garrison.toml.policy > /etc/garrison/garrison.toml'
    installer '/root/release/bin/garrison install'
    running "after the policy elsewhere" "$new"
}

scenario_policy_foreign() {
    step "A policy file of another user is never made the broker's"
    upgraded
    # As a user who may write the policy's folder would put one there.
    inside 'chown nobody /etc/garrison/access-policy.json'
    pid=$(web_pid)
    refused "the installer refuses a policy of another user" '/root/release/bin/garrison install' \
        install-policy-foreign
    check "and leaves it that user's, and nothing stopped" "
        test \"\$(stat -c %U /etc/garrison/access-policy.json)\" = nobody &&
            test \"\$(systemctl show -p MainPID --value garrison-web.service)\" = '$pid'"
    inside 'chown root /etc/garrison/access-policy.json'
    installer '/root/release/bin/garrison install'
    running "after the policy of another user" "$new"
}

scenario_unwritten() {
    step "A file the installer could not write from the configuration is named"
    upgraded
    # A configuration that does not load, no policy yet, and services the
    # installer never started, which it enables as it starts them: not
    # configured, as between the first two runs of an installation.
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.unwritten &&
        mv /etc/garrison/access-policy.json /root/access-policy.away &&
        systemctl disable garrison-web.service garrison-ingest.service garrison-broker.socket \
            garrison-collect.timer garrison-watch.timer &&
        sed -i "s|^schema = 1\$|schema = 1\nnonsense = 1|" /etc/garrison/garrison.toml'
    says "the installer names the polkit rule it could not write" '/root/release/bin/garrison install' \
        install-unwritten
    check "and which file" 'grep -q -F /etc/polkit-1/rules.d/50-garrison.rules /root/answer'
    inside 'mv /root/access-policy.away /etc/garrison/access-policy.json &&
        cat /root/garrison.toml.unwritten > /etc/garrison/garrison.toml'
    installer '/root/release/bin/garrison install'
    running "after the unwritten file" "$new"
}

# A policy that the broker's unit hides from it: root reads it, the broker
# never does, so the installer refuses it before an upgrade and changes
# nothing, and doctor names it.
scenario_hidden_policy() {
    step "A policy where the broker's unit hides it stops the upgrade"
    current=$(inside 'basename "$(readlink -f /opt/garrison/current)"')
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.hidden && mkdir -p /home/admin &&
        cp -p /etc/garrison/access-policy.json /home/admin/access-policy.json &&
        printf "\n[broker]\npolicy = \"/home/admin/access-policy.json\"\n" >> /etc/garrison/garrison.toml &&
        cp -p /etc/garrison/garrison.toml /root/garrison.toml.named'
    backups=$(inside 'ls /var/backups/garrison | wc -l')
    refused_words "the installer refuses a policy the broker's unit hides" '/root/release/bin/garrison install' \
        "broker.policy is /home/admin/access-policy.json, under /home, which garrison-broker.service hides from the broker (ProtectHome=true): the broker cannot read it there, and nobody can sign in"
    # Without cmp, which minimal images lack.
    check "and changes nothing: the release that ran is current, garrison.toml as it was, nothing backed up" \
        "test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$current' &&
            test \"\$(cat /etc/garrison/garrison.toml)\" = \"\$(cat /root/garrison.toml.named)\" &&
            test \$(ls /var/backups/garrison | wc -l) -eq $backups"
    says_words "doctor names the policy the broker cannot read" '/opt/garrison/current/bin/garrison doctor || true' \
        "FAIL  broker.policy is /home/admin/access-policy.json, under /home, which garrison-broker.service hides"
    inside 'cat /root/garrison.toml.hidden > /etc/garrison/garrison.toml && rm -r /home/admin'
    running "after the policy under /home" "$current"
}

# A check's path that the collector's unit hides from it, a receipt under
# /home: the installer refuses it before an upgrade and changes nothing,
# doctor names it, and the place shown to the collector as checks.md says,
# the folder bound read-only at another one, is taken and read.
scenario_hidden_check() {
    step "A check's path where the collector's unit hides it stops the upgrade, and a place shown to it is read"
    current=$(inside 'basename "$(readlink -f /opt/garrison/current)"')
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.hidden && mkdir -p /home/jobs &&
        printf "{\"date\": \"%s\", \"result\": \"passed\"}\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            > /home/jobs/nightly.json && chmod 644 /home/jobs/nightly.json &&
        printf "\n[[providers]]\ntype = \"receipt\"\nid = \"nightly\"\ntitle = \"Nightly job\"\npath = \"/home/jobs/nightly.json\"\nmodules = [\"services\"]\nmax_age_hours = 24\n" \
            >> /etc/garrison/garrison.toml &&
        cp -p /etc/garrison/garrison.toml /root/garrison.toml.named'
    backups=$(inside 'ls /var/backups/garrison | wc -l')
    refused_words "the installer refuses a check's path the collector's unit hides" '/root/release/bin/garrison install' \
        "providers[receipt].path is /home/jobs/nightly.json, under /home, which garrison-collect.service hides from the collector (ProtectHome=true): the check cannot read it there"
    # Without cmp, which minimal images lack.
    check "and changes nothing: the release that ran is current, garrison.toml as it was, nothing backed up" \
        "test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$current' &&
            test \"\$(cat /etc/garrison/garrison.toml)\" = \"\$(cat /root/garrison.toml.named)\" &&
            test \$(ls /var/backups/garrison | wc -l) -eq $backups"
    says_words "doctor names the check's path the collector cannot see" '/opt/garrison/current/bin/garrison doctor || true' \
        "FAIL  providers[receipt].path is /home/jobs/nightly.json, under /home, which garrison-collect.service hides"
    inside 'mkdir -p /srv/garrison/jobs /etc/systemd/system/garrison-collect.service.d &&
        printf "[Service]\nBindReadOnlyPaths=/home/jobs:/srv/garrison/jobs\n" \
            > /etc/systemd/system/garrison-collect.service.d/jobs.conf && systemctl daemon-reload &&
        sed -i "s|^path = \"/home/jobs/nightly.json\"\$|path = \"/srv/garrison/jobs/nightly.json\"|" \
            /etc/garrison/garrison.toml && grep -q "^path = \"/srv/garrison/jobs/nightly.json\"\$" /etc/garrison/garrison.toml'
    says "the installer takes the place shown to the collector" '/root/release/bin/garrison install' \
        "install-running install-as-installed"
    check "the collector reads the receipt there, and root sees an empty folder" \
        'systemctl start garrison-collect.service && test -z "$(ls -A /srv/garrison/jobs)" &&
            sqlite3 /var/lib/garrison/collector/status.sqlite "SELECT document FROM snapshots ORDER BY id DESC LIMIT 1" |
                grep -o "\"id\":\"receipt.nightly\"[^}]*\"state\":\"[a-z]*\"" | grep -q "\"state\":\"ok\""'
    inside 'rm /etc/systemd/system/garrison-collect.service.d/jobs.conf &&
        { rmdir /etc/systemd/system/garrison-collect.service.d 2>/dev/null || true; } && systemctl daemon-reload &&
        cat /root/garrison.toml.hidden > /etc/garrison/garrison.toml && rm -r /home/jobs /srv/garrison &&
        systemctl start garrison-collect.service'
    running "after the check's path under /home" "$new"
}

# The web service's process, to show that a refusal stopped nothing.
web_pid() { inside 'systemctl show -p MainPID --value garrison-web.service'; }

scenario_restore_refused() {
    step "A restore whose policy the configuration no longer takes is refused before anything stops"
    upgraded
    installer '/opt/garrison/current/bin/garrison backup --to /root/policy-state' >/dev/null
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.refused &&
        cp -p /etc/garrison/access-policy.json /root/access-policy.refused &&
        sed -i "/^\[\[actions\]\]$/,/^timeout_seconds = 30$/d" /etc/garrison/garrison.toml &&
        ! grep -q run_check /etc/garrison/garrison.toml &&
        sed -i "s/\"actions\": \[\"run_check\"\]/\"actions\": []/" /etc/garrison/access-policy.json &&
        ! grep -q run_check /etc/garrison/access-policy.json'
    check "the configuration without the action is valid" '/opt/garrison/current/bin/garrison check-config'
    pid=$(web_pid)
    copies=$(inside 'ls -d /var/backups/garrison/pre-restore-* 2>/dev/null | wc -l')
    refused "a restore whose policy grants an action the configuration no longer has is refused" \
        '/opt/garrison/current/bin/garrison restore --from /root/policy-state' install-restore-policy
    check "and nothing stopped or changed: the web service ran on, no copy, the live policy as it was" "
        test \"\$(systemctl show -p MainPID --value garrison-web.service)\" = '$pid' &&
            test \$(ls -d /var/backups/garrison/pre-restore-* 2>/dev/null | wc -l) -eq $copies &&
            ! grep -q run_check /etc/garrison/access-policy.json"
    inside 'cat /root/garrison.toml.refused > /etc/garrison/garrison.toml &&
        cat /root/access-policy.refused > /etc/garrison/access-policy.json && rm -r /root/policy-state'
    running "after the refused restore" "$new"
}

scenario_restore_refused_config() {
    step "A restore under a configuration that check-config refuses is refused before anything stops"
    upgraded
    installer '/opt/garrison/current/bin/garrison backup --to /root/config-state' >/dev/null
    # Written since the services started: they run on what they loaded.
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.refused && mkdir -p /home/jobs &&
        printf "\n[[providers]]\ntype = \"receipt\"\nid = \"nightly\"\ntitle = \"Nightly job\"\npath = \"/home/jobs/nightly.json\"\nmodules = [\"services\"]\nmax_age_hours = 24\n" \
            >> /etc/garrison/garrison.toml'
    pid=$(web_pid)
    refused "a restore under a configuration check-config refuses is refused" \
        '/opt/garrison/current/bin/garrison restore --from /root/config-state' install-restore-config-refused
    check "and nothing stopped" "test \"\$(systemctl show -p MainPID --value garrison-web.service)\" = '$pid'"
    inside 'cat /root/garrison.toml.refused > /etc/garrison/garrison.toml && rm -r /home/jobs /root/config-state'
    running "after the restore under a refused configuration" "$new"
}

scenario_rollback_refused_config() {
    step "A rollback with the state from before the upgrade under a configuration the release it returns to refuses is refused before anything stops"
    upgraded_from_old
    # Written since the services started, which run on what they loaded.
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.refused && mkdir -p /home/jobs &&
        printf "\n[[providers]]\ntype = \"receipt\"\nid = \"nightly\"\ntitle = \"Nightly job\"\npath = \"/home/jobs/nightly.json\"\nmodules = [\"services\"]\nmax_age_hours = 24\n" \
            >> /etc/garrison/garrison.toml'
    pid=$(web_pid)
    refused "a rollback under a configuration the release it returns to refuses is refused" \
        '/opt/garrison/current/bin/garrison install --rollback --restore-state' install-rollback-unloadable
    check "and nothing stopped or switched" "
        test \"\$(systemctl show -p MainPID --value garrison-web.service)\" = '$pid' &&
            $(current_is "$new")"
    inside 'cat /root/garrison.toml.refused > /etc/garrison/garrison.toml && rm -r /home/jobs'
    running "after the rollback under a refused configuration" "$new"
}

scenario_rollback_refused() {
    step "A rollback whose state from before the upgrade the configuration no longer takes is refused before anything stops"
    upgraded
    # The action the policy from before the upgrade grants is taken out.
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.refused &&
        cp -p /etc/garrison/access-policy.json /root/access-policy.refused &&
        grep -q run_check "$(readlink -f /var/backups/garrison/last-pre-upgrade)/access-policy.json" &&
        sed -i "/^\[\[actions\]\]$/,/^timeout_seconds = 30$/d" /etc/garrison/garrison.toml &&
        sed -i "s/\"actions\": \[\"run_check\"\]/\"actions\": []/" /etc/garrison/access-policy.json'
    pid=$(web_pid)
    refused "a rollback whose state brings a policy the configuration does not take is refused" \
        '/opt/garrison/current/bin/garrison install --rollback --restore-state' install-rollback-policy
    check "and nothing stopped or changed: the release under test runs on, the live policy as it was" "
        test \"\$(systemctl show -p MainPID --value garrison-web.service)\" = '$pid' &&
            test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$new' &&
            ! grep -q run_check /etc/garrison/access-policy.json"
    inside 'cat /root/garrison.toml.refused > /etc/garrison/garrison.toml &&
        cat /root/access-policy.refused > /etc/garrison/access-policy.json'
    running "after the refused rollback" "$new"
}

scenario_restore_policy() {
    step "A restore puts the access policy back root's, readable for the broker's group alone"
    upgraded
    catalog='printf "%s\n" "{\"op\": \"catalog\", \"token\": \"acceptance-token-0123456789abcdef\"}" |
        timeout 10 runuser -u garrison -- /usr/local/bin/acceptance-connect /run/garrison/broker.sock'
    installer '/opt/garrison/current/bin/garrison backup --to /root/policy-back' >/dev/null
    # As on a new host, where no policy exists yet.
    inside 'mv /etc/garrison/access-policy.json /root/access-policy.away'
    says "a restore without a live policy puts the backup's back" \
        '/opt/garrison/current/bin/garrison restore --from /root/policy-back' install-restored
    check "the policy is root's, readable for the broker's group alone" \
        'test "$(stat -c "%U %G %a" /etc/garrison/access-policy.json)" = "root garrison-broker 640"'
    check "the broker grants by it" "$catalog | grep -q run_check"
    inside 'rm /root/access-policy.away && rm -r /root/policy-back'
    running "after the restored policy" "$new"
}

scenario_restore_policy_link() {
    step "A restore where broker.policy names a link is refused, and the link's target stays"
    upgraded
    installer '/opt/garrison/current/bin/garrison backup --to /root/policy-link' >/dev/null
    inside 'printf "kept\n" > /root/victim && chmod 644 /root/victim &&
        cp -p /etc/garrison/garrison.toml /root/garrison.toml.link && mkdir -p /etc/garrison-link &&
        ln -s /root/victim /etc/garrison-link/access.json &&
        printf "\n[broker]\npolicy = \"/etc/garrison-link/access.json\"\n" >> /etc/garrison/garrison.toml'
    pid=$(web_pid)
    refused "a restore where broker.policy names a link is refused" \
        '/opt/garrison/current/bin/garrison restore --from /root/policy-link' install-policy-place
    check "and the link's target is as it was, and nothing stopped" "
        test \"\$(cat /root/victim)\" = kept && test \"\$(stat -c %a /root/victim)\" = 644 &&
            test \"\$(systemctl show -p MainPID --value garrison-web.service)\" = '$pid'"
    inside 'cat /root/garrison.toml.link > /etc/garrison/garrison.toml && rm -r /etc/garrison-link /root/victim /root/policy-link'
    running "after the policy named by a link" "$new"
}

scenario_rollback_after_restore() {
    step "A rollback that fails once the state from before the upgrade went back says what went back"
    upgraded
    # The web service refuses to start while current names the release the
    # rollback returns to, and only then.
    inside_input 'cat > /usr/local/bin/acceptance-refuse-release && chmod 755 /usr/local/bin/acceptance-refuse-release' <<'REFUSE'
#!/bin/sh
! test "$(basename "$(readlink -f /opt/garrison/current)")" = "$(cat /run/garrison-acceptance-refused)"
REFUSE
    inside "printf '%s\n' '$old' > /run/garrison-acceptance-refused &&
        mkdir -p /etc/systemd/system/garrison-web.service.d &&
        printf '[Service]\nExecStartPre=+/usr/local/bin/acceptance-refuse-release\n' \
            > /etc/systemd/system/garrison-web.service.d/acceptance-refuse.conf && systemctl daemon-reload"
    refused "a rollback that failed after the state went back names the databases that went back" \
        '/opt/garrison/current/bin/garrison install --rollback --restore-state' install-went-back
    inside 'rm /run/garrison-acceptance-refused /etc/systemd/system/garrison-web.service.d/acceptance-refuse.conf &&
        rmdir /etc/systemd/system/garrison-web.service.d && systemctl daemon-reload'
    running "after the failed rollback" "$new"
}

scenario_elsewhere_unloadable() {
    step "With the policy kept elsewhere, a configuration that does not load stops the upgrade"
    # The release before the one under test runs, and the upgrade is to come.
    installer '/root/previous/bin/garrison install'
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.elsewhere && mkdir -p /etc/garrison-policy &&
        mv /etc/garrison/access-policy.json /etc/garrison-policy/access.json &&
        printf "\n[broker]\npolicy = \"/etc/garrison-policy/access.json\"\n" >> /etc/garrison/garrison.toml &&
        cp -p /etc/garrison/garrison.toml /root/garrison.toml.named'
    installer '/root/previous/bin/garrison install'
    backups=$(inside 'ls /var/backups/garrison | wc -l')
    # A setting no release loads, as a typo while preparing the upgrade.
    inside 'sed -i "1i nonsense_setting = 1" /etc/garrison/garrison.toml'
    refused "an upgrade over a configuration that does not load is refused, the policy kept elsewhere" \
        '/root/release/bin/garrison install' install-config-refused
    check "and changes nothing: the release that ran is current, nothing backed up" "
        test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$old' &&
            test \$(ls /var/backups/garrison | wc -l) -eq $backups"
    # Also where the operator disabled the web service: the other services
    # the installer enabled say that it started them.
    inside 'systemctl disable --quiet garrison-web.service'
    refused "with the web service disabled, that upgrade is refused all the same" \
        '/root/release/bin/garrison install' install-config-refused
    check "and changes nothing then either" "
        test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$old' &&
            test \$(ls /var/backups/garrison | wc -l) -eq $backups"
    inside 'systemctl enable --quiet garrison-web.service'
    # Where the configuration loads and names a policy that is not there.
    inside 'cat /root/garrison.toml.named > /etc/garrison/garrison.toml &&
        mv /etc/garrison-policy/access.json /root/access.json.away'
    refused "an upgrade whose access policy is missing is refused" \
        '/root/release/bin/garrison install' install-config-refused
    check "and changes nothing either" "
        test \"\$(basename \"\$(readlink -f /opt/garrison/current)\")\" = '$old' &&
            test \$(ls /var/backups/garrison | wc -l) -eq $backups"
    inside 'mv /root/access.json.away /etc/garrison/access-policy.json && rmdir /etc/garrison-policy &&
        cat /root/garrison.toml.elsewhere > /etc/garrison/garrison.toml'
    upgraded
    running "after the configuration that did not load" "$new"
}

scenario_elsewhere_purge() {
    step "A purge says where it cannot find a policy kept elsewhere"
    upgraded
    inside 'cp -p /etc/garrison/garrison.toml /root/garrison.toml.purge &&
        sed -i "1i nonsense_setting = 1" /etc/garrison/garrison.toml'
    says "a purge's dry run says that garrison.toml does not load and names what it then leaves" \
        '/opt/garrison/current/bin/garrison uninstall --purge --dry-run' install-policy-unknown
    inside 'cat /root/garrison.toml.purge > /etc/garrison/garrison.toml'
    running "after the purge's dry run" "$new"
}

scenario_restore_room() {
    step "A restore whose copies do not fit beside the databases is refused before anything stops"
    upgraded
    installer '/opt/garrison/current/bin/garrison backup --to /root/room-state' >/dev/null
    # The copy of the event history grows to some 10 MiB, more than the small
    # file system that the receiver's folder lies on below.
    inside "sqlite3 /root/room-state/ingest/events.sqlite 'CREATE TABLE padding(x);
        WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 10000)
        INSERT INTO padding SELECT randomblob(1000) FROM n;'"
    inside 'systemctl stop garrison-ingest.service && cp -a /var/lib/garrison/ingest /root/ingest-room &&
        mount -t tmpfs -o size=8m garrison-room /var/lib/garrison/ingest &&
        cp -a /root/ingest-room/. /var/lib/garrison/ingest/ && rm -r /root/ingest-room &&
        systemctl start garrison-ingest.service'
    pid=$(web_pid)
    refused "a restore whose copy does not fit beside its database is refused" \
        '/opt/garrison/current/bin/garrison restore --from /root/room-state' install-no-room
    check "and nothing stopped" "test \"\$(systemctl show -p MainPID --value garrison-web.service)\" = '$pid'"
    inside 'systemctl stop garrison-ingest.service && cp -a /var/lib/garrison/ingest /root/ingest-room &&
        umount /var/lib/garrison/ingest && cp -a /root/ingest-room/. /var/lib/garrison/ingest/ &&
        rm -r /root/ingest-room /root/room-state && systemctl start garrison-ingest.service'
    running "after the restore that did not fit" "$new"
}

scenario_rollback_room() {
    step "A rollback with the state from before the upgrade whose copies do not fit is refused before anything stops"
    upgraded_from_old
    last=$(inside 'readlink -f /var/backups/garrison/last-pre-upgrade')
    # The copy of the event history grows to some 10 MiB, more than the
    # small file system that the receiver's folder lies on below.
    inside "sqlite3 $last/ingest/events.sqlite 'CREATE TABLE padding(x);
        WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 10000)
        INSERT INTO padding SELECT randomblob(1000) FROM n;'"
    inside 'systemctl stop garrison-ingest.service && cp -a /var/lib/garrison/ingest /root/ingest-room &&
        mount -t tmpfs -o size=8m garrison-room /var/lib/garrison/ingest &&
        cp -a /root/ingest-room/. /var/lib/garrison/ingest/ && rm -r /root/ingest-room &&
        systemctl start garrison-ingest.service'
    pid=$(web_pid)
    refused "a rollback whose copy does not fit beside its database is refused" \
        '/opt/garrison/current/bin/garrison install --rollback --restore-state' install-no-room
    check "and nothing stopped or switched" "
        test \"\$(systemctl show -p MainPID --value garrison-web.service)\" = '$pid' &&
            $(current_is "$new")"
    inside "systemctl stop garrison-ingest.service && cp -a /var/lib/garrison/ingest /root/ingest-room &&
        umount /var/lib/garrison/ingest && cp -a /root/ingest-room/. /var/lib/garrison/ingest/ &&
        rm -r /root/ingest-room && systemctl start garrison-ingest.service &&
        sqlite3 $last/ingest/events.sqlite 'DROP TABLE padding; VACUUM;'"
    running "after the rollback that did not fit" "$new"
}
