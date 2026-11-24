//! The rows of the rollback's, the restore's, the copies' and the
//! uninstallation's states.

use std::path::Path;

use super::{Rows, web_restarted};
use crate::install::states::*;

pub(super) fn rollback() -> Rows {
    let backup = Path::new("/var/backups/garrison/pre-upgrade-20261124T080000");
    let went = went_back(backup, &["web", "the access policy"], &["broker"]);
    let settings = Path::new("/etc/garrison/garrison.toml");
    vec![
        (
            no_previous(),
            "There is no previous release to return to. [install-no-previous]",
        ),
        (
            no_other_release(),
            "There is no other release to return to: /opt/garrison/previous names the release \
             /opt/garrison/current names. A rollback cut short is finished by the installer its \
             first line named. [install-no-other-release]",
        ),
        (
            no_state(Path::new("/var/backups/garrison/last-pre-upgrade")),
            "There is no state from before an upgrade to restore \
             (/var/backups/garrison/last-pre-upgrade); nothing was changed. [install-no-state]",
        ),
        (
            state_newer(backup, "0.2.0", "0.1.2"),
            "The state in /var/backups/garrison/pre-upgrade-20261124T080000 was written by Garrison \
             0.2.0, which is newer than 0.1.2; 0.1.2 cannot read it. Nothing was changed. \
             [install-state-newer]",
        ),
        (
            no_broker_group(),
            "The group garrison-broker, which reads the access policy, does not exist; the \
             installer makes it. Nothing was changed. [install-no-broker-group]",
        ),
        (
            unchanged(unloadable(settings, "unknown field `nonsense`")),
            "Cannot load /etc/garrison/garrison.toml: unknown field `nonsense`. Nothing was \
             changed. [install-unloadable]",
        ),
        (
            rollback_unloadable("0.1.2", "Configuration not usable: unknown field `modules`"),
            "0.1.2 cannot load /etc/garrison/garrison.toml:\nConfiguration not usable: unknown \
             field `modules`\nRemove the settings 0.1.2 does not know, or put back the file from \
             before the upgrade (/var/backups/garrison/last-pre-upgrade/etc/garrison.toml), then \
             roll back. [install-rollback-unloadable]",
        ),
        (
            rollback_unreadable("0.1.2", "collector (schema 3, integrity ok)"),
            "0.1.2 cannot read the current data, as its self-check says of collector (schema 3, \
             integrity ok). Roll back with --restore-state to return to the data from before the \
             upgrade. [install-rollback-unreadable]",
        ),
        (
            rollback_policy(
                backup,
                settings,
                "0.1.2",
                "Access policy not usable: unknown actions",
            ),
            "The access policy from before the upgrade, in \
             /var/backups/garrison/pre-upgrade-20261124T080000, does not suit \
             /etc/garrison/garrison.toml, as 0.1.2's check-config says:\nAccess policy not usable: \
             unknown actions\nNothing was changed. [install-rollback-policy]",
        ),
        (
            rolling_back(
                "0.1.2",
                "/opt/garrison/releases/0.2.0/bin/garrison install --rollback",
            ),
            "Rolling back to 0.1.2. [install-rolling-back]\n      If this is interrupted, run it \
             again: /opt/garrison/releases/0.2.0/bin/garrison install --rollback",
        ),
        (
            rollback_stopped(&web_restarted(), "0.1.2", None),
            "The rollback failed (garrison-web.service restarted 3 times within 8 s of starting \
             [install-restarting]); 0.1.2 is stopped. See the journal. [install-rollback-stopped]",
        ),
        (
            rollback_returned(&web_restarted(), went.as_ref()),
            "The rollback failed (garrison-web.service restarted 3 times within 8 s of starting \
             [install-restarting]); the release that ran before is running again. These went back \
             to their copies in /var/backups/garrison/pre-upgrade-20261124T080000: web, the access \
             policy. Removed, as they did not exist then: broker. [install-went-back] See the \
             journal. [install-rollback-returned]",
        ),
        (
            rollback_neither(&web_restarted(), None),
            "The rollback failed (garrison-web.service restarted 3 times within 8 s of starting \
             [install-restarting]); the release that ran before did not start either. See the \
             journal. [install-rollback-neither]",
        ),
        (
            rolled_back("0.1.2"),
            "Rolled back to 0.1.2. [install-rolled-back]",
        ),
        (
            went.unwrap(),
            "These went back to their copies in /var/backups/garrison/pre-upgrade-20261124T080000: \
             web, the access policy. Removed, as they did not exist then: broker. \
             [install-went-back]",
        ),
    ]
}

pub(super) fn restore() -> Rows {
    let kept = Path::new("/var/backups/garrison/pre-restore-20261124T080000");
    let settings = Path::new("/etc/garrison/garrison.toml");
    vec![
        (
            not_a_backup(Path::new("/root/kept")),
            "/root/kept is no backup that `garrison backup` wrote (no backup.json there); nothing \
             was changed. [install-not-a-backup]",
        ),
        (
            copies_refused("/root/kept", "{\"result\": \"failed\"}"),
            "The copies in /root/kept did not pass `garrison self-check --state`; nothing was \
             changed.\n{\"result\": \"failed\"} [install-copies-refused]",
        ),
        (
            restore_config_refused("0.2.0", settings, "Configuration not usable: [x]"),
            "Garrison 0.2.0's check-config refuses /etc/garrison/garrison.toml; nothing was \
             changed:\nConfiguration not usable: [x] [install-restore-config-refused]",
        ),
        (
            restore_policy(
                "/root/kept",
                settings,
                "0.2.0",
                "Access policy not usable: unknown actions",
            ),
            "The access policy in /root/kept does not suit /etc/garrison/garrison.toml, as Garrison \
             0.2.0's check-config says; nothing was changed:\nAccess policy not usable: unknown \
             actions [install-restore-policy]",
        ),
        (
            keep_failed("/var/backups/garrison: File exists (os error 17)"),
            "The state as it is could not be backed up (/var/backups/garrison: File exists (os \
             error 17)); nothing was changed. [install-keep-failed]",
        ),
        (
            restored("/root/kept", "0.2.0", kept),
            "Restored the state from /root/kept; Garrison 0.2.0 is running. Users sign in again: a \
             backup holds no sessions. The state from before is in \
             /var/backups/garrison/pre-restore-20261124T080000. [install-restored]",
        ),
        (
            restore_failed(&no_broker_group(), None, kept),
            "The restore failed (The group garrison-broker, which reads the access policy, does not \
             exist; the installer makes it. Nothing was changed. [install-no-broker-group]); \
             Garrison is running with what could be put back. The state from before is in \
             /var/backups/garrison/pre-restore-20261124T080000. [install-restore-failed]",
        ),
        (
            restore_neither(&web_restarted(), None, kept),
            "The restore failed (garrison-web.service restarted 3 times within 8 s of starting \
             [install-restarting]); Garrison did not start either. The state from before is in \
             /var/backups/garrison/pre-restore-20261124T080000. [install-restore-neither]",
        ),
        (
            restore_unstarted(&web_restarted(), kept),
            "The state was put back, but Garrison did not start (garrison-web.service restarted 3 \
             times within 8 s of starting [install-restarting]). The state from before is in \
             /var/backups/garrison/pre-restore-20261124T080000; see the journal. \
             [install-restore-unstarted]",
        ),
    ]
}

pub(super) fn places() -> Rows {
    let policy = Path::new("/etc/garrison-link/access.json");
    vec![
        (
            policy_left(policy),
            "broker.policy names /etc/garrison-link/access.json, which is not a file of its own; it \
             was left as it is [install-policy-left]",
        ),
        (
            policy_nameless(Path::new("/")),
            "broker.policy names /, which is no file's name [install-policy-nameless]",
        ),
        (
            policy_place(policy),
            "broker.policy names /etc/garrison-link/access.json, which is not a file of its own: \
             the access policy goes back only as a file, never through a link or into a folder. \
             Nothing was changed. [install-policy-place]",
        ),
        (
            policy_folder(Path::new("/srv/absent")),
            "The folder of broker.policy, /srv/absent, does not exist. Nothing was changed. \
             [install-policy-folder]",
        ),
        (
            policy_hidden("broker.policy is /home/admin/access.json, under /home. Move it."),
            "Access policy not usable: broker.policy is /home/admin/access.json, under /home. Move \
             it. Nothing was changed. [install-policy-hidden]",
        ),
        (
            policy_unknown(
                Path::new("/etc/garrison/garrison.toml"),
                "unknown field `nonsense`",
            ),
            "/etc/garrison/garrison.toml does not load, so an access policy it names outside \
             /etc/garrison is not removed (unknown field `nonsense`); remove it yourself if there \
             is one. [install-policy-unknown]",
        ),
        (
            needs_unshare("/usr/bin/unshare"),
            "/usr/bin/unshare (util-linux) is needed to test nginx without Garrison's snippets; \
             nothing was changed [install-needs-unshare]",
        ),
        (
            nginx_invalid("nginx: [emerg] open() \"/etc/nginx/snippets/garrison.conf\" failed"),
            "nginx would not start without Garrison's snippets; nothing was changed. Remove the \
             `include /etc/nginx/snippets/garrison…` lines from your server blocks first:\nnginx: \
             [emerg] open() \"/etc/nginx/snippets/garrison.conf\" failed [install-nginx-invalid]",
        ),
    ]
}
