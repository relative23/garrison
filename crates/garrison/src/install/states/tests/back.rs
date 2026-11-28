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
        no_previous(),
        no_other_release(),
        no_state(Path::new("/var/backups/garrison/last-pre-upgrade")),
        state_newer(backup, "0.2.0", "0.1.2"),
        no_broker_group(),
        rollback_unloadable("0.1.2", "Configuration not usable: unknown field `modules`"),
        rollback_unreadable("0.1.2", "collector (schema 3, integrity ok)"),
        rollback_policy(
            backup,
            settings,
            "0.1.2",
            "Access policy not usable: unknown actions",
        ),
        rolling_back(
            "0.1.2",
            "/opt/garrison/releases/0.2.0/bin/garrison install --rollback",
        ),
        rollback_stopped(&web_restarted(), "0.1.2", None),
        rollback_returned(&web_restarted(), went.as_ref()),
        rollback_neither(&web_restarted(), None),
        rolled_back("0.1.2"),
        went.unwrap(),
    ]
}

pub(super) fn restore() -> Rows {
    let kept = Path::new("/var/backups/garrison/pre-restore-20261124T080000");
    let settings = Path::new("/etc/garrison/garrison.toml");
    vec![
        not_a_backup(Path::new("/root/kept")),
        copies_refused("/root/kept", "{\"result\": \"failed\"}"),
        restore_config_refused("0.2.0", settings, "Configuration not usable: [x]"),
        restore_policy(
            "/root/kept",
            settings,
            "0.2.0",
            "Access policy not usable: unknown actions",
        ),
        keep_failed("/var/backups/garrison: File exists (os error 17)"),
        restored("/root/kept", "0.2.0", kept),
        restore_failed(&no_broker_group(), None, kept),
        restore_neither(&web_restarted(), None, kept),
        restore_unstarted(&web_restarted(), kept),
    ]
}

pub(super) fn places() -> Rows {
    let policy = Path::new("/etc/garrison-link/access.json");
    vec![
        policy_left(policy),
        policy_nameless(Path::new("/")),
        policy_place(policy),
        policy_folder(Path::new("/srv/absent")),
        policy_hidden("broker.policy is /home/admin/access.json, under /home. Move it."),
        policy_unknown(
            Path::new("/etc/garrison/garrison.toml"),
            "unknown field `nonsense`",
        ),
        sessions_revoked(3),
        sessions_unrevoked(2, 3, "Stalwart is unavailable"),
        sessions_unread(
            Path::new("/var/lib/garrison/web/web.sqlite"),
            "file is not a database",
        ),
        needs_unshare("/usr/bin/unshare"),
        nginx_invalid("nginx: [emerg] open() \"/etc/nginx/snippets/garrison.conf\" failed"),
    ]
}
