//! The rows of `garrison access`'s states.

use std::collections::BTreeMap;
use std::path::Path;

use super::Rows;
use crate::access::Candidate;
use crate::states::access::*;

fn candidates() -> BTreeMap<String, Candidate> {
    BTreeMap::from([
        (
            "1".to_owned(),
            Candidate {
                description: Some("Administrators".to_owned()),
                fit: Ok(crate::access::Fit {
                    lacks: vec!["sysRoleUpdate".to_owned()],
                    meets: vec!["viewer".to_owned()],
                }),
            },
        ),
        (
            "2".to_owned(),
            Candidate {
                description: None,
                fit: Err(every_users_role()),
            },
        ),
    ])
}

pub(super) fn rows() -> Rows {
    let policy = Path::new("/etc/garrison/access-policy.json");
    let gone = actions_gone(policy, &["run_other".to_owned()]);
    vec![
        invalid_profile("Admin"),
        not_a_file(policy),
        missing(policy),
        too_large(policy),
        unread_answer("x:Role/get did not return the objects asked for"),
        gone.clone(),
        io(policy, std::io::Error::from_raw_os_error(2)),
        invalid_policy("unknown actions: run_other"),
        unread_policy("not JSON"),
        save_too_large(policy),
        no_group(policy),
        not_chowned(policy, "Operation not permitted (os error 1)"),
        saved(
            policy,
            Some(Path::new(
                "/etc/garrison/access-policy.json.20261124T080000.bak",
            )),
        ),
        actions_held(),
        profile_changed("administrator", &["run_other"], &["run_check"]),
        run_installer(),
    ]
}

/// Stalwart's answers and the authorization's refusals.
pub(super) fn answers() -> Rows {
    vec![
        no_object(),
        unavailable("Stalwart did not answer".into()),
        limited("Stalwart limits the requests".into()),
        invalid_token("The token has ended".into()),
        denied("This identity's profiles grant no module this installation offers".into()),
        misconfigured("Garrison has no API key for Stalwart".into()),
    ]
}

pub(super) fn roles() -> Rows {
    let policy = Path::new("/etc/garrison/access-policy.json");
    let gone = actions_gone(policy, &["run_other".to_owned()]);
    vec![
        exists(policy),
        unbound(&candidates()),
        kept(policy, Some(&gone), true, &BTreeMap::new()),
        bound("1", Some("Administrators")),
        unknown_profile("auditor", &["administrator", "operator", "viewer"]),
        no_role("17"),
        role_unjudged("5", "operator", &tenant_role(None)),
        role_lacks(
            "e",
            "administrator",
            &["sysAccountUpdate".to_owned(), "sysDomainUpdate".to_owned()],
            &[],
        ),
    ]
}

pub(super) fn locks() -> Rows {
    let policy = Path::new("/etc/garrison/access-policy.json");
    let lock = Path::new("/srv/shared/access.json.lock");
    vec![
        no_subject("a b"),
        no_file_name(Path::new("/")),
        lock_link(lock),
        lock_not_a_file(lock),
        lock_foreign(lock),
        lock_linked(lock),
        lock_held(lock),
        no_backup_name(policy),
        pending_folder(Path::new("/etc/garrison/.access-policy.json.pending")),
    ]
}

/// The reasons a role is judged or left out by.
pub(super) fn reasons() -> Rows {
    vec![
        too_many_roles(64),
        inherits_missing("9"),
        role_unreadable("9"),
        tenant_role(Some("9")),
        unevaluable("a cycle of roles"),
        every_users_role(),
        no_such_role(),
        rights_unevaluated(&unevaluable("a cycle of roles")),
    ]
}
