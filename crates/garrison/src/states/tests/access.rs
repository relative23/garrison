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
        (
            invalid_profile("Admin"),
            "invalid profile name 'Admin' [access-invalid-profile]",
        ),
        (
            not_a_file(policy),
            "/etc/garrison/access-policy.json is a link or a folder, not a file: remove it; then \
             `garrison access init` makes the file itself there. [access-not-a-file]",
        ),
        (
            missing(policy),
            "The access policy /etc/garrison/access-policy.json is missing: `garrison access init` \
             makes it. [access-missing]",
        ),
        (
            too_large(policy),
            "The access policy /etc/garrison/access-policy.json is larger than the broker reads \
             (64 KiB), so it is no policy: move it away and run `garrison access init`, or copy \
             back the newest backup beside it (/etc/garrison/access-policy.json.<time>.bak) with \
             sudo cp where there is one. [access-too-large]",
        ),
        (
            unread_answer("x:Role/get did not return the objects asked for"),
            "Stalwart answered in a form this release of Garrison does not read (x:Role/get did \
             not return the objects asked for); see the supported Stalwart releases in the README \
             [access-unread-answer]",
        ),
        (
            gone.clone(),
            "The access policy /etc/garrison/access-policy.json names run_other, which \
             garrison.toml no longer has: run `garrison access update`, which takes it out of the \
             profiles. [access-actions-gone]",
        ),
        (
            io(policy, std::io::Error::from_raw_os_error(2)),
            "/etc/garrison/access-policy.json: No such file or directory (os error 2) [access-io]",
        ),
        (
            invalid_policy("unknown actions: run_other"),
            "unknown actions: run_other [access-invalid-policy]",
        ),
        (
            unread_policy("not JSON"),
            "Garrison access policy: not JSON [access-unread-policy]",
        ),
        (
            save_too_large(policy),
            "The policy would be larger than the broker reads (64 KiB): the change is not saved, \
             and /etc/garrison/access-policy.json stays as it is. [access-save-too-large]",
        ),
        (
            no_group(policy),
            "Note: the broker cannot read /etc/garrison/access-policy.json: this host has no group \
             garrison-broker. Run the installer, which makes the group and gives it the policy. \
             [access-no-group]",
        ),
        (
            not_chowned(policy, "Operation not permitted (os error 1)"),
            "Note: the broker cannot read /etc/garrison/access-policy.json: it could not be made \
             root's with the group garrison-broker (Operation not permitted (os error 1)). Run the \
             command as root, or the installer again, which does. [access-not-chowned]",
        ),
        (
            saved(
                policy,
                Some(Path::new(
                    "/etc/garrison/access-policy.json.20261124T080000.bak",
                )),
            ),
            "Saved /etc/garrison/access-policy.json; the previous file is kept as \
             /etc/garrison/access-policy.json.20261124T080000.bak. [access-saved]",
        ),
        (
            actions_held(),
            "The profiles have the actions garrison.toml names; nothing to change. \
             [access-actions-held]",
        ),
        (
            profile_changed("administrator", &["run_other"], &["run_check"]),
            "Profile administrator: run_other added, run_check taken out. \
             [access-profile-changed]",
        ),
        (
            run_installer(),
            "Run the installer again now: it writes the polkit rule for these actions and \
             restarts the broker and the web service, which read them only when they start; until \
             then an added action is offered to nobody. [access-run-installer]",
        ),
    ]
}

/// Stalwart's answers and the authorization's refusals.
pub(super) fn answers() -> Rows {
    vec![
        (
            no_object(),
            "Stalwart returned no object [access-no-object]",
        ),
        (
            unavailable("Stalwart did not answer".into()),
            "Stalwart did not answer [access-unavailable]",
        ),
        (
            limited("Stalwart limits the requests".into()),
            "Stalwart limits the requests [access-limited]",
        ),
        (
            invalid_token("The token has ended".into()),
            "The token has ended [access-invalid-token]",
        ),
        (
            denied("This identity's profiles grant no module this installation offers".into()),
            "This identity's profiles grant no module this installation offers [access-denied]",
        ),
        (
            misconfigured("Garrison has no API key for Stalwart".into()),
            "Garrison has no API key for Stalwart [access-misconfigured]",
        ),
    ]
}

pub(super) fn roles() -> Rows {
    let policy = Path::new("/etc/garrison/access-policy.json");
    let gone = actions_gone(policy, &["run_other".to_owned()]);
    vec![
        (
            exists(policy),
            "/etc/garrison/access-policy.json exists; use --force to replace it (a backup is \
             kept). [access-exists]",
        ),
        (
            unbound(&candidates()),
            "No native administrator role with full administrative rights was found, so the \
             policy binds no role and nobody can sign in yet. The administrator profile requires \
             authenticate, sysAccountUpdate, sysActionCreate, sysDomainUpdate and sysRoleUpdate.\n\
             Stalwart's default administrator role 1 (Administrators) lacks sysRoleUpdate: give \
             the role that right in the native administration (Roles), then run garrison access \
             bind-role 1 --profile administrator. As it is, it meets the profile viewer.\n\
             Stalwart's default administrator role 2 is left out: it is every user's default role \
             too, and binding it would make every user an administrator \
             [access-every-users-role]. [access-unbound]",
        ),
        (
            kept(policy, Some(&gone), true, &BTreeMap::new()),
            "No native administrator role with full administrative rights was found, and a new \
             default policy would bind no role and sign everyone out: \
             /etc/garrison/access-policy.json is kept as it is.\nThe access policy \
             /etc/garrison/access-policy.json names run_other, which garrison.toml no longer has: \
             run `garrison access update`, which takes it out of the profiles. \
             [access-actions-gone]\nIt binds no role or account either, so nobody can sign in \
             yet. The administrator profile requires authenticate, sysAccountUpdate, \
             sysActionCreate, sysDomainUpdate and sysRoleUpdate.\nStalwart names no default \
             administrator role: once the role of your administrators holds these rights, bind it \
             with garrison access bind-role <role-id> --profile administrator. [access-kept]",
        ),
        (
            bound("1", Some("Administrators")),
            "Bound native role 1 (Administrators) to profile administrator. [access-bound]",
        ),
        (
            unknown_profile("auditor", &["administrator", "operator", "viewer"]),
            "Unknown profile auditor; known: administrator, operator, viewer \
             [access-unknown-profile]",
        ),
        (
            no_role("17"),
            "Stalwart has no role 17: bind one of the roles the native administration shows \
             (Roles). [access-no-role]",
        ),
        (
            role_unjudged("5", "operator", &tenant_role(None)),
            "Note: the rights of role 5 cannot be evaluated (it belongs to a tenant \
             [access-tenant-role]), so whether its users get the profile operator is not known; \
             `garrison access check <subject>` shows what a user gets. [access-role-unjudged]",
        ),
        (
            role_lacks(
                "e",
                "administrator",
                &["sysAccountUpdate".to_owned(), "sysDomainUpdate".to_owned()],
                &[],
            ),
            "Note: role e lacks sysAccountUpdate and sysDomainUpdate, which the profile \
             administrator requires, so its users get nothing of it until Stalwart's administrator \
             gives the role those rights in the native administration (Roles). As it is, it meets \
             none of the profiles. [access-role-lacks]",
        ),
    ]
}

pub(super) fn locks() -> Rows {
    let policy = Path::new("/etc/garrison/access-policy.json");
    let lock = Path::new("/srv/shared/access.json.lock");
    vec![
        (
            no_subject("a b"),
            "\"a b\" is no subject: a subject is 1 to 128 letters, digits and _ . : @ -, and that \
             of a local Stalwart account its numeric account ID. [access-no-subject]",
        ),
        (
            no_file_name(Path::new("/")),
            "broker.policy names no file: / [access-no-file-name]",
        ),
        (
            lock_link(lock),
            "/srv/shared/access.json.lock is a link, not the lock of `garrison access`: remove it, \
             then run the command again. [access-lock-link]",
        ),
        (
            lock_not_a_file(lock),
            "/srv/shared/access.json.lock is not a file, so not the lock of `garrison access`: \
             remove it, then run the command again. [access-lock-not-a-file]",
        ),
        (
            lock_foreign(lock),
            "/srv/shared/access.json.lock is another user's file, not the lock of `garrison \
             access`: remove it, then run the command again. [access-lock-foreign]",
        ),
        (
            lock_linked(lock),
            "/srv/shared/access.json.lock has another name too (a hard link), so it is not the \
             lock of `garrison access`: remove it, then run the command again. \
             [access-lock-linked]",
        ),
        (
            lock_held(lock),
            "/srv/shared/access.json.lock is held by another process, as another `garrison \
             access` command: try again once it has ended. Where none runs, remove the file and \
             run the command again. [access-lock-held]",
        ),
        (
            no_backup_name(policy),
            "No backup of /etc/garrison/access-policy.json could be kept: every name for one of \
             this second is taken. [access-no-backup-name]",
        ),
        (
            pending_folder(Path::new("/etc/garrison/.access-policy.json.pending")),
            "/etc/garrison/.access-policy.json.pending is a folder, not the file `garrison access` \
             writes the policy to first: remove it, then run the command again. \
             [access-pending-folder]",
        ),
    ]
}

/// The reasons a role is judged or left out by.
pub(super) fn reasons() -> Rows {
    vec![
        (
            too_many_roles(64),
            "it inherits from more than 64 roles, more than Garrison evaluates \
             [access-too-many-roles]",
        ),
        (
            inherits_missing("9"),
            "it inherits from role 9, which Stalwart does not have [access-inherits-missing]",
        ),
        (
            role_unreadable("9"),
            "this release cannot read role 9 [access-role-unreadable]",
        ),
        (
            tenant_role(Some("9")),
            "role 9, from which it inherits, belongs to a tenant [access-tenant-role]",
        ),
        (
            unevaluable("a cycle of roles"),
            "a cycle of roles [access-unevaluable]",
        ),
        (
            every_users_role(),
            "it is every user's default role too, and binding it would make every user an \
             administrator [access-every-users-role]",
        ),
        (
            no_such_role(),
            "Stalwart has no role of that ID [access-no-such-role]",
        ),
        (
            rights_unevaluated(&unevaluable("a cycle of roles")),
            "its rights cannot be evaluated (a cycle of roles [access-unevaluable]) \
             [access-rights-unevaluated]",
        ),
    ]
}
