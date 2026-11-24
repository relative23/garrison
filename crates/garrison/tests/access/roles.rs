//! What `garrison access` says of a role that lacks a right its profile
//! requires: `init` names the rights each of Stalwart's default
//! administrator roles lacks and what it meets as it is, `bind-role` says
//! it of the role it binds, and `init --force` keeps a policy that works
//! where no role qualifies.

use garrison_testing::http::serve;
use serde_json::{Value, json};

use super::support::{against, names, prepared, respond, run, text};
use super::{ADMINISTRATOR_RIGHTS, policy, role};

/// Stalwart's default administrator role `admin`, which lacks
/// sysRoleUpdate but holds what the viewer and operator profiles require.
fn lacking() -> (Value, Value) {
    let rights: Vec<&str> = ADMINISTRATOR_RIGHTS
        .into_iter()
        .filter(|right| *right != "sysRoleUpdate")
        .chain(["sysAccountGet", "sysDomainGet"])
        .collect();
    (
        json!({"id": "singleton", "defaultAdminRoleIds": names(&["admin"]), "defaultUserRoleIds": {}}),
        json!([role("admin", &rights, "Administrators")]),
    )
}

/// The reviewer's case: init names what the role lacks, bind-role binds it
/// as told and says that its users get nothing, and `access check` shows
/// that they do not.
#[test]
fn a_role_that_lacks_a_right_its_profile_requires_is_said_so() {
    let (authentication, roles) = lacking();
    let account = json!({"id": "b", "@type": "User",
                         "roles": {"@type": "Custom", "roleIds": names(&["admin"])},
                         "permissions": {"@type": "Inherit"}});
    let server = serve(vec![
        respond("x:Authentication/get", &json!([authentication])),
        respond("x:Role/get", &roles),
        respond("x:Authentication/get", &json!([authentication])),
        respond("x:Role/get", &roles),
        respond("x:Account/get", &json!([account])),
        respond("x:Authentication/get", &json!([authentication])),
        respond("x:Role/get", &roles),
    ]);
    let directory = against(&server.url);
    let init = run(directory.path(), &["access", "init"]);
    assert_eq!(init.status.code(), Some(1), "{}", text(&init.stderr));
    assert_eq!(
        text(&init.stderr),
        "No native administrator role with full administrative rights was found, so the policy \
         binds no role and nobody can sign in yet. The administrator profile requires \
         authenticate, sysAccountUpdate, sysDomainUpdate, sysRoleUpdate and sysActionCreate.\n\
         Stalwart's default administrator role admin (Administrators) lacks sysRoleUpdate: \
         give the role that right in the native administration (Roles), then run garrison \
         access bind-role admin --profile administrator. As it is, it meets the profiles \
         operator and viewer.\n"
    );
    let bound = run(
        directory.path(),
        &["access", "bind-role", "admin", "--profile", "administrator"],
    );
    assert_eq!(bound.status.code(), Some(0), "{}", text(&bound.stderr));
    let said = text(&bound.stdout);
    assert!(said.contains("Saved "), "{said}");
    assert!(
        said.contains(
            "Note: role admin lacks sysRoleUpdate, which the profile administrator requires, so \
             its users get nothing of it until Stalwart's administrator gives the role that \
             right in the native administration (Roles). As it is, it meets the profiles \
             operator and viewer.\n"
        ),
        "{said}"
    );
    assert_eq!(
        policy(directory.path())["roleBindings"],
        json!({"admin": "administrator"})
    );
    // Subject 1 is the native account "b", whose role is admin alone.
    let check = run(directory.path(), &["access", "check", "1"]);
    assert_eq!(
        (check.status.code(), text(&check.stderr)),
        (
            Some(1),
            "This identity has no eligible Garrison profile\n".to_owned()
        )
    );
    server.requests();
}

/// A role bound to a profile whose rights it holds is bound without a note,
/// and one that Stalwart does not have is not bound.
#[test]
fn a_role_that_meets_its_profile_is_bound_without_a_note() {
    let (authentication, roles) = lacking();
    // Stalwart names an ID it has no object of as not found.
    let none =
        json!({"methodResponses": [["x:Role/get", {"list": [], "notFound": ["nobody"]}, "0"]]});
    let server = serve(vec![
        respond("x:Authentication/get", &json!([authentication])),
        respond("x:Role/get", &roles),
        respond("x:Authentication/get", &json!([authentication])),
        garrison_testing::http::json(&none),
    ]);
    let directory = prepared();
    let settings = directory.path().join("garrison.toml");
    let written = std::fs::read_to_string(&settings).unwrap();
    std::fs::write(
        &settings,
        written.replace("http://127.0.0.1:9", &server.url),
    )
    .unwrap();
    let bound = run(
        directory.path(),
        &["access", "bind-role", "admin", "--profile", "viewer"],
    );
    assert_eq!(bound.status.code(), Some(0), "{}", text(&bound.stderr));
    assert!(
        !text(&bound.stdout).contains("Note: role"),
        "{}",
        text(&bound.stdout)
    );
    let unknown = run(
        directory.path(),
        &["access", "bind-role", "nobody", "--profile", "viewer"],
    );
    assert_eq!(
        (unknown.status.code(), text(&unknown.stderr)),
        (
            Some(1),
            "Stalwart has no role nobody: bind one of the roles the native administration shows \
             (Roles).\n"
                .to_owned()
        )
    );
    assert_eq!(
        policy(directory.path())["roleBindings"]["nobody"],
        Value::Null
    );
    server.requests();
}

/// Where no role qualifies, `init --force` keeps a policy that reads, since
/// a new one would bind nobody and sign everyone out; one that does not read
/// lets nobody in either, and is replaced, its backup kept.
#[test]
fn init_force_keeps_a_policy_that_reads_where_no_role_qualifies() {
    let (authentication, roles) = lacking();
    let answers = || {
        vec![
            respond("x:Authentication/get", &json!([authentication.clone()])),
            respond("x:Role/get", &roles),
        ]
    };
    let server = serve([answers(), answers()].concat());
    let directory = prepared();
    let settings = directory.path().join("garrison.toml");
    let written = std::fs::read_to_string(&settings).unwrap();
    std::fs::write(
        &settings,
        written.replace("http://127.0.0.1:9", &server.url),
    )
    .unwrap();
    let path = directory.path().join("policy.json");
    let before = std::fs::read(&path).unwrap();
    let forced = run(directory.path(), &["access", "init", "--force"]);
    assert_eq!(forced.status.code(), Some(1), "{}", text(&forced.stderr));
    assert!(
        text(&forced.stderr).contains(&format!(
            "a new default policy would bind no role and sign everyone out: {} is kept as it \
             is.",
            path.display()
        )),
        "{}",
        text(&forced.stderr)
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    // A file that is no policy is replaced, and kept as a backup.
    garrison_testing::write_private(&path, b"{ not a policy");
    let replaced = run(directory.path(), &["access", "init", "--force"]);
    assert_eq!(
        replaced.status.code(),
        Some(1),
        "{}",
        text(&replaced.stderr)
    );
    assert_eq!(policy(directory.path())["roleBindings"], json!({}));
    assert!(
        text(&replaced.stdout).contains("the previous file is kept as"),
        "{}",
        text(&replaced.stdout)
    );
    server.requests();
}
