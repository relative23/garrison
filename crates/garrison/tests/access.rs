//! `garrison access`: the policy it derives from Stalwart's roles, the
//! changes it makes and the backups it keeps.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

// The tests of one part each, beside this crate's root.
#[path = "access/folder.rs"]
mod folder;
#[path = "access/links.rs"]
mod links;

use std::collections::BTreeSet;

use garrison_testing::http::serve;
use serde_json::{Value, json};
use support::{against, names, prepared, respond, run, text};

const ADMINISTRATOR_RIGHTS: [&str; 5] = [
    "authenticate",
    "sysAccountUpdate",
    "sysDomainUpdate",
    "sysRoleUpdate",
    "sysActionCreate",
];

fn role(id: &str, enabled: &[&str], description: &str) -> Value {
    json!({"id": id, "roleIds": {}, "enabledPermissions": names(enabled),
           "disabledPermissions": {}, "description": description})
}

fn policy(directory: &std::path::Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(directory.join("policy.json")).unwrap()).unwrap()
}

#[test]
fn init_binds_only_roles_with_every_administrator_right() {
    let all = ADMINISTRATOR_RIGHTS;
    let authentication = json!({"id": "singleton", "defaultAdminRoleIds": names(&["admin", "partial"]),
                                "defaultUserRoleIds": names(&["user"])});
    let roles = json!([
        role("admin", &all, "Administrators"),
        role("partial", &all[..4], "Almost administrators"),
        role("user", &["authenticate"], "Users"),
    ]);
    let server = serve(vec![
        respond("x:Authentication/get", &json!([authentication])),
        respond("x:Role/get", &roles),
    ]);
    let directory = against(&server.url);
    let init = run(directory.path(), &["access", "init"]);
    assert_eq!(init.status.code(), Some(0), "{}", text(&init.stderr));
    let said = text(&init.stdout);
    assert!(
        said.contains("Bound native role admin (Administrators) to profile administrator.\n"),
        "{said}"
    );
    assert!(!said.contains("partial"), "{said}");
    let policy = policy(directory.path());
    assert_eq!(policy["roleBindings"], json!({"admin": "administrator"}));
    let profile = |name: &str, key: &str| policy["profiles"][name][key].clone();
    assert_eq!(
        profile("administrator", "actions"),
        json!(["run_backup", "run_monitor"])
    );
    assert_eq!(profile("operator", "actions"), json!(["run_monitor"]));
    assert_eq!(profile("viewer", "actions"), json!([]));
    let modules = |name: &str| profile(name, "modules").as_array().unwrap().clone();
    assert!(!modules("viewer").contains(&json!("actions")));
    assert!(modules("operator").contains(&json!("actions")));
    assert_eq!(
        profile("viewer", "requiredNativePermissions"),
        json!(["authenticate", "sysAccountGet", "sysDomainGet"])
    );
    assert_eq!(
        profile("operator", "requiredNativePermissions"),
        json!([
            "authenticate",
            "sysAccountGet",
            "sysActionCreate",
            "sysDomainGet"
        ])
    );
    let sorted: BTreeSet<&str> = all.into_iter().collect();
    assert_eq!(
        profile("administrator", "requiredNativePermissions"),
        json!(sorted)
    );
    server.requests();
    // An existing policy stays unless --force replaces it.
    let again = run(directory.path(), &["access", "init"]);
    assert_eq!(again.status.code(), Some(1));
    assert!(text(&again.stdout).contains("exists; use --force to replace it"));
}

/// Where no role qualifies, as where the administrators' role lacks a right
/// or is none of Stalwart's default administrator roles, init still writes
/// the default profiles, binds no role, says so and how to bind one, and
/// ends with 1; `bind-role` then binds the role the operator names.
#[test]
fn init_without_an_administrator_role_writes_the_profiles_to_bind_one_to() {
    let authentication = json!({"id": "singleton", "defaultAdminRoleIds": names(&["weak"]),
                                "defaultUserRoleIds": {}});
    let server = serve(vec![
        respond("x:Authentication/get", &json!([authentication])),
        respond(
            "x:Role/get",
            &json!([role("weak", &["authenticate"], "Weak")]),
        ),
        respond("x:Role/get", &json!([{"id": "admins"}])),
    ]);
    let directory = against(&server.url);
    let init = run(directory.path(), &["access", "init"]);
    assert_eq!(init.status.code(), Some(1), "{}", text(&init.stderr));
    assert_eq!(
        text(&init.stderr),
        "No native administrator role with full administrative rights was found, so the \
         policy binds no role and nobody can sign in yet. Bind the role of your \
         administrators: garrison access bind-role <role-id> --profile administrator\n"
    );
    let written = policy(directory.path());
    assert_eq!(written["roleBindings"], json!({}));
    let profiles: Vec<&String> = written["profiles"].as_object().unwrap().keys().collect();
    assert_eq!(profiles, ["administrator", "operator", "viewer"]);
    let bound = run(
        directory.path(),
        &[
            "access",
            "bind-role",
            "admins",
            "--profile",
            "administrator",
        ],
    );
    assert_eq!(bound.status.code(), Some(0), "{}", text(&bound.stderr));
    assert_eq!(
        policy(directory.path())["roleBindings"],
        json!({"admins": "administrator"})
    );
    server.requests();
}

#[test]
fn check_shows_what_a_subject_may_use() {
    let account = json!({"id": "b", "@type": "User",
                         "roles": {"@type": "Custom", "roleIds": names(&["e"])},
                         "permissions": {"@type": "Inherit"}});
    let authentication =
        json!({"id": "singleton", "defaultAdminRoleIds": {}, "defaultUserRoleIds": {}});
    let rights = ["authenticate", "sysActionCreate", "sysRoleUpdate"];
    let server = serve(vec![
        respond("x:Account/get", &json!([account])),
        respond("x:Authentication/get", &json!([authentication])),
        respond("x:Role/get", &json!([role("e", &rights, "Editors")])),
    ]);
    let directory = against(&server.url);
    garrison_testing::write_private(
        &directory.path().join("policy.json"),
        garrison_testing::policy_document().to_string().as_bytes(),
    );
    // Subject 1 is the native account "b".
    let check = run(directory.path(), &["access", "check", "1"]);
    assert_eq!(check.status.code(), Some(0), "{}", text(&check.stderr));
    let shown: Value = serde_json::from_str(&text(&check.stdout)).unwrap();
    assert_eq!(shown["roles"], json!(["e"]));
    assert_eq!(shown["profiles"], json!(["administrator"]));
    assert_eq!(shown["actions"], json!(["run_backup", "run_monitor"]));
    assert!(
        shown["modules"]
            .as_array()
            .unwrap()
            .contains(&json!("actions"))
    );
    server.requests();
}

/// What the broker would grant: only the modules this installation offers,
/// actions only with the maintenance module, and nothing at all where no
/// module is left.
#[test]
fn check_shows_only_what_this_installation_offers() {
    let account = json!({"id": "b", "@type": "User",
                         "roles": {"@type": "Custom", "roleIds": names(&["e"])},
                         "permissions": {"@type": "Inherit"}});
    let authentication =
        json!({"id": "singleton", "defaultAdminRoleIds": {}, "defaultUserRoleIds": {}});
    let rights = ["authenticate", "sysActionCreate", "sysRoleUpdate"];
    let answers = [
        respond("x:Account/get", &json!([account])),
        respond("x:Authentication/get", &json!([authentication])),
        respond("x:Role/get", &json!([role("e", &rights, "Editors")])),
    ];
    // Two checks, one answer of each kind for each.
    let server = serve([answers.clone(), answers].concat());
    let directory = against(&server.url);
    let settings = directory.path().join("garrison.toml");
    let written = std::fs::read_to_string(&settings).unwrap();
    let offered = written.replacen("schema = 1\n", "schema = 1\nmodules = [\"logs\"]\n", 1);
    std::fs::write(&settings, offered).unwrap();
    let policy = |document: &Value| {
        garrison_testing::write_private(
            &directory.path().join("policy.json"),
            document.to_string().as_bytes(),
        );
    };
    policy(&garrison_testing::policy_document());
    let check = run(directory.path(), &["access", "check", "1"]);
    assert_eq!(check.status.code(), Some(0), "{}", text(&check.stderr));
    let shown: Value = serde_json::from_str(&text(&check.stdout)).unwrap();
    assert_eq!(shown["profiles"], json!(["administrator"]));
    assert_eq!(shown["modules"], json!(["dashboard", "logs", "services"]));
    assert_eq!(shown["actions"], json!([]));
    // A profile that names only modules this installation does not offer
    // grants nothing: the broker refuses such a user.
    let mut only_actions = garrison_testing::policy_document();
    only_actions["profiles"]["administrator"]["modules"] = json!(["actions"]);
    policy(&only_actions);
    let refused = run(directory.path(), &["access", "check", "1"]);
    assert_eq!(
        (
            refused.status.code(),
            text(&refused.stdout),
            text(&refused.stderr)
        ),
        (
            Some(1),
            String::new(),
            "This identity's profiles grant no module this installation offers\n".to_owned()
        )
    );
    server.requests();
}

/// An answer of Stalwart's that this release does not read is said as one,
/// with where the supported releases are named, and not as a refusal.
#[test]
fn an_answer_this_release_does_not_read_is_said_as_one() {
    // An account whose permissions are of a kind this release does not know.
    let account = json!({"id": "b", "@type": "User", "roles": {"@type": "User"},
                         "permissions": {"@type": "Whatever"}});
    let server = serve(vec![respond("x:Account/get", &json!([account]))]);
    let directory = against(&server.url);
    garrison_testing::write_private(
        &directory.path().join("policy.json"),
        garrison_testing::policy_document().to_string().as_bytes(),
    );
    let check = run(directory.path(), &["access", "check", "1"]);
    assert_eq!(
        (check.status.code(), text(&check.stderr)),
        (
            Some(1),
            "Stalwart answered in a form this release of Garrison does not read \
             (x:Account/get returned an unsupported object); see the supported Stalwart \
             releases in the README\n"
                .to_owned()
        )
    );
    server.requests();
}

#[test]
fn a_role_is_bound_to_a_known_profile_once_stalwart_knows_it() {
    let server = serve(vec![respond("x:Role/get", &json!([{"id": "r2"}]))]);
    let directory = against(&server.url);
    garrison_testing::write_private(
        &directory.path().join("policy.json"),
        garrison_testing::policy_document().to_string().as_bytes(),
    );
    let bound = run(
        directory.path(),
        &["access", "bind-role", "r2", "--profile", "viewer"],
    );
    assert_eq!(bound.status.code(), Some(0), "{}", text(&bound.stderr));
    assert_eq!(policy(directory.path())["roleBindings"]["r2"], "viewer");
    server.requests();
    let unknown = run(
        directory.path(),
        &["access", "bind-role", "r3", "--profile", "auditor"],
    );
    assert_eq!(unknown.status.code(), Some(1));
    assert_eq!(
        text(&unknown.stdout),
        "Unknown profile auditor; known: administrator, viewer\n"
    );
}

#[test]
fn access_changes_keep_a_backup_and_write_the_policy() {
    let directory = prepared();
    for arguments in [
        &["access", "unbind-role", "v"][..],
        &["access", "deny", "42"],
        &["access", "deny", "7"],
        &["access", "deny", "8"],
        &["access", "deny", "8", "--undo"],
    ] {
        let output = run(directory.path(), arguments);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{arguments:?}: {}",
            text(&output.stderr)
        );
        let said = text(&output.stdout);
        assert!(said.contains("Saved "), "{said}");
        // Without root the file cannot be made root's, and the note says
        // which file the broker cannot read.
        if !rustix::process::geteuid().is_root() {
            let policy = directory.path().join("policy.json");
            let note = format!("Note: the broker cannot read {}: ", policy.display());
            assert!(said.contains(&note), "{said}");
        }
    }
    let written = std::fs::read_to_string(directory.path().join("policy.json")).unwrap();
    assert_eq!(written, include_str!("fixtures/policy.json"));
    let backups = std::fs::read_dir(directory.path())
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".bak")
        })
        .count();
    assert!(backups >= 1);
    let listed = run(directory.path(), &["access", "list"]);
    assert_eq!(text(&listed.stdout), written);
    let invalid = run(directory.path(), &["access", "deny", "a b"]);
    assert_eq!(
        (invalid.status.code(), text(&invalid.stdout)),
        (Some(1), "Invalid subject\n".to_owned())
    );
    let profile = run(
        directory.path(),
        &["access", "bind-role", "r", "--profile", "Bad"],
    );
    assert_eq!(profile.status.code(), Some(2));
    assert!(text(&profile.stderr).contains("invalid profile name 'Bad'"));
}
