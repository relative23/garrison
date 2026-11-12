//! `garrison access`: the policy it derives from Stalwart's roles, the
//! changes it makes and the backups it keeps.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

mod support;

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

#[test]
fn init_without_an_administrator_role_writes_nothing() {
    let authentication = json!({"id": "singleton", "defaultAdminRoleIds": names(&["weak"]),
                                "defaultUserRoleIds": {}});
    let server = serve(vec![
        respond("x:Authentication/get", &json!([authentication])),
        respond(
            "x:Role/get",
            &json!([role("weak", &["authenticate"], "Weak")]),
        ),
    ]);
    let directory = against(&server.url);
    let init = run(directory.path(), &["access", "init"]);
    assert_eq!(init.status.code(), Some(1), "{}", text(&init.stderr));
    assert!(text(&init.stdout).contains("No native administrator role"));
    assert!(!directory.path().join("policy.json").exists());
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
        assert!(text(&output.stdout).contains("Saved "));
        if !rustix::process::geteuid().is_root() {
            assert!(
                text(&output.stdout)
                    .contains("Note: could not set group garrison-broker on the policy file.")
            );
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
