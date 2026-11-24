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
         authenticate, sysAccountUpdate, sysActionCreate, sysDomainUpdate and sysRoleUpdate.\n\
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

/// What the administrator profile requires, as init says it.
const REQUIRES: &str = "The administrator profile requires authenticate, sysAccountUpdate, \
                        sysActionCreate, sysDomainUpdate and sysRoleUpdate.";

/// What init says of the role `lacking` gives.
const ADMIN_LACKS: &str = "Stalwart's default administrator role admin (Administrators) lacks \
                           sysRoleUpdate: give the role that right in the native administration \
                           (Roles), then run garrison access bind-role admin --profile \
                           administrator. As it is, it meets the profiles operator and viewer.";

/// Where no role qualifies, `init --force` says that it keeps the policy,
/// and what keeps the kept one from working, if anything: an action
/// garrison.toml no longer has, or that it binds nobody, and then what to
/// do. Of a policy that binds a role it says nothing more.
#[test]
fn init_force_says_what_keeps_the_kept_policy_from_working() {
    let (authentication, roles) = lacking();
    let (url, _) = super::graph::stalwart(authentication, roles.as_array().unwrap().clone());
    let directory = prepared();
    let settings = directory.path().join("garrison.toml");
    let written = std::fs::read_to_string(&settings).unwrap();
    std::fs::write(&settings, written.replace("http://127.0.0.1:9", &url)).unwrap();
    let path = directory.path().join("policy.json");
    let forced = || {
        let ran = run(directory.path(), &["access", "init", "--force"]);
        assert_eq!(ran.status.code(), Some(1), "{}", text(&ran.stderr));
        text(&ran.stderr)
    };
    let kept = format!(
        "No native administrator role with full administrative rights was found, and a new \
         default policy would bind no role and sign everyone out: {} is kept as it is.\n",
        path.display()
    );
    // Each part is looked at, whatever the one before it showed.
    let mut wrong = Vec::new();
    let mut expect = |what: &str, said: String, wanted: String| {
        if said != wanted {
            wrong.push(format!("{what}: {said:?}"));
        }
    };
    expect("a policy that binds roles", forced(), kept.clone());
    let mut naming = garrison_testing::policy_document();
    naming["profiles"]["administrator"]["actions"] = json!(["run_backup", "run_other"]);
    garrison_testing::write_private(&path, naming.to_string().as_bytes());
    let removed = format!(
        "{kept}The access policy {} names run_other, which garrison.toml no longer has: run \
         `garrison access update`, which takes it out of the profiles.\n",
        path.display()
    );
    expect("one naming a removed action", forced(), removed);
    let mut nobody = garrison_testing::policy_document();
    nobody["roleBindings"] = json!({});
    garrison_testing::write_private(&path, nobody.to_string().as_bytes());
    let unbound = format!(
        "{kept}It binds no role or account either, so nobody can sign in yet. \
         {REQUIRES}\n{ADMIN_LACKS}\n"
    );
    expect("one that binds nobody", forced(), unbound);
    let help = run(directory.path(), &["access", "init", "--help"]);
    let help = text(&help.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let force = "--force Start over with the default policy, keeping a backup; where no role \
                 qualifies, a policy that reads stays";
    expect(
        "--help",
        help.contains(force).to_string(),
        "true".to_owned(),
    );
    assert_eq!(wrong, Vec::<String>::new());
}

/// Each of Stalwart's default administrator roles that init leaves out is
/// named with why: one that is every user's default role too, one Stalwart
/// has no role of, one whose rights cannot be evaluated. Where none is left
/// that only lacks rights, init says how to bind a role of one's own.
#[test]
fn init_names_each_default_administrator_role_it_leaves_out() {
    let (_, roles) = lacking();
    let mut odd = role("odd", &["authenticate"], "Of another shape");
    odd["enabledPermissions"] = json!(["authenticate"]);
    let mut all = roles.as_array().unwrap().clone();
    all.extend([role("both", &ADMINISTRATOR_RIGHTS, "Everyone's"), odd]);
    let defaults = |admin: &[&str]| {
        json!({"id": "singleton", "defaultAdminRoleIds": names(admin),
               "defaultUserRoleIds": names(&["both"])})
    };
    let first = "No native administrator role with full administrative rights was found, so the \
                 policy binds no role and nobody can sign in yet.";
    let both = "Stalwart's default administrator role both is left out: it is every user's \
                default role too, and binding it would make every user an administrator.";
    let (url, _) = super::graph::stalwart(defaults(&["admin", "both", "gone", "odd"]), all.clone());
    let directory = against(&url);
    let init = run(directory.path(), &["access", "init"]);
    assert_eq!(
        (init.status.code(), text(&init.stderr)),
        (
            Some(1),
            format!(
                "{first} {REQUIRES}\n{ADMIN_LACKS}\n{both}\nStalwart's default administrator \
                 role gone is left out: Stalwart has no role of that ID.\nStalwart's default \
                 administrator role odd (Of another shape) is left out: its rights cannot be \
                 evaluated (this release cannot read role odd).\n"
            )
        )
    );
    let (url, _) = super::graph::stalwart(defaults(&["both"]), all);
    let directory = against(&url);
    let init = run(directory.path(), &["access", "init"]);
    assert_eq!(
        text(&init.stderr),
        format!(
            "{first} {REQUIRES}\n{both}\nOnce the role of your administrators holds these \
             rights, bind it with garrison access bind-role <role-id> --profile administrator.\n"
        )
    );
}
