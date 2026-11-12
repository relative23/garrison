//! The permission evaluation must equal Stalwart's own answer.
//!
//! For each account shape, Stalwart reports the account's effective permissions
//! through `/api/account` when the account itself signs in with a password.
//! Garrison evaluates the same account from the stored Account and Role
//! objects. The last test holds what Garrison assumes about Stalwart's sign-in
//! page (`sign_in_page`) against the page itself. These tests need a lab: start it with `eval "$(cargo xtask lab
//! start)"`, then run `cargo test --workspace --test contract -- --ignored`.

// Helpers fail the calling test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use garrison_stalwart::ids::account_id_for_subject;
use garrison_stalwart::jmap::JmapClient;
use garrison_stalwart::permissions::{
    ACCOUNT_PROPERTIES, AUTHENTICATION_PROPERTIES, Account, Authentication, ROLE_PROPERTIES, Role,
    RoleIds, evaluate, is_verified_scope, native_rights,
};
use garrison_stalwart::sign_in_page;
use garrison_testing::lab::{Lab, random_hex, unique};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// An object of Stalwart as Garrison's types read it: every role of the
/// server must be one, not only those an account of these tests has.
fn read<T: DeserializeOwned>(value: &Value) -> T {
    serde_json::from_value(value.clone()).unwrap_or_else(|error| panic!("{value}: {error}"))
}

fn fetch(lab: &Lab, account_id: &str) -> (Account, BTreeMap<String, Role>, Authentication) {
    let account = lab.call(
        "x:Account/get",
        &json!({"ids": [account_id], "properties": ACCOUNT_PROPERTIES}),
    );
    let authentication = lab.call(
        "x:Authentication/get",
        &json!({"ids": ["singleton"], "properties": AUTHENTICATION_PROPERTIES}),
    );
    let roles = lab.call(
        "x:Role/get",
        &json!({"ids": null, "properties": ROLE_PROPERTIES}),
    );
    let roles = roles["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|role| {
            let role: Role = read(role);
            (role.id.clone(), role)
        })
        .collect();
    (
        read(&account["list"][0]),
        roles,
        read(&authentication["list"][0]),
    )
}

fn domain_id(lab: &Lab) -> String {
    let domains = lab.call("x:Domain/get", &json!({"ids": null, "properties": ["id"]}));
    domains["list"][0]["id"].as_str().unwrap().to_owned()
}

struct User {
    id: String,
    name: String,
    password: String,
}

fn make_user(lab: &mut Lab, roles: &Value, permissions: &Value) -> User {
    let password = random_hex(18);
    let name = unique();
    let domain = domain_id(lab);
    let id = lab.create(
        "Account",
        &json!({
            "@type": "User",
            "name": name,
            "domainId": domain,
            "credentials": {"0": {"@type": "Password", "secret": password}},
            "roles": roles,
            "permissions": permissions,
        }),
    );
    User { id, name, password }
}

/// Compare the administrative scope exactly; Garrison relies on nothing else.
fn assert_equal(lab: &Lab, user: &User) -> BTreeSet<String> {
    let (account, roles, authentication) = fetch(lab, &user.id);
    let evaluated: BTreeSet<String> = evaluate(&account, &roles, &authentication)
        .unwrap()
        .permissions
        .into_iter()
        .filter(|name| is_verified_scope(name))
        .collect();
    let credentials = format!("{}@example.test:{}", user.name, user.password);
    let native: BTreeSet<String> = lab.http("/api/account", &credentials, None)["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .filter(|name| is_verified_scope(name))
        .map(str::to_owned)
        .collect();
    assert_eq!(
        evaluated,
        native,
        "only evaluated: {:?}, only native: {:?}",
        evaluated.difference(&native).collect::<Vec<_>>(),
        native.difference(&evaluated).collect::<Vec<_>>()
    );
    evaluated
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn default_admin_and_user_roles() {
    let mut lab = Lab::from_environment();
    for kind in ["Admin", "User"] {
        let user = make_user(
            &mut lab,
            &json!({"@type": kind}),
            &json!({"@type": "Inherit"}),
        );
        assert_equal(&lab, &user);
    }
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn custom_roles_with_inheritance_and_denial() {
    let mut lab = Lab::from_environment();
    let tag = unique();
    let parent = lab.create(
        "Role",
        &json!({
            "description": format!("{tag} parent"),
            "roleIds": {},
            "enabledPermissions": {"authenticate": true, "sysAccountGet": true, "sysDomainGet": true},
            "disabledPermissions": {},
        }),
    );
    let child = lab.create(
        "Role",
        &json!({
            "description": format!("{tag} child"),
            "roleIds": {parent: true},
            "enabledPermissions": {"sysRoleGet": true},
            "disabledPermissions": {"sysDomainGet": true},
        }),
    );
    let user = make_user(
        &mut lab,
        &json!({"@type": "Custom", "roleIds": {child: true}}),
        &json!({"@type": "Inherit"}),
    );
    let result = assert_equal(&lab, &user);
    // The child's denial wins over the parent.
    assert!(!result.contains("sysDomainGet"));
    assert!(result.contains("sysAccountGet") && result.contains("sysRoleGet"));
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn account_level_overrides() {
    let mut lab = Lab::from_environment();
    for mode in ["Merge", "Replace"] {
        let user = make_user(
            &mut lab,
            &json!({"@type": "User"}),
            &json!({
                "@type": mode,
                "enabledPermissions": {"authenticate": true, "sysAccountGet": true},
                "disabledPermissions": {"sysDomainGet": true},
            }),
        );
        let result = assert_equal(&lab, &user);
        assert!(result.contains("sysAccountGet"), "{mode}");
        assert!(!result.contains("sysDomainGet"), "{mode}");
    }
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn oidc_subject_maps_to_account_id() {
    let mut lab = Lab::from_environment();
    let user = make_user(
        &mut lab,
        &json!({"@type": "User"}),
        &json!({"@type": "Inherit"}),
    );
    let credentials = format!("{}@example.test:{}", user.name, user.password);
    let session = lab.http("/jmap/session", &credentials, None);
    let primary: BTreeSet<&str> = session["primaryAccounts"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(primary, BTreeSet::from([user.id.as_str()]));
    // The decimal subject that UserInfo returns maps to the same JMAP identifier.
    assert!((0..4096).any(|number| {
        account_id_for_subject(&number.to_string()).is_ok_and(|id| id == user.id)
    }));
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn role_map_shape_is_boolean() {
    let lab = Lab::from_environment();
    let authentication = lab.call(
        "x:Authentication/get",
        &json!({"ids": ["singleton"], "properties": AUTHENTICATION_PROPERTIES}),
    );
    let defaults: RoleIds = read(&authentication["list"][0]["defaultAdminRoleIds"]);
    assert!(!defaults.0.is_empty());
}

/// The permissions `garrison stalwart setup` gives the broker's API key.
const BROKER_PERMISSIONS: [&str; 4] = [
    "authenticate",
    "sysAccountGet",
    "sysRoleGet",
    "sysAuthenticationGet",
];

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn the_broker_key_reads_the_role_graph_it_evaluates() {
    let mut lab = Lab::from_environment();
    let tag = unique();
    let permissions: Value = BROKER_PERMISSIONS
        .iter()
        .map(|name| (name.to_string(), json!(true)))
        .collect();
    let created = lab.call(
        "x:ApiKey/set",
        &json!({"create": {"k": {
            "description": format!("{tag} broker contract test"),
            "permissions": {"@type": "Replace", "permissions": permissions},
            "expiresAt": null,
        }}}),
    );
    let key = &created["created"]["k"];
    lab.created
        .push(("ApiKey".into(), key["id"].as_str().unwrap().to_owned()));
    let parent = lab.create(
        "Role",
        &json!({
            "description": format!("{tag} parent"),
            "roleIds": {},
            "enabledPermissions": {"authenticate": true, "sysAccountGet": true},
            "disabledPermissions": {},
        }),
    );
    let child = lab.create(
        "Role",
        &json!({
            "description": format!("{tag} child"),
            "roleIds": {parent.clone(): true},
            "enabledPermissions": {"sysRoleGet": true},
            "disabledPermissions": {},
        }),
    );
    let user = make_user(
        &mut lab,
        &json!({"@type": "Custom", "roleIds": {child.clone(): true}}),
        &json!({"@type": "Inherit"}),
    );
    let client = JmapClient::new(&lab.url, key["secret"].as_str().unwrap());
    let rights = native_rights(&client, &user.id).unwrap();
    assert_eq!(rights.roles, BTreeSet::from([parent, child]));
    let (account, roles, authentication) = fetch(&lab, &user.id);
    assert_eq!(rights, evaluate(&account, &roles, &authentication).unwrap());
    assert_eq!(
        rights
            .permissions
            .into_iter()
            .filter(|name| is_verified_scope(name))
            .collect::<BTreeSet<_>>(),
        assert_equal(&lab, &user)
    );
}

/// The texts in quotes in `html` that name a script or a style sheet.
fn named_files(html: &str) -> BTreeSet<&str> {
    html.split(['"', '\'', '`'])
        .filter(|text| {
            let kind = std::path::Path::new(text).extension();
            kind.is_some_and(|kind| {
                kind.eq_ignore_ascii_case("js") || kind.eq_ignore_ascii_case("css")
            })
        })
        .filter(|text| {
            text.len() > 4
                && text.len() < 200
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_./:".contains(&byte))
        })
        .collect()
}

/// Whatever script or style sheet the page everybody signs in on names, it
/// must name in the tags that `garrison doctor` reads, and Stalwart must
/// serve each as what it is. If this fails, the page was rebuilt: a doctor
/// that misses a file
/// would call a page in order that a proxy has cut off from it.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn the_sign_in_page_names_files_that_stalwart_serves() {
    let lab = Lab::from_environment();
    let (status, media, html) = lab.page(sign_in_page::PATH);
    assert_eq!(status, 200, "{}", sign_in_page::PATH);
    assert!(media.starts_with("text/html"), "{media}");
    let files = sign_in_page::files(&html);
    let read: BTreeSet<&str> = files.iter().map(|(_, name)| name.as_str()).collect();
    assert_eq!(
        named_files(&html),
        read,
        "the sign-in page names files outside the tags the doctor reads"
    );
    let page = format!("{}{}", lab.url, sign_in_page::PATH);
    for (kind, reference) in &files {
        let address = sign_in_page::address(&page, reference)
            .unwrap_or_else(|| panic!("{reference} is not on Stalwart's own host"));
        let path = address.strip_prefix(&lab.url).unwrap();
        let (status, media, _) = lab.page(path);
        assert_eq!(status, 200, "{path}");
        assert!(
            sign_in_page::media_fits(*kind, &media),
            "{path} is served as {media}"
        );
    }
    println!("the sign-in page names {} files", files.len());
}
