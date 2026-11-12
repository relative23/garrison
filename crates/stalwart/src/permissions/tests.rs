use serde_json::json;

use super::*;
use garrison_testing::http::{json as answer, serve};

/// An object as the client reads it from an answer of Stalwart.
fn read<T: DeserializeOwned>(value: Value) -> T {
    let shown = value.to_string();
    serde_json::from_value(value).unwrap_or_else(|error| panic!("{shown}: {error}"))
}

fn authentication() -> Value {
    json!({
        "id": "singleton",
        "defaultAdminRoleIds": {"admin": true},
        "defaultUserRoleIds": {"user": true, "unused": false},
    })
}

fn account(roles: Value, permissions: Value) -> Value {
    let mut account = json!({"id": "b", "@type": "User"});
    account["roles"] = roles;
    account["permissions"] = permissions;
    account
}

/// `value` with one key set to something else.
fn with(mut value: Value, key: &str, other: Value) -> Value {
    value[key] = other;
    value
}

fn inherit() -> Value {
    json!({"@type": "Inherit"})
}

/// A role as Stalwart sends it.
fn native_role(id: &str, parents: &[&str], enabled: &[&str], disabled: &[&str]) -> Value {
    let map = |names: &[&str]| -> Value {
        names
            .iter()
            .map(|name| (name.to_string(), json!(true)))
            .collect()
    };
    json!({
        "id": id,
        "roleIds": map(parents),
        "enabledPermissions": map(enabled),
        "disabledPermissions": map(disabled),
    })
}

fn role(id: &str, parents: &[&str], enabled: &[&str], disabled: &[&str]) -> (String, Role) {
    (
        id.to_owned(),
        read(native_role(id, parents, enabled, disabled)),
    )
}

/// The rights of an account in the shape Stalwart sent, or why it has none.
fn rights(account: Value, roles: &BTreeMap<String, Role>) -> Result<Rights, Error> {
    evaluate(&read(account), roles, &read(authentication()))
}

fn roles() -> BTreeMap<String, Role> {
    BTreeMap::from([
        role(
            "admin",
            &["user"],
            &["sysAccountGet", "sysBootstrapGet", "sysActionCreate"],
            &[],
        ),
        role("user", &[], &["authenticate", "jmapEmailGet"], &[]),
        role(
            "parent",
            &[],
            &["authenticate", "sysAccountGet", "sysDomainGet"],
            &[],
        ),
        role("child", &["parent"], &["sysRoleGet"], &["sysDomainGet"]),
    ])
}

fn names(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

fn denied(message: &str) -> Result<Rights, Error> {
    Err(Error::denied(message))
}

#[test]
fn default_roles_inherit_and_bootstrap_rights_are_withheld() {
    let admin = rights(account(json!({"@type": "Admin"}), inherit()), &roles()).unwrap();
    assert_eq!(
        admin.permissions,
        names(&[
            "authenticate",
            "jmapEmailGet",
            "sysAccountGet",
            "sysActionCreate"
        ])
    );
    assert_eq!(admin.roles, names(&["admin", "user"]));
    let user = rights(account(json!({"@type": "User"}), inherit()), &roles()).unwrap();
    assert_eq!(user.permissions, names(&["authenticate", "jmapEmailGet"]));
}

#[test]
fn a_denial_anywhere_wins_over_inherited_grants() {
    let custom = json!({"@type": "Custom", "roleIds": {"child": true}});
    let found = rights(account(custom, inherit()), &roles()).unwrap();
    assert_eq!(
        found.permissions,
        names(&["authenticate", "sysAccountGet", "sysRoleGet"])
    );
    assert_eq!(found.roles, names(&["child", "parent"]));
}

#[test]
fn merge_adds_to_roles_and_replace_ignores_them() {
    let own = |mode: &str| {
        json!({
            "@type": mode,
            "enabledPermissions": {"authenticate": true, "sysAccountGet": true},
            "disabledPermissions": {"jmapEmailGet": true},
        })
    };
    let merged = rights(account(json!({"@type": "User"}), own("Merge")), &roles()).unwrap();
    assert_eq!(
        merged.permissions,
        names(&["authenticate", "sysAccountGet"])
    );
    assert_eq!(merged.roles, names(&["user"]));
    let replaced = rights(
        account(json!({"@type": "Admin"}), own("Replace")),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(
        replaced.permissions,
        names(&["authenticate", "sysAccountGet"])
    );
    assert!(replaced.roles.is_empty());
}

#[test]
fn cycles_depth_and_missing_roles_deny() {
    let custom = |id: &str| json!({"@type": "Custom", "roleIds": {id: true}});
    let cyclic = BTreeMap::from([role("a", &["b"], &[], &[]), role("b", &["a"], &[], &[])]);
    let cycle = "Native role inheritance cycle or depth limit";
    assert_eq!(
        rights(account(custom("a"), inherit()), &cyclic),
        denied(cycle)
    );
    let chain: BTreeMap<String, Role> = (0..=17)
        .map(|level| {
            let parent = format!("r{}", level + 1);
            let parents: &[&str] = if level < 17 { &[parent.as_str()] } else { &[] };
            role(&format!("r{level}"), parents, &["authenticate"], &[])
        })
        .collect();
    assert_eq!(
        rights(account(custom("r0"), inherit()), &chain),
        denied(cycle)
    );
    let mut short = chain.clone();
    short.insert("r16".into(), role("r16", &[], &["authenticate"], &[]).1);
    assert!(rights(account(custom("r0"), inherit()), &short).is_ok());
    assert_eq!(
        rights(account(custom("ghost"), inherit()), &roles()),
        denied("Required native role is unavailable")
    );
    // A tenant's role, and a role stored under another role's ID.
    let mut tenant = native_role("parent", &[], &["authenticate"], &[]);
    tenant["memberTenantId"] = json!("t");
    let mut of_tenant = roles();
    of_tenant.insert("parent".into(), read(tenant));
    let mut misfiled = roles();
    misfiled.insert(
        "parent".into(),
        role("other", &[], &["authenticate"], &[]).1,
    );
    for graph in [of_tenant, misfiled] {
        assert_eq!(
            rights(account(custom("child"), inherit()), &graph),
            denied("Required native role is unavailable")
        );
    }
}

#[test]
fn accounts_garrison_does_not_evaluate_deny() {
    let user = json!({"@type": "User"});
    let mut tenant_member = account(user.clone(), inherit());
    tenant_member["memberTenantId"] = json!("t1");
    let mut group = account(user.clone(), inherit());
    group["@type"] = json!("Group");
    for shape in [tenant_member, group] {
        assert_eq!(
            rights(shape.clone(), &roles()),
            denied("A non-tenant native user account is required"),
            "{shape}"
        );
    }
    let mut other = authentication();
    other["id"] = json!("other");
    assert_eq!(
        evaluate(&read(account(user, inherit())), &roles(), &read(other)),
        denied("Native authentication configuration is unavailable")
    );
}

/// A shape this module does not know is no account, role or setting at all:
/// it is never read as the nearest shape it knows.
#[test]
fn unknown_account_shapes_are_not_read() {
    let user = json!({"@type": "User"});
    let lists =
        |mode: &str| json!({"@type": mode, "enabledPermissions": {}, "disabledPermissions": {}});
    let accounts = [
        // A variant with a key it does not have.
        account(json!({"@type": "User", "x": 1}), inherit()),
        account(json!({"@type": "Admin", "x": 1}), inherit()),
        account(json!({"@type": "Custom", "roleIds": {}, "x": 1}), inherit()),
        account(
            user.clone(),
            json!({"@type": "Inherit", "enabledPermissions": {}}),
        ),
        account(user.clone(), with(lists("Merge"), "x", json!(1))),
        account(user.clone(), with(lists("Replace"), "x", json!(1))),
        // A variant without a key it needs, and one that does not exist.
        account(json!({"@type": "Custom"}), inherit()),
        account(user.clone(), json!({"@type": "Merge"})),
        account(
            user.clone(),
            json!({"@type": "Merge", "enabledPermissions": {}}),
        ),
        account(json!({"@type": "Owner"}), inherit()),
        account(json!({"@type": "user"}), inherit()),
        account(user.clone(), json!({"@type": "Append"})),
        account(json!({}), inherit()),
        // Anything but an object, also where serde alone would read a list.
        account(json!(["User"]), inherit()),
        account(json!("User"), inherit()),
        account(json!(null), inherit()),
        account(user.clone(), json!(["Inherit"])),
        account(user.clone(), json!("Inherit")),
        account(user.clone(), json!(null)),
        // Maps with a name that is none, or a value that is no boolean.
        account(
            user.clone(),
            json!({"@type": "Merge", "enabledPermissions": {"Bad": true}, "disabledPermissions": {}}),
        ),
        account(
            user.clone(),
            json!({"@type": "Merge", "enabledPermissions": {}, "disabledPermissions": {"sysRoleGet": 1}}),
        ),
        account(
            json!({"@type": "Custom", "roleIds": {"a": "yes"}}),
            inherit(),
        ),
        account(
            json!({"@type": "Custom", "roleIds": {"a b": true}}),
            inherit(),
        ),
        account(json!({"@type": "Custom", "roleIds": ["a"]}), inherit()),
        // An account without its type, and a tenant that is no ID.
        json!({"id": "b", "roles": user, "permissions": inherit()}),
        with(
            account(user.clone(), inherit()),
            "memberTenantId",
            json!(false),
        ),
        with(account(user.clone(), inherit()), "@type", json!(null)),
    ];
    for shape in accounts {
        assert!(
            serde_json::from_value::<Account>(shape.clone()).is_err(),
            "{shape}"
        );
    }
    // What Stalwart sends is read.
    let merged: Account = read(account(user, lists("Merge")));
    assert_eq!(
        merged.permissions,
        Permissions::Merge {
            enabled_permissions: PermissionNames::default(),
            disabled_permissions: PermissionNames::default(),
        }
    );
}

#[test]
fn unknown_role_and_setting_shapes_are_not_read() {
    let role = || native_role("r", &["p"], &["authenticate"], &[]);
    let roles = [
        with(role(), "id", json!(null)),
        with(role(), "roleIds", json!(null)),
        with(role(), "roleIds", json!({"p": "true"})),
        with(role(), "enabledPermissions", json!(["authenticate"])),
        with(role(), "disabledPermissions", json!({"Authenticate": true})),
        with(role(), "memberTenantId", json!(7)),
        json!({"id": "r", "roleIds": {}, "enabledPermissions": {}}),
    ];
    for shape in roles {
        assert!(
            serde_json::from_value::<Role>(shape.clone()).is_err(),
            "{shape}"
        );
    }
    for shape in [
        json!({"id": "singleton", "defaultAdminRoleIds": {"admin": true}}),
        json!({"id": "singleton", "defaultAdminRoleIds": {}, "defaultUserRoleIds": null}),
        json!({"defaultAdminRoleIds": {}, "defaultUserRoleIds": {}}),
    ] {
        assert!(
            serde_json::from_value::<Authentication>(shape.clone()).is_err(),
            "{shape}"
        );
    }
    // What Stalwart sends is read, with or without a tenant that is null.
    let plain: Role = read(with(role(), "memberTenantId", json!(null)));
    assert_eq!(plain, read(role()));
    assert_eq!(plain.member_tenant_id, None);
}

#[test]
fn maps_and_names_are_bounded() {
    let many: Value = (0..65)
        .map(|index| (format!("r{index}"), json!(true)))
        .collect();
    assert!(serde_json::from_value::<RoleIds>(many).is_err());
    let roles: Value = (0..64)
        .map(|index| (format!("r{index}"), json!(index % 2 == 0)))
        .collect();
    assert_eq!(read::<RoleIds>(roles).0.len(), 32);
    let names = |count: usize| -> Value {
        (0..count)
            .map(|index| (format!("p{index}"), json!(false)))
            .collect()
    };
    assert_eq!(
        read::<PermissionNames>(names(2048)),
        PermissionNames::default()
    );
    assert!(serde_json::from_value::<PermissionNames>(names(2049)).is_err());
    assert!(is_permission("sysAccountGet") && !is_permission("SysAccountGet"));
    assert!(
        !is_permission("") && !is_permission(&"a".repeat(129)) && is_permission(&"a".repeat(128))
    );
    assert!(is_identifier("a-b_9") && !is_identifier("a b") && !is_identifier(""));
    assert!(is_verified_scope("authenticate") && is_verified_scope("sysRoleGet"));
    assert!(!is_verified_scope("jmapEmailGet"));
}

#[test]
fn native_rights_fetch_only_the_roles_the_account_reaches() {
    let respond = |method: &str, list: Value| {
        answer(&json!({"methodResponses": [[method, {"list": list, "notFound": []}, "0"]]}))
    };
    let server = serve(vec![
        respond(
            "x:Account/get",
            json!([account(
                json!({"@type": "Custom", "roleIds": {"child": true}}),
                inherit()
            )]),
        ),
        respond("x:Authentication/get", json!([authentication()])),
        respond(
            "x:Role/get",
            json!([native_role(
                "child",
                &["parent"],
                &["sysRoleGet"],
                &["sysDomainGet"]
            )]),
        ),
        respond(
            "x:Role/get",
            json!([native_role(
                "parent",
                &[],
                &["authenticate", "sysAccountGet"],
                &[]
            )]),
        ),
    ]);
    let client = JmapClient::new(&server.url, "native-key-0123456789");
    let found = native_rights(&client, "b").unwrap();
    assert_eq!(found.roles, names(&["child", "parent"]));
    assert_eq!(
        found.permissions,
        names(&["authenticate", "sysAccountGet", "sysRoleGet"])
    );
    let requests = server.requests();
    assert!(
        requests[2].contains(r#""ids":["child"]"#),
        "{}",
        requests[2]
    );
    assert!(
        requests[3].contains(r#""ids":["parent"]"#),
        "{}",
        requests[3]
    );
}

/// `count` roles without parents as Stalwart sends them, and an account that
/// has all of them.
fn many_roles(count: usize) -> (Value, BTreeMap<String, Value>) {
    let ids: Vec<String> = (0..count).map(|index| format!("r{index}")).collect();
    let assigned: Value = ids.iter().map(|id| (id.clone(), json!(true))).collect();
    let roles = ids
        .iter()
        .map(|id| (id.clone(), native_role(id, &[], &["authenticate"], &[])))
        .collect();
    (
        account(json!({"@type": "Custom", "roleIds": assigned}), inherit()),
        roles,
    )
}

#[test]
fn at_most_64_roles_are_evaluated() {
    let (account, roles) = many_roles(MAX_ROLES);
    let mut roles: BTreeMap<String, Role> = roles
        .into_iter()
        .map(|(id, role)| (id, read(role)))
        .collect();
    assert_eq!(
        rights(account.clone(), &roles).unwrap().roles.len(),
        MAX_ROLES
    );
    roles.extend([role("extra", &[], &[], &[])]);
    assert_eq!(
        rights(account, &roles),
        denied("Native role graph is too large")
    );
}

#[test]
fn native_rights_fetch_up_to_64_roles_in_batches_of_eight() {
    let respond = |method: &str, list: Value| {
        answer(&json!({"methodResponses": [[method, {"list": list, "notFound": []}, "0"]]}))
    };
    let (account, roles) = many_roles(MAX_ROLES);
    let mut responses = vec![
        respond("x:Account/get", json!([account])),
        respond("x:Authentication/get", json!([authentication()])),
    ];
    let mut ids: Vec<&String> = roles.keys().collect();
    ids.sort();
    for batch in ids.chunks(8) {
        let list: Vec<&Value> = batch.iter().map(|id| &roles[*id]).collect();
        responses.push(respond("x:Role/get", json!(list)));
    }
    let server = serve(responses);
    let client = JmapClient::new(&server.url, "native-key-0123456789");
    assert_eq!(native_rights(&client, "b").unwrap().roles.len(), MAX_ROLES);
    assert_eq!(server.requests().len(), 2 + MAX_ROLES / 8);
}
