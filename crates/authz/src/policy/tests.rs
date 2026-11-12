use serde_json::json;

use super::*;

fn actions() -> BTreeSet<&'static str> {
    BTreeSet::from(["run_monitor", "run_backup"])
}

fn document() -> Value {
    garrison_testing::policy_document()
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

#[test]
fn profiles_union_with_native_rights_as_upper_bound() {
    let policy = parse_policy(&document(), &actions()).unwrap();
    let admin_rights = set(&[
        "authenticate",
        "sysActionCreate",
        "sysRoleUpdate",
        "sysAccountGet",
    ]);
    let result = policy
        .capabilities("1", &admin_rights, &set(&["e", "v"]))
        .unwrap();
    assert_eq!(result.profiles, ["administrator", "viewer"]);
    assert!(result.actions.contains("run_backup"));
    assert!(result.modules.contains(&ModuleId::Actions));
    // The same role binding without the native rights grants only the viewer profile.
    let weaker = policy
        .capabilities(
            "1",
            &set(&["authenticate", "sysAccountGet"]),
            &set(&["e", "v"]),
        )
        .unwrap();
    assert_eq!(weaker.profiles, ["viewer"]);
    assert!(weaker.actions.is_empty());
}

#[test]
fn denial_wins_before_any_native_lookup() {
    let mut value = document();
    value["deniedSubjects"] = json!(["1"]);
    value["subjects"] = json!({"1": {"accountId": "b", "profile": "viewer"}});
    let policy = parse_policy(&value, &actions()).unwrap();
    assert_eq!(
        policy.account_for("1"),
        Err(Error::Denied(
            "This identity is explicitly denied Garrison access".into()
        ))
    );
}

#[test]
fn subjects_map_explicitly_or_by_their_native_number() {
    let mut value = document();
    value["subjects"] = json!({"user@sso": {"accountId": "x7", "profile": "viewer"}});
    let policy = parse_policy(&value, &actions()).unwrap();
    assert_eq!(policy.account_for("user@sso").unwrap(), "x7");
    assert_eq!(policy.account_for("32").unwrap(), "ba");
    assert!(policy.account_for("other@sso").is_err());
    value["roleBindings"] = json!({});
    let unbound = parse_policy(&value, &actions()).unwrap();
    assert_eq!(
        unbound.account_for("32"),
        Err(Error::Denied("This identity has no Garrison grant".into()))
    );
    // An explicit subject entry is a profile candidate without a role binding.
    let rights = set(&["authenticate", "sysAccountGet"]);
    let result = unbound
        .capabilities("user@sso", &rights, &BTreeSet::new())
        .unwrap();
    assert_eq!(result.profiles, ["viewer"]);
}

#[test]
fn unbound_roles_grant_nothing() {
    let policy = parse_policy(&document(), &actions()).unwrap();
    assert_eq!(
        policy.capabilities("1", &set(&["authenticate", "sysAccountGet"]), &set(&["b"])),
        Err(Error::Denied(
            "This identity has no eligible Garrison profile".into()
        ))
    );
}

/// Why a changed test document is refused.
fn refused(mutate: fn(&mut Value)) -> String {
    let mut value = document();
    mutate(&mut value);
    match parse_policy(&value, &actions()) {
        Err(PolicyError(reason)) => reason,
        Ok(_) => panic!("accepted: {value}"),
    }
}

type Mutation = fn(&mut Value);

#[test]
fn policies_that_break_a_rule_fail_closed_with_a_reason() {
    let cases: [(Mutation, &str); 14] = [
        (
            |d| {
                d["profiles"]["viewer"]["modules"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("unknown"));
            },
            "unknown modules",
        ),
        (
            |d| {
                d["profiles"]["viewer"]["requiredNativePermissions"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("jmapEmailGet"));
            },
            "profile viewer requiredNativePermissions must list authenticate and sys* rights",
        ),
        (
            |d| {
                d["profiles"]["administrator"]["requiredNativePermissions"] =
                    json!(["authenticate", "sysRoleUpdate"]);
            },
            "profile administrator grants actions without requiring sysActionCreate",
        ),
        (
            |d| d["profiles"]["administrator"]["modules"] = json!(["dashboard"]),
            "profile administrator grants actions without the actions module",
        ),
        (
            |d| {
                d["profiles"]["administrator"]["actions"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("format_disk"));
            },
            "unknown actions",
        ),
        (
            |d| {
                d["profiles"]["administrator"]["actions"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("run_backup"));
            },
            "duplicate actions",
        ),
        (
            |d| {
                d["profiles"]["viewer"]["requiredNativePermissions"] =
                    json!(["authenticate", "authenticate"]);
            },
            "profile viewer requiredNativePermissions must list authenticate and sys* rights",
        ),
        (
            |d| d["profiles"]["viewer"]["requiredNativePermissions"] = json!(["sysAccountGet"]),
            "profile viewer requiredNativePermissions must list authenticate and sys* rights",
        ),
        (|d| d["schemaVersion"] = json!(2), "schemaVersion must be 1"),
        (
            |d| d["roleBindings"]["x"] = json!("missing-profile"),
            "role x names an unknown profile",
        ),
        (|d| d["roleBindings"]["a b"] = json!("viewer"), "role ID"),
        (|d| d["profiles"]["Viewer"] = json!({}), "profile name"),
        (
            |d| d["subjects"]["1"] = json!({"accountId": "b c", "profile": "viewer"}),
            "subject 1 accountId",
        ),
        (|d| d["deniedSubjects"] = json!(["a b"]), "deniedSubjects"),
    ];
    for (mutate, reason) in cases {
        assert_eq!(refused(mutate), reason);
    }
}

#[test]
fn files_of_another_shape_fail_closed_and_name_what_is_wrong() {
    let cases: [(Mutation, &str); 12] = [
        (
            |d| d["extra"] = json!(true),
            "unknown field `extra`, expected one of `schemaVersion`, `profiles`, \
             `roleBindings`, `subjects`, `deniedSubjects`",
        ),
        (
            |d| {
                d.as_object_mut().unwrap().remove("subjects");
            },
            "missing field `subjects`",
        ),
        (
            |d| d["roleBindings"]["e"] = json!(1),
            "invalid type: integer `1`, expected a string",
        ),
        (|d| d["profiles"] = json!({}), "profiles"),
        (
            |d| {
                let viewer = d["profiles"]["viewer"].clone();
                for index in 0..31 {
                    d["profiles"][format!("p{index}")] = viewer.clone();
                }
            },
            "profiles",
        ),
        // A profile or a subject written as a list of its values is none.
        (
            |d| d["profiles"]["viewer"] = json!([[], [], ["authenticate"]]),
            "profile viewer: not a JSON object",
        ),
        (
            |d| d["subjects"]["1"] = json!(["b", "viewer"]),
            "subject 1: not a JSON object",
        ),
        (
            |d| d["subjects"]["1"] = json!({"accountId": "b", "profile": "viewer", "x": 1}),
            "subject 1: unknown field `x`, expected `accountId` or `profile`",
        ),
        (
            |d| d["subjects"]["1"] = json!({"accountId": "b"}),
            "subject 1: missing field `profile`",
        ),
        (
            |d| d["subjects"]["1"] = json!({"accountId": "b", "profile": "owner"}),
            "subject 1 names an unknown profile",
        ),
        (
            |d| d["profiles"]["viewer"]["modules"] = json!("dashboard"),
            "profile viewer: invalid type: string \"dashboard\", expected a sequence",
        ),
        (
            |d| d["profiles"]["viewer"]["more"] = json!(1),
            "profile viewer: unknown field `more`, expected one of `modules`, `actions`, \
             `requiredNativePermissions`",
        ),
    ];
    for (mutate, reason) in cases {
        assert_eq!(refused(mutate), reason);
    }
    // Neither a list, nor the values of the document in the order of its keys.
    let positional = json!([3, document()["profiles"], {}, {}, []]);
    for value in [json!([]), positional] {
        assert_eq!(
            parse_policy(&value, &actions()).unwrap_err().to_string(),
            "Garrison access policy: the document must be an object"
        );
    }
    // A file of another schema is told so, whatever else it holds.
    for value in [
        json!({"schemaVersion": 2}),
        json!({}),
        json!({"schemaVersion": "1"}),
    ] {
        assert_eq!(
            parse_policy(&value, &actions()),
            Err(PolicyError("schemaVersion must be 1".into()))
        );
    }
}

#[test]
fn the_document_form_is_sorted_and_round_trips() {
    let policy = parse_policy(&document(), &actions()).unwrap();
    let written = policy.to_document();
    assert_eq!(parse_policy(&written, &actions()).unwrap(), policy);
    let profiles: Vec<&String> = written["profiles"].as_object().unwrap().keys().collect();
    assert_eq!(profiles, ["administrator", "viewer"]);
    let modules = &written["profiles"]["administrator"]["modules"];
    let menu: Vec<&str> = ModuleId::all().map(ModuleId::as_str).collect();
    assert_eq!(modules, &json!(menu));
    assert_eq!(
        written["profiles"]["administrator"]["requiredNativePermissions"],
        json!(["authenticate", "sysActionCreate", "sysRoleUpdate"])
    );
}

#[test]
fn profile_names_have_a_fixed_shape() {
    assert!(
        is_profile_name("viewer") && is_profile_name("a-1_b") && is_profile_name(&"a".repeat(64))
    );
    assert!(!is_profile_name("") && !is_profile_name("1a") && !is_profile_name(&"a".repeat(65)));
    assert!(!is_profile_name("Admin"));
}
