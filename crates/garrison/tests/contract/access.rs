//! What `garrison access bind-role` asks of Stalwart: the role it binds by
//! its ID, with those it inherits from, and an ID Stalwart has no role of is
//! said as one.

use std::path::Path;

use garrison_stalwart::ids::decode_native_id;
use garrison_testing::lab::Lab;
use serde_json::{Value, json};

use super::{run, text};

/// bind-role of the role `init` bound in `directory`, which meets its
/// profile; of an ID Stalwart has no role of, and of one that is none of its
/// IDs. Every role's ID is a numeral of Stalwart's, as bind-role takes it.
pub(crate) fn bind_role(lab: &Lab, directory: &Path) {
    let written = std::fs::read_to_string(directory.join("policy.json")).unwrap();
    let policy: Value = serde_json::from_str(&written).unwrap();
    let bindings = policy["roleBindings"].as_object().unwrap();
    let role = bindings.keys().next().unwrap().clone();
    let bound = run(
        directory,
        &["access", "bind-role", &role, "--profile", "administrator"],
    );
    let said = text(&bound);
    assert_eq!(bound.status.code(), Some(0), "{said}");
    // A note that the broker cannot read the file is this host's, not the role's.
    assert!(
        said.contains("Saved ")
            && !said.contains("Note: role")
            && !said.contains("cannot be evaluated"),
        "{said}"
    );
    for unknown in ["zzzzzzzz", "no-such-role"] {
        let refused = run(
            directory,
            &["access", "bind-role", unknown, "--profile", "viewer"],
        );
        let said = text(&refused);
        assert_eq!(refused.status.code(), Some(1), "{said}");
        assert!(
            said.contains(&format!("Stalwart has no role {unknown}:")),
            "{said}"
        );
    }
    let roles = lab.call("x:Role/get", &json!({"ids": null, "properties": ["id"]}));
    for role in roles["list"].as_array().unwrap() {
        let id = role["id"].as_str().unwrap();
        assert!(decode_native_id(id).is_some(), "{id}");
    }
}
