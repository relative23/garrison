//! What setup says where something refuses it, and that it leaves both
//! places agreeing: the administrator refused.

use std::path::Path;

use garrison_testing::lab::{Lab, random_hex, unique};
use garrison_testing::write_private;
use serde_json::json;

use super::{Setup, forget, lab, text};

/// The keys in the lab described as Garrison's.
fn garrisons_keys(lab: &Lab) -> usize {
    let listed = lab.call("x:ApiKey/get", &json!({"ids": null}));
    listed["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|key| {
            key["description"]
                .as_str()
                .is_some_and(|text| text.starts_with("garrison "))
        })
        .count()
}

/// A wrong password, an unknown user and an API key Stalwart does not know
/// are all answered 401, an API key of the administrator's that does not
/// allow this host's address 403: setup says that the administrator was
/// refused and what to check, where it said "x:ApiKey/get: HTTP 401", and
/// changes nothing. A user without administrator rights gets as far as the
/// first key, which Stalwart does not let it make.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_refused_administrator_is_said_as_such() {
    let (_guard, mut lab) = lab();
    let setup = Setup::new(&lab, "http://127.0.0.1:9/webhook");
    forget(&lab, &setup.directory.join("credentials"));
    let elsewhere = lab.call(
        "x:ApiKey/set",
        &json!({"create": {"k": {
            "description": "an administrator's key for loopback alone",
            "permissions": {"@type": "Replace", "permissions": {"authenticate": true}},
            "allowedIps": {"127.0.0.1/32": true},
            "expiresAt": null,
        }}}),
    );
    let key = &elsewhere["created"]["k"];
    let domains = lab.call("x:Domain/get", &json!({"ids": null, "properties": ["id"]}));
    let (user, password) = (unique(), random_hex(18));
    lab.create(
        "Account",
        &json!({
            "@type": "User",
            "name": user,
            "domainId": domains["list"][0]["id"],
            "credentials": {"0": {"@type": "Password", "secret": password}},
            "roles": {"@type": "User"},
            "permissions": {"@type": "Inherit"},
        }),
    );
    let refused = [
        (
            json!({"username": lab.admin_name(), "secret": "not-the-password"}),
            401,
        ),
        (
            json!({"username": "nobody-here", "secret": "not-the-password"}),
            401,
        ),
        (
            json!({"apiKey": "an-api-key-that-stalwart-does-not-know"}),
            401,
        ),
        (json!({"apiKey": key["secret"]}), 403),
        (json!({"username": user, "secret": password}), 200),
    ];
    let mut said = Vec::new();
    for (wrong, status) in refused {
        write_private(Path::new(&setup.credential), wrong.to_string().as_bytes());
        let output = setup.run(&[]);
        said.push((
            status,
            output.status.code(),
            text(&output),
            garrisons_keys(&lab),
        ));
    }
    lab.call("x:ApiKey/set", &json!({"destroy": [key["id"]]}));
    for (status, code, said, keys) in said {
        let expected = match status {
            401 => {
                "Stalwart refused the administrator (HTTP 401): check the user name and the \
                 password, or the API key."
            }
            403 => "Stalwart refused the administrator from this host's address (HTTP 403)",
            _ => {
                "Stalwart refused the administrator the API key 'garrison broker', since it may \
                 not grant the key's permissions: run setup as an administrator who holds them"
            }
        };
        assert!(
            code == Some(1) && said.contains(expected) && keys == 0,
            "{status}: exit {code:?}, {keys} keys of Garrison's: {said}"
        );
    }
}
