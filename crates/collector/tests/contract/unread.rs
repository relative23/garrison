//! A method Stalwart does not know, as a release Garrison does not support
//! may lack one this release asks for, is answered with the error
//! `unknownMethod`, also to the collector's own key: the client takes it for
//! an answer this release does not read, not for a refusal of the key, so
//! the checks point to the supported releases and not to setup.

use std::time::Duration;

use garrison_collector::providers::stalwart::REQUIRED_PERMISSIONS;
use garrison_stalwart::Error;
use garrison_stalwart::jmap::JmapClient;
use garrison_testing::lab::{Lab, unique};
use serde_json::{Value, json};

use super::one_at_a_time;

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_method_stalwart_does_not_know_is_no_refusal() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let permissions: Value = REQUIRED_PERMISSIONS
        .iter()
        .map(|name| (name.to_string(), json!(true)))
        .collect();
    let created = lab.call(
        "x:ApiKey/set",
        &json!({"create": {"k": {
            "description": format!("{} unknown method contract test", unique()),
            "permissions": {"@type": "Replace", "permissions": permissions},
            "expiresAt": null,
        }}}),
    );
    let key = &created["created"]["k"];
    lab.created
        .push(("ApiKey".into(), key["id"].as_str().unwrap().to_owned()));
    let client = JmapClient::new(&lab.url, key["secret"].as_str().unwrap())
        .with_timeout(Duration::from_secs(15));
    assert_eq!(
        client.get::<Value>("NoSuchThing", None, &["id"]),
        Err(Error::Unreadable(
            "x:NoSuchThing/get answered the error unknownMethod".into()
        ))
    );
    // A method it knows, beside, answers as before.
    assert!(client.get::<Value>("Domain", None, &["id"]).is_ok());
}
