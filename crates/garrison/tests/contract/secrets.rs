//! What Stalwart answers where it refuses one of the two objects that carry
//! a secret of setup's, the webhook with its signature key and the metrics
//! with the scrape credential: setup prints that refusal as Stalwart words
//! it, so it must not hold the secret that was sent with it.

use garrison_testing::lab::{Lab, random_hex};
use serde_json::{Value, json};

use super::{Setup, forget, lab, run, text};

/// The webhook as setup writes it, signing with `secret`, with the fields
/// of `changed` in place of its own.
fn webhook(secret: &str, changed: &Value) -> Value {
    let events: serde_json::Map<String, Value> = garrison_ingest::policy::event_types()
        .into_iter()
        .map(|kind| (kind.to_owned(), json!(true)))
        .collect();
    let mut object = json!({
        "url": "http://127.0.0.1:9/webhook", "events": events, "eventsPolicy": "include",
        "level": "trace", "timeout": 5000, "throttle": 1000, "discardAfter": 3_600_000,
        "lossy": false, "signatureKey": {"@type": "Value", "secret": secret},
        "httpAuth": {"@type": "Unauthenticated"}, "httpHeaders": {"X-Garrison-Probe": "secrets"},
        "allowInvalidCerts": false, "enable": true,
    });
    for (field, value) in changed.as_object().unwrap() {
        object[field] = value.clone();
    }
    object
}

/// What Stalwart answers `method` with `arguments`, as the lab's
/// administrator, whatever it answers: the method's response.
fn answer(lab: &Lab, method: &str, arguments: &Value) -> Value {
    let admin = std::env::var("GARRISON_LAB_ADMIN").unwrap();
    let request = json!({"using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
        "methodCalls": [[method, arguments, "0"]]});
    lab.http("/jmap/", &admin, Some(&request))["methodResponses"][0].clone()
}

/// Whether Stalwart refused what `response` answers: a method's error, or
/// an object it did not create or change.
fn refused(response: &Value) -> bool {
    response[0] == "error"
        || ["notCreated", "notUpdated"].iter().any(|key| {
            response[1][key]
                .as_object()
                .is_some_and(|map| !map.is_empty())
        })
}

/// The objects with a secret that Stalwart is to refuse, each in the form
/// setup sends with one field Stalwart does not take, and what it answered:
/// new webhooks, changes of Garrison's webhook `id` and of the metrics. An
/// empty secret, which holds none to show, says whether Stalwart repeats a
/// secret's value where it refuses that.
fn probes(lab: &Lab, id: &str, secret: &str) -> Vec<(&'static str, Value)> {
    let value = || json!({"@type": "Value", "secret": secret});
    let unknown = || json!({"@type": "NoSuchSecret", "secret": secret});
    let mut asked = Vec::new();
    for changed in [
        json!({"url": 5}),
        json!({"timeout": "never"}),
        json!({"level": "loudest"}),
        json!({"signatureKey": unknown()}),
        json!({"signatureKey": {"@type": "Value", "secret": ""}}),
    ] {
        let create = json!({"create": {"probe": webhook(secret, &changed)}});
        let response = answer(lab, "x:WebHook/set", &create);
        asked.push(("x:WebHook/set create", response));
    }
    for changed in [
        json!({"url": 5, "signatureKey": value()}),
        json!({"signatureKey": unknown()}),
    ] {
        let mut update = serde_json::Map::new();
        update.insert(id.to_owned(), changed);
        let response = answer(lab, "x:WebHook/set", &json!({ "update": update }));
        asked.push(("x:WebHook/set update", response));
    }
    for prometheus in [
        json!({"@type": "Enabled", "authUsername": 5, "authSecret": value()}),
        json!({"@type": "Enabled", "authUsername": "garrison", "authSecret": unknown()}),
        json!({"@type": "NoSuchExporter", "authUsername": "garrison", "authSecret": value()}),
        json!({"@type": "Enabled", "authUsername": "garrison",
            "authSecret": {"@type": "Value", "secret": ""}}),
    ] {
        let update = json!({"update": {"singleton": {"prometheus": prometheus}}});
        let response = answer(lab, "x:Metrics/set", &update);
        asked.push(("x:Metrics/set update", response));
    }
    asked
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn stalwarts_refusals_of_the_objects_with_secrets_hold_no_secret() {
    let (_guard, mut lab) = lab();
    let setup = Setup::new(&lab, "http://127.0.0.1:9/webhook");
    let credentials = setup.directory.join("credentials");
    forget(&lab, &credentials);
    let first = setup.run(&[]);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first));
    let hooks = lab.call("x:WebHook/get", &json!({"ids": null}));
    let mut listed = hooks["list"].as_array().unwrap().iter();
    let ours = listed.find(|hook| hook["httpHeaders"]["X-Garrison"] == "events");
    let id = ours.unwrap()["id"].as_str().unwrap().to_owned();
    let secret = random_hex(24);
    let asked = probes(&lab, &id, &secret);
    // Setup itself, with a webhook address Stalwart may refuse.
    let empty = run(
        &setup.directory,
        &[
            "stalwart",
            "setup",
            "--admin-credential",
            &setup.credential,
            "--webhook-url",
            "",
            "--allow-network",
            &setup.gateway,
        ],
    );
    let key = std::fs::read_to_string(credentials.join("webhook-signature-key")).unwrap();
    let said = text(&empty);
    // What Stalwart took of the probes goes, and setup puts back what it wrote.
    for (_, response) in &asked {
        if let Some(made) = response[1]["created"]["probe"]["id"].as_str() {
            lab.created.push(("WebHook".into(), made.to_owned()));
        }
    }
    let again = setup.run(&[]);
    forget(&lab, &credentials);
    for (what, response) in &asked {
        println!("{what}: {response}");
    }
    println!("setup with an empty webhook address: {said}");
    let shown: Vec<String> = asked
        .iter()
        .map(|(_, response)| response.to_string())
        .collect();
    assert_eq!(
        shown.iter().filter(|text| text.contains(&secret)).count(),
        0,
        "{shown:?}"
    );
    for method in ["x:WebHook/set", "x:Metrics/set"] {
        let any = asked
            .iter()
            .any(|(what, response)| what.starts_with(method) && refused(response));
        assert!(any, "Stalwart refused no {method}: {shown:?}");
    }
    assert!(!said.contains(key.trim()), "{said}");
    assert_eq!(again.status.code(), Some(0), "{}", text(&again));
}
