//! The API keys' part of the setup contract test: a rotation that keeps
//! the old keys working until the services hold the new ones, and keys
//! refused where Stalwart sees this host at an address they do not allow.

use std::sync::{Arc, Mutex};

use garrison_testing::lab::{Lab, random_hex, unique};
use garrison_testing::relay::relay;
use garrison_testing::{config_text, write_private};
use serde_json::json;

use super::together::{Capture, assert_exporter_held, assert_keys_held_in, assert_webhook_held};
use super::{Setup, forget, lab, remove_afterwards, run, text};

/// Without the gateway the keys are allowed from loopback only, which this
/// host is not for the lab's Stalwart, just as for a Stalwart in a bridge
/// network: setup says so instead of leaving keys that never work. A
/// rotation that stops there asks for the services' restart, removes the
/// old keys all the same and names the run that finishes it.
pub(super) fn refused_without_the_gateway(
    lab: &mut Lab,
    directory: &std::path::Path,
    credential: &str,
) {
    let setup = |more: &[&str]| {
        let base = ["stalwart", "setup", "--admin-credential", credential];
        let rest = [
            "--webhook-url",
            "http://127.0.0.1:9/webhook",
            "--skip-metrics",
        ];
        let output = run(directory, &[&base[..], &rest, more].concat());
        (output.status.code(), text(&output))
    };
    let (code, output) = setup(&[]);
    assert_eq!(code, Some(1), "{output}");
    let refused = "Stalwart refuses the API key in broker-native-key from this host";
    assert!(output.contains(refused), "{output}");
    lab.created.retain(|(kind, _)| kind != "ApiKey");
    let (code, output) = setup(&["--rotate"]);
    remove_afterwards(lab);
    assert_eq!(code, Some(1), "{output}");
    assert!(output.contains(refused), "{output}");
    assert!(
        output
            .contains("Restart garrison-ingest and garrison-broker so they read the new secrets.")
            && output.contains(
                "with Compose). Run `garrison stalwart setup --rotate` again once this is mended."
            ),
        "{output}"
    );
    let keys = lab.call("x:ApiKey/get", &json!({"ids": null}));
    for description in ["garrison broker", "garrison collector"] {
        let named = keys["list"].as_array().unwrap().iter();
        assert_eq!(
            named
                .filter(|key| key["description"] == description)
                .count(),
            1
        );
    }
}

/// `--rotate` writes new secrets everywhere. The old keys still work while
/// setup tries the new ones, the last thing it does before it restarts the
/// services that hold the old ones, and stop working once it is done.
pub(super) fn rotate(lab: &mut Lab, directory: &std::path::Path, credential: &str, gateway: &str) {
    let credentials = directory.join("credentials");
    let before = secrets(&credentials);
    // Setup reaches Stalwart through a relay that asks Stalwart about the
    // old broker key each time setup tries a key.
    let tried = Arc::new(Mutex::new(Vec::new()));
    let relayed = {
        let (url, old, tried) = (
            lab.url.clone(),
            before["broker-native-key"].clone(),
            Arc::clone(&tried),
        );
        relay(&lab.url, "GET /jmap/session ", move || {
            tried.lock().unwrap().push(key_status(&url, &old));
        })
    };
    let settings = directory.join("garrison.toml");
    std::fs::write(&settings, config_text(directory, &relayed)).unwrap();
    // The rotation removes the old keys itself; the new ones are recorded below.
    lab.created.retain(|(kind, _)| kind != "ApiKey");
    let rotated = run(
        directory,
        &[
            "stalwart",
            "setup",
            "--admin-credential",
            credential,
            "--webhook-url",
            "http://127.0.0.1:9/webhook",
            "--allow-network",
            gateway,
            "--skip-metrics",
            "--rotate",
        ],
    );
    std::fs::write(&settings, config_text(directory, &lab.url)).unwrap();
    remove_afterwards(lab);
    assert_eq!(rotated.status.code(), Some(0), "{}", text(&rotated));
    for key in ["garrison broker", "garrison collector"] {
        assert!(
            text(&rotated).contains(&format!("- replaced API key '{key}'")),
            "{}",
            text(&rotated)
        );
    }
    let after = secrets(&credentials);
    for (name, old) in &before {
        assert_ne!(&after[name], old, "{name} kept its secret");
    }
    // A broker that still held the old key could check rights all along:
    // while setup asks whose the files' keys are, and while it tries the
    // new ones.
    assert_eq!(
        *tried.lock().unwrap(),
        [200, 200, 200, 200],
        "{}",
        text(&rotated)
    );
    assert_eq!(key_status(&lab.url, &before["broker-native-key"]), 401);
    assert_eq!(key_status(&lab.url, &after["broker-native-key"]), 200);
}

/// The secrets `stalwart setup` wrote, by file name.
fn secrets(credentials: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    [
        "broker-native-key",
        "collector-native-key",
        "webhook-signature-key",
    ]
    .into_iter()
    .map(|name| {
        (
            name.to_owned(),
            std::fs::read_to_string(credentials.join(name)).unwrap(),
        )
    })
    .collect()
}

/// The status of the JMAP session of Stalwart at `url` for an API key: 200
/// or 401.
pub(super) fn key_status(url: &str, key: &str) -> u16 {
    let answer = ureq::get(format!("{url}/jmap/session"))
        .header("Authorization", &format!("Bearer {}", key.trim()))
        .call();
    match answer {
        Ok(answer) => answer.status().as_u16(),
        Err(ureq::Error::StatusCode(code)) => code,
        Err(error) => panic!("{error}"),
    }
}

/// What `garrison doctor` tries the broker's key with, the reads of a rights
/// check, as doctor sends them with `key`.
fn broker_reads(url: &str, key: &str) -> Vec<String> {
    reads(
        url,
        key,
        &json!([
            ["x:Account/get", {"ids": null, "properties": ["id"]}, "0"],
            ["x:Authentication/get", {"ids": ["singleton"], "properties": ["id"]}, "1"],
            ["x:Role/get", {"ids": null, "properties": ["id"]}, "2"]]),
    )
}

/// What `garrison doctor` tries the collector's key with, the queries by
/// which the checks find Stalwart's domains and accounts, as doctor sends
/// them with `key`.
fn collector_reads(url: &str, key: &str) -> Vec<String> {
    reads(
        url,
        key,
        &json!([
            ["x:Domain/query", {"limit": 1}, "0"],
            ["x:Account/query", {"limit": 1}, "1"]]),
    )
}

/// What Stalwart answers `calls` with `key`: the method's name for each
/// that answered, the error's type for each that did not.
fn reads(url: &str, key: &str, calls: &serde_json::Value) -> Vec<String> {
    let body = json!({"using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
        "methodCalls": calls});
    let mut answer = ureq::post(format!("{url}/jmap/"))
        .header("Authorization", &format!("Bearer {}", key.trim()))
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .unwrap();
    let answer: serde_json::Value =
        serde_json::from_str(&answer.body_mut().read_to_string().unwrap()).unwrap();
    answer["methodResponses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|response| match response[0].as_str() {
            Some("error") => response[1]["type"].as_str().unwrap_or("?").to_owned(),
            name => name.unwrap_or("?").to_owned(),
        })
        .collect()
}

/// Stalwart answers the broker's reads for the key setup makes, and refuses
/// each with `forbidden` once the key is narrowed to `authenticate`, whose
/// JMAP session it still opens; a plain setup run gives the key its
/// permissions again.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn the_broker_reads_with_the_key_setup_makes_and_no_narrower_one() {
    let (_guard, lab) = lab();
    let setup = Setup::new(&lab, "http://127.0.0.1:9/webhook");
    let credentials = setup.directory.join("credentials");
    forget(&lab, &credentials);
    let ran = setup.run(&["--skip-metrics"]);
    assert_eq!(ran.status.code(), Some(0), "{}", text(&ran));
    let key = std::fs::read_to_string(credentials.join("broker-native-key")).unwrap();
    let all = ["x:Account/get", "x:Authentication/get", "x:Role/get"];
    assert_eq!(broker_reads(&lab.url, &key), all);
    let only_authenticate = json!({"@type": "Replace", "permissions": {"authenticate": true}});
    lab.call(
        "x:ApiKey/set",
        &json!({"update": {key_id(&lab, "garrison broker"): {"permissions": only_authenticate}}}),
    );
    let narrowed = (key_status(&lab.url, &key), broker_reads(&lab.url, &key));
    let again = setup.run(&["--skip-metrics"]);
    let mended = broker_reads(&lab.url, &key);
    forget(&lab, &credentials);
    assert_eq!(narrowed, (200, vec!["forbidden".to_owned(); 3]));
    assert_eq!(again.status.code(), Some(0), "{}", text(&again));
    assert_eq!(mended, all);
}

/// The ID of Garrison's API key of `description`, such as "garrison broker".
fn key_id(lab: &Lab, description: &str) -> String {
    let keys = lab.call("x:ApiKey/get", &json!({"ids": null}));
    keys["list"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["description"] == description)
        .and_then(|key| key["id"].as_str())
        .unwrap()
        .to_owned()
}

/// Stalwart answers the checks' queries for the collector's key setup makes,
/// and refuses each with `forbidden` once the key holds the ten permissions
/// 0.1.2's setup gave it, whose JMAP session it still opens: what an upgrade
/// leaves until setup runs again, which gives the key its permissions.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn the_collector_queries_with_the_key_setup_makes_and_not_with_an_older_one() {
    let (_guard, lab) = lab();
    let setup = Setup::new(&lab, "http://127.0.0.1:9/webhook");
    let credentials = setup.directory.join("credentials");
    forget(&lab, &credentials);
    let ran = setup.run(&["--skip-metrics"]);
    assert_eq!(ran.status.code(), Some(0), "{}", text(&ran));
    let file = credentials.join("collector-native-key");
    let key = std::fs::read_to_string(&file).unwrap();
    let both = ["x:Domain/query", "x:Account/query"];
    assert_eq!(collector_reads(&lab.url, &key), both);
    let older: serde_json::Map<String, serde_json::Value> = [
        "authenticate",
        "sysSpamSettingsGet",
        "sysSpamClassifierGet",
        "sysSpamRuleQuery",
        "sysSpamTrainingSampleQuery",
        "sysQueuedMessageQuery",
        "sysMtaMilterGet",
        "sysAccountGet",
        "sysDomainGet",
        "sysNetworkListenerGet",
    ]
    .iter()
    .map(|name| ((*name).to_owned(), json!(true)))
    .collect();
    let older = json!({"@type": "Replace", "permissions": older});
    lab.call(
        "x:ApiKey/set",
        &json!({"update": {key_id(&lab, "garrison collector"): {"permissions": older}}}),
    );
    let upgraded = (key_status(&lab.url, &key), collector_reads(&lab.url, &key));
    let again = setup.run(&["--skip-metrics"]);
    let key = std::fs::read_to_string(&file).unwrap();
    let mended = collector_reads(&lab.url, &key);
    forget(&lab, &credentials);
    assert_eq!(upgraded, (200, vec!["forbidden".to_owned(); 2]));
    assert_eq!(again.status.code(), Some(0), "{}", text(&again));
    assert_eq!(mended, both);
}

/// The keys setup makes are the administrator's, and another administrator
/// lists only its own account's. A plain run as a second administrator
/// keeps the first one's keys, which the files hold, and its `--rotate`
/// removes them, where both once left them valid for good.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_second_administrator_finds_the_keys_the_first_made() {
    let (_guard, mut lab) = lab();
    let capture = Capture::start();
    let setup = Setup::new(&lab, &capture.url);
    let credentials = setup.directory.join("credentials");
    forget(&lab, &credentials);
    let first = setup.run(&[]);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first));
    let domains = lab.call("x:Domain/get", &json!({"ids": null, "properties": ["id"]}));
    let (name, password) = (unique(), random_hex(18));
    let second = lab.create(
        "Account",
        &json!({
            "@type": "User",
            "name": name,
            "domainId": domains["list"][0]["id"],
            "credentials": {"0": {"@type": "Password", "secret": password}},
            "roles": {"@type": "Admin"},
            "permissions": {"@type": "Inherit"},
        }),
    );
    let administrator = json!({"username": name, "secret": password}).to_string();
    write_private(
        std::path::Path::new(&setup.credential),
        administrator.as_bytes(),
    );
    let plain = setup.run(&[]);
    let said = text(&plain);
    assert_eq!(plain.status.code(), Some(0), "{said}");
    for description in ["garrison broker", "garrison collector"] {
        let kept = format!("- updated API key '{description}' (secret unchanged)");
        assert!(said.contains(&kept), "{said}");
    }
    let context = "a plain run as the second administrator";
    assert_keys_held_in(&lab, &[None], &credentials, &setup.gateway, context);
    let rotated = setup.run(&["--rotate"]);
    let said = text(&rotated);
    assert_eq!(rotated.status.code(), Some(0), "{said}");
    let first_keys = lab.call("x:ApiKey/get", &json!({"ids": null}));
    let left = first_keys["list"].as_array().unwrap().iter().filter(|key| {
        key["description"]
            .as_str()
            .is_some_and(|text| text.starts_with("garrison "))
    });
    assert_eq!(left.count(), 0, "{said}");
    let context = "a rotation as the second administrator";
    assert_keys_held_in(
        &lab,
        &[Some(&second)],
        &credentials,
        &setup.gateway,
        context,
    );
    assert_webhook_held(&lab, &credentials, &capture, context);
    assert_exporter_held(&lab, &credentials, context);
    // The second administrator's keys go before its account does.
    let theirs = lab.call("x:ApiKey/get", &json!({"accountId": second, "ids": null}));
    for key in theirs["list"].as_array().unwrap() {
        lab.call(
            "x:ApiKey/set",
            &json!({"accountId": second, "destroy": [key["id"]]}),
        );
    }
    forget(&lab, &credentials);
}
