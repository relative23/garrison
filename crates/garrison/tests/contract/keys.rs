//! The API keys' part of the setup contract test: a rotation that keeps
//! the old keys working until the services hold the new ones, and keys
//! refused where Stalwart sees this host at an address they do not allow.

use std::sync::{Arc, Mutex};

use garrison_testing::config_text;
use garrison_testing::lab::Lab;
use garrison_testing::relay::relay;
use serde_json::json;

use super::{remove_afterwards, run, text};

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
    // A broker that still held the old key could check rights all along.
    assert_eq!(*tried.lock().unwrap(), [200, 200], "{}", text(&rotated));
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
