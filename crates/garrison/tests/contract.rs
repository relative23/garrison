//! An operator's setup against the pinned Stalwart: `stalwart setup` creates
//! the webhook, both API keys and the exporter credential, is idempotent and
//! leaves other applications' OAuth clients alone;
//! `access init` then finds the native administrator role with the broker's
//! key. The macro filter is entered only while it answers and taken out with
//! its section of the configuration. Run with `cargo test --workspace --test contract -- --ignored` and the
//! variables of `cargo xtask lab start`. The lab runs in Docker, where
//! Stalwart sees the bridge gateway (`GARRISON_LAB_CALLBACK_HOST`) instead of
//! 127.0.0.1, so the keys allow that address as well.

// Helpers fail the test by panicking, like the test itself.
#![allow(clippy::unwrap_used)]

use std::process::{Command, Output};

use garrison_testing::lab::Lab;
use garrison_testing::{config_text, write_private};
use serde_json::json;

fn run(directory: &std::path::Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_garrison"))
        .arg("--config")
        .arg(directory.join("garrison.toml"))
        .args(arguments)
        .env_remove("CREDENTIALS_DIRECTORY")
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn setup_is_idempotent_and_access_init_finds_the_administrators() {
    let mut lab = Lab::from_environment();
    let admin = std::env::var("GARRISON_LAB_ADMIN").unwrap();
    let (user, secret) = admin.split_once(':').unwrap();
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("garrison.toml"),
        config_text(directory.path(), &lab.url),
    )
    .unwrap();
    let credential = directory.path().join("admin.json");
    write_private(
        &credential,
        json!({"username": user, "secret": secret})
            .to_string()
            .as_bytes(),
    );
    let credential = credential.to_str().unwrap().to_owned();
    let gateway = format!(
        "{}/32",
        std::env::var("GARRISON_LAB_CALLBACK_HOST").unwrap()
    );
    register_foreign_client(&lab);

    let first = run(
        directory.path(),
        &[
            "stalwart",
            "setup",
            "--admin-credential",
            &credential,
            "--webhook-url",
            "http://127.0.0.1:9/webhook",
            "--allow-network",
            &gateway,
        ],
    );
    remove_afterwards(&mut lab);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first));
    let output = text(&first);
    for line in [
        "- created API key 'garrison broker'",
        "- created API key 'garrison collector'",
        "webhook -> http://127.0.0.1:9/webhook (111 event types)",
        "- Stalwart accepts both API keys from this host",
    ] {
        assert!(output.contains(line), "{output}");
    }
    let client = "https://admin.example.test/oauth-client.json";
    assert!(
        output.contains(&format!("- registered OAuth client {client}")),
        "{output}"
    );
    let registered = oauth_client(&lab, client);
    assert_sign_in_check(&lab, client);
    assert_foreign_client_kept(&lab);
    let credentials = directory.path().join("credentials");
    for name in [
        "broker-native-key",
        "collector-native-key",
        "webhook-signature-key",
    ] {
        assert!(credentials.join(name).is_file(), "{name}");
    }

    let again = run(
        directory.path(),
        &[
            "stalwart",
            "setup",
            "--admin-credential",
            &credential,
            "--webhook-url",
            "http://127.0.0.1:9/webhook",
            "--allow-network",
            &gateway,
            "--skip-metrics",
        ],
    );
    assert_eq!(again.status.code(), Some(0), "{}", text(&again));
    assert!(text(&again).contains("- updated API key 'garrison broker' (secret unchanged)"));
    assert!(text(&again).contains("- updated webhook"));
    assert!(text(&again).contains(&format!("- updated OAuth client {client}")));
    assert_eq!(oauth_client(&lab, client)["id"], registered["id"]);

    rotate(&mut lab, directory.path(), &credential, &gateway);

    // access init signs in with the new broker key.
    let init = run(directory.path(), &["access", "init"]);
    assert_eq!(init.status.code(), Some(0), "{}", text(&init));
    assert!(
        text(&init).contains("to profile administrator."),
        "{}",
        text(&init)
    );
    let check = run(directory.path(), &["check-config"]);
    assert!(
        text(&check).contains("Access policy valid"),
        "{}",
        text(&check)
    );
    macro_filter(&mut lab, directory.path(), &credential, &gateway);
    refused_without_the_gateway(directory.path(), &credential);
}

/// The macro filter's entry in Stalwart follows the configuration: none while
/// the filter does not answer, one while the `[milter]` section is there,
/// changed in place, and none again once the section is gone.
fn macro_filter(lab: &mut Lab, directory: &std::path::Path, credential: &str, gateway: &str) {
    let path = directory.join("garrison.toml");
    let plain = std::fs::read_to_string(&path).unwrap();
    let setup = || {
        let output = run(
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
            ],
        );
        (output.status.code(), text(&output))
    };
    let entries = |lab: &Lab| {
        lab.call("x:MtaMilter/get", &json!({"ids": null}))["list"]
            .as_array()
            .unwrap()
            .clone()
    };
    let before = entries(lab).len();
    let note = directory.join("credentials/stalwart-milter-id");

    // Nothing listens on the filter's port: setup changes nothing at all.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let with_filter = format!("{plain}\n[milter]\nport = {port}\nwhen_unreachable = \"accept\"\n");
    std::fs::write(&path, &with_filter).unwrap();
    let (code, output) = setup();
    assert_eq!(code, Some(1), "{output}");
    assert!(
        output.contains(&format!(
            "The macro milter does not answer on 127.0.0.1:{port}"
        )),
        "{output}"
    );
    assert!(!output.contains("- updated"), "{output}");
    assert_eq!(entries(lab).len(), before);
    assert!(!note.exists());

    // The filter runs: Stalwart is told of it, as the configuration has it.
    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        garrison_milter::server::serve(
            &listener,
            garrison_milter::Settings {
                tag: false,
                max_bytes: 1024,
            },
        );
    });
    let (code, output) = setup();
    assert_eq!(code, Some(0), "{output}");
    assert!(
        output.contains(&format!("- entered the macro milter (127.0.0.1:{port})")),
        "{output}"
    );
    let id = std::fs::read_to_string(&note).unwrap().trim().to_owned();
    lab.created.push(("MtaMilter".into(), id.clone()));
    let entered = entries(lab);
    assert_eq!(entered.len(), before + 1);
    let entry = entered
        .iter()
        .find(|entry| entry["id"] == id.as_str())
        .unwrap();
    assert_eq!(entry["host"], "127.0.0.1");
    assert_eq!(entry["port"], port);
    assert_eq!(entry["tempFailOnError"], false);

    // Once more, with mail deferred while the filter is away: the same entry.
    std::fs::write(
        &path,
        with_filter.replace("when_unreachable = \"accept\"\n", ""),
    )
    .unwrap();
    let (code, output) = setup();
    assert_eq!(code, Some(0), "{output}");
    assert!(
        output.contains("- updated the macro milter's entry"),
        "{output}"
    );
    let updated = entries(lab);
    assert_eq!(updated.len(), before + 1);
    let entry = updated
        .iter()
        .find(|entry| entry["id"] == id.as_str())
        .unwrap();
    assert_eq!(entry["tempFailOnError"], true);

    // The section is gone: so is the entry, and setup's note of it.
    std::fs::write(&path, &plain).unwrap();
    let (code, output) = setup();
    assert_eq!(code, Some(0), "{output}");
    assert!(
        output.contains("- took the macro milter's entry out of Stalwart"),
        "{output}"
    );
    lab.created.retain(|(_, known)| *known != id);
    assert_eq!(entries(lab).len(), before);
    assert!(!note.exists());
}

/// Without the gateway the keys are allowed from loopback only, which this
/// host is not for the lab's Stalwart, just as for a Stalwart in a bridge
/// network: setup says so instead of leaving keys that never work.
fn refused_without_the_gateway(directory: &std::path::Path, credential: &str) {
    let narrowed = run(
        directory,
        &[
            "stalwart",
            "setup",
            "--admin-credential",
            credential,
            "--webhook-url",
            "http://127.0.0.1:9/webhook",
            "--skip-metrics",
        ],
    );
    assert_eq!(narrowed.status.code(), Some(1), "{}", text(&narrowed));
    assert!(
        text(&narrowed)
            .contains("Stalwart refuses the API key in broker-native-key from this host"),
        "{}",
        text(&narrowed)
    );
}

/// `--rotate` writes new secrets everywhere, and the old keys stop working.
fn rotate(lab: &mut Lab, directory: &std::path::Path, credential: &str, gateway: &str) {
    let credentials = directory.join("credentials");
    let before = secrets(&credentials);
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
    assert_eq!(key_status(lab, &before["broker-native-key"]), 401);
    assert_eq!(key_status(lab, &after["broker-native-key"]), 200);
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

/// The status of Stalwart's JMAP session for an API key: 200 or 401.
fn key_status(lab: &Lab, key: &str) -> u16 {
    let answer = ureq::get(format!("{}/jmap/session", lab.url))
        .header("Authorization", &format!("Bearer {}", key.trim()))
        .call();
    match answer {
        Ok(answer) => answer.status().as_u16(),
        Err(ureq::Error::StatusCode(code)) => code,
        Err(error) => panic!("{error}"),
    }
}

/// Stalwart's answer to doctor's sign-in check (doctor/public.rs): a sign-in
/// request with a fixed state and code challenge, with or without Garrison's
/// callback.
fn sign_in_answer(lab: &Lab, client: &str, callback: Option<&str>) -> serde_json::Value {
    let mut request = ureq::get(format!("{}/api/auth/client", lab.url)).query("client_id", client);
    if let Some(callback) = callback {
        request = request.query("redirect_uri", callback);
    }
    let mut answer = request
        .query("response_type", "code")
        .query("scope", "openid")
        .query("state", "garrison-doctor-0123456789abcdef")
        .query(
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )
        .query("code_challenge_method", "S256")
        .call()
        .unwrap();
    serde_json::from_str(&answer.body_mut().read_to_string().unwrap()).unwrap()
}

/// Stalwart names a registered client only for a request with its callback;
/// without one it answers with an error, which once made doctor report a
/// registered client as unknown.
fn assert_sign_in_check(lab: &Lab, client: &str) {
    let callback = "https://admin.example.test/auth/callback";
    let answer = sign_in_answer(lab, client, Some(callback));
    assert_eq!(answer["verified"], true, "{answer}");
    assert_eq!(answer["name"], "Garrison", "{answer}");
    let answer = sign_in_answer(lab, client, None);
    assert_eq!(answer["error"], "invalid_request", "{answer}");
}

/// Another application's client at Stalwart's own origin.
const FOREIGN: &str = "https://mail.example.test/oauth-client.json";

fn register_foreign_client(lab: &Lab) {
    lab.call(
        "x:OAuthClient/set",
        &json!({"create": {"o": {"clientId": FOREIGN, "description": "Another application",
            "redirectUris": {}, "postLogoutRedirectUris": {}, "scopes": {}}}}),
    );
}

fn assert_foreign_client_kept(lab: &Lab) {
    let clients = lab.call("x:OAuthClient/get", &json!({"ids": null}));
    assert!(
        clients["list"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["clientId"] == FOREIGN),
        "{clients:?}"
    );
}

/// The one OAuth client with this client ID, registered for sign-in only: no
/// service such as mail, no grant but the authorization code, back only to
/// its callback.
fn oauth_client(lab: &Lab, client: &str) -> serde_json::Value {
    let list = lab.call("x:OAuthClient/get", &json!({"ids": null}));
    let mut matching = list["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["clientId"] == client);
    let found = matching
        .next()
        .unwrap_or_else(|| panic!("no OAuth client {client}"));
    assert!(matching.next().is_none(), "two OAuth clients {client}");
    assert_eq!(
        found["redirectUris"],
        json!({"https://admin.example.test/auth/callback": true})
    );
    assert_eq!(found["scopes"], json!({}));
    assert_eq!(found["grantTypes"], json!({"authorizationCode": true}));
    found.clone()
}

/// Remove what setup created when the test ends, so the lab stays reusable.
fn remove_afterwards(lab: &mut Lab) {
    for kind in ["ApiKey", "WebHook", "OAuthClient"] {
        let list = lab.call(&format!("x:{kind}/get"), &json!({"ids": null}));
        for item in list["list"].as_array().unwrap() {
            let ours = match kind {
                "ApiKey" => item["description"]
                    .as_str()
                    .is_some_and(|text| text.starts_with("garrison")),
                "OAuthClient" => item["clientId"]
                    .as_str()
                    .is_some_and(|text| text.ends_with("/oauth-client.json")),
                _ => item["httpHeaders"]["X-Garrison"] == "events",
            };
            let id = item["id"].as_str().unwrap().to_owned();
            if ours && !lab.created.iter().any(|(_, known)| *known == id) {
                lab.created.push((kind.into(), id));
            }
        }
    }
}
