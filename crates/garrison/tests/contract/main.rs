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
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, PoisonError};

use clients::{
    assert_foreign_client_kept, assert_sign_in_check, oauth_client, register_foreign_client,
};
use garrison_testing::lab::Lab;
use garrison_testing::{config_text, write_private};
use keys::{refused_without_the_gateway, rotate};
use serde_json::json;

// The parts of this test, in files beside this one.
mod clients;
mod entries;
mod entry_stops;
mod keys;
mod milter;
mod refused;
mod stopper;
mod stops;
mod together;
mod wire;

/// The tests of this target share Garrison's objects in the lab, one key
/// of each description and one webhook, so they run one at a time.
static LAB: Mutex<()> = Mutex::new(());

/// The lab, for this test alone while the guard lives.
fn lab() -> (MutexGuard<'static, ()>, Lab) {
    let guard = LAB.lock().unwrap_or_else(PoisonError::into_inner);
    (guard, Lab::from_environment())
}

/// Garrison's keys, webhook and sign-in client out of the lab, and the
/// files out of `credentials`, as before a first setup.
fn forget(lab: &Lab, credentials: &std::path::Path) {
    for kind in ["ApiKey", "WebHook", "OAuthClient"] {
        let list = lab.call(&format!("x:{kind}/get"), &json!({"ids": null}));
        for item in list["list"].as_array().unwrap() {
            let ours = match kind {
                "ApiKey" => item["description"]
                    .as_str()
                    .is_some_and(|text| text.starts_with("garrison ")),
                "OAuthClient" => item["clientId"] == "https://admin.example.test/oauth-client.json",
                _ => item["httpHeaders"]["X-Garrison"] == "events",
            };
            if ours {
                lab.call(&format!("x:{kind}/set"), &json!({"destroy": [item["id"]]}));
            }
        }
    }
    let _ = std::fs::remove_dir_all(credentials);
}

/// A configuration in a folder of its own and the lab's administrator in a
/// file, for setup runs whose webhook delivers to `webhook`; the keys also
/// allow the lab's gateway.
struct Setup {
    _folder: tempfile::TempDir,
    directory: PathBuf,
    credential: String,
    webhook: String,
    gateway: String,
}

impl Setup {
    fn new(lab: &Lab, webhook: &str) -> Setup {
        let folder = tempfile::tempdir().unwrap();
        let directory = folder.path().to_owned();
        let settings = config_text(&directory, &lab.url);
        std::fs::write(directory.join("garrison.toml"), settings).unwrap();
        let admin = std::env::var("GARRISON_LAB_ADMIN").unwrap();
        let (user, secret) = admin.split_once(':').unwrap();
        let credential = directory.join("admin.json");
        let document = json!({"username": user, "secret": secret}).to_string();
        write_private(&credential, document.as_bytes());
        Setup {
            _folder: folder,
            credential: credential.to_str().unwrap().to_owned(),
            webhook: webhook.to_owned(),
            gateway: format!(
                "{}/32",
                std::env::var("GARRISON_LAB_CALLBACK_HOST").unwrap()
            ),
            directory,
        }
    }

    /// `stalwart setup` with this administrator, webhook and gateway, then `more`.
    fn arguments(&self, more: &[&str]) -> Vec<String> {
        let base = [
            "stalwart",
            "setup",
            "--admin-credential",
            &self.credential,
            "--webhook-url",
            &self.webhook,
            "--allow-network",
            &self.gateway,
        ];
        base.iter()
            .chain(more)
            .map(|&word| word.to_owned())
            .collect()
    }

    fn run(&self, more: &[&str]) -> Output {
        let arguments = self.arguments(more);
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        run(&self.directory, &arguments)
    }
}

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
    let (_guard, mut lab) = lab();
    let admin = std::env::var("GARRISON_LAB_ADMIN").unwrap();
    let (user, secret) = admin.split_once(':').unwrap();
    let directory = tempfile::tempdir().unwrap();
    forget(&lab, &directory.path().join("credentials"));
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
    milter::macro_filter(&mut lab, directory.path(), &credential, &gateway);
    refused_without_the_gateway(&mut lab, directory.path(), &credential);
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
