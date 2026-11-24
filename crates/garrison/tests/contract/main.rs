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
mod access;
mod clients;
mod entries;
mod entry_refusals;
mod entry_stalwart;
mod entry_stops;
mod exporter;
mod held;
mod keys;
mod milter;
mod refused;
mod scene;
mod stopper;
mod stops;
mod together;
mod wire;

#[path = "../support/mod.rs"]
mod support;

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

/// The states `output` says, on standard output and then standard error.
fn states(output: &Output) -> Vec<String> {
    let mut said = support::states(&output.stdout);
    said.extend(support::states(&output.stderr));
    said
}

/// What a write that was interrupted leaves beside the files, which the
/// next run removes.
const PENDING: &str = ".pending-of-an-interrupted-write";

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
    write_private(&credentials.join(PENDING), b"part of a key");
    unchanged(&lab, directory.path(), &credential, &gateway);
    assert!(!credentials.join(PENDING).exists(), "{PENDING} was left");
    assert_eq!(oauth_client(&lab, client)["id"], registered["id"]);

    rotate(&mut lab, directory.path(), &credential, &gateway);

    access_after_the_rotation(&lab, directory.path());
    milter::macro_filter(&mut lab, directory.path(), &credential, &gateway);
    refused_without_the_gateway(&mut lab, directory.path(), &credential);
}

/// What setup says, and nothing else on standard output, where it finds
/// everything as asked.
const UNCHANGED: &str = "Stalwart is set up as asked; nothing was changed.";

/// The run after a first setup, with the same arguments, through a relay
/// that keeps every request: it finds everything as asked, so it writes no
/// object in Stalwart, restarts no service and says so. It asks Stalwart to
/// reload its settings, as every run does, since no read shows whether
/// Stalwart uses what it holds.
fn unchanged(lab: &Lab, directory: &std::path::Path, credential: &str, gateway: &str) {
    let relay = stopper::Stopper::new(&lab.url, usize::MAX, stopper::Stop::Lost);
    let settings = directory.join("garrison.toml");
    std::fs::write(&settings, config_text(directory, &relay.url)).unwrap();
    let again = run(
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
        ],
    );
    std::fs::write(&settings, config_text(directory, &lab.url)).unwrap();
    let (said, asked) = (text(&again), relay.asked());
    assert_eq!(again.status.code(), Some(0), "{said}");
    let written: Vec<&String> = asked
        .iter()
        .filter(|asked| asked.contains("/set") && *asked != "x:Action/set create")
        .collect();
    assert_eq!(written, Vec::<&String>::new(), "{said}");
    assert!(
        !said.contains("Restart ") && !said.contains(" restarted"),
        "{said}"
    );
    let stdout = String::from_utf8_lossy(&again.stdout);
    assert_eq!(stdout.lines().last(), Some(UNCHANGED), "{said}");
}

/// `access init` signs in with the new broker key and finds the
/// administrators, `bind-role` binds a role, and the policy is valid.
fn access_after_the_rotation(lab: &Lab, directory: &std::path::Path) {
    let init = run(directory, &["access", "init"]);
    assert_eq!(init.status.code(), Some(0), "{}", text(&init));
    assert!(
        states(&init).contains(&"access-bound".to_owned()),
        "{}",
        text(&init)
    );
    access::bind_role(lab, directory);
    let check = run(directory, &["check-config"]);
    assert!(
        states(&check).contains(&"check-config-policy-valid".to_owned()),
        "{}",
        text(&check)
    );
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
            // Stalwart numbers each kind of object on its own: an API key and
            // an OAuth client can have the same ID.
            let id = item["id"].as_str().unwrap().to_owned();
            let known = |(other, known): &(String, String)| other == kind && *known == id;
            if ours && !lab.created.iter().any(known) {
                lab.created.push((kind.into(), id));
            }
        }
    }
}
