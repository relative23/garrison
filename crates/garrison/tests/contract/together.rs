//! What it is for Stalwart and the credentials directory to agree after a
//! setup run: one key of each of Garrison's descriptions, which its file
//! holds; one webhook of Garrison's, which signs with its file's key; and an
//! exporter that takes its file's credential. Stalwart shows no secret, so
//! each is tried.

use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_testing::lab::{Lab, unique};
use garrison_testing::smtp::Smtp;
use serde_json::{Value, json};

use super::keys::key_status;
use super::wire::{answer, read_request};

/// A batch as Stalwart delivered it: its signature and its body.
type Delivery = (String, Vec<u8>);

/// Webhook deliveries at an address of this machine that the lab reaches.
pub(super) struct Capture {
    pub(super) url: String,
    seen: Arc<Mutex<Vec<Delivery>>>,
}

impl Capture {
    pub(super) fn start() -> Capture {
        let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").unwrap();
        let listener = TcpListener::bind((callback.as_str(), 0)).unwrap();
        let url = format!("http://{}/webhook", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&seen);
        thread::spawn(move || {
            for mut client in listener.incoming().flatten() {
                // A batch is a POST to the webhook's path.
                let request = read_request(&client);
                let request = request.filter(|it| it.method == "POST" && it.path == "/webhook");
                if let Some(request) = request {
                    let signature = request.header("X-Signature").unwrap_or_default();
                    let mut seen = kept.lock().unwrap();
                    seen.push((signature.to_owned(), request.body));
                    let excess = seen.len().saturating_sub(200);
                    seen.drain(..excess);
                }
                answer(&mut client, 200, "text/plain", b"");
            }
        });
        Capture { url, seen }
    }

    /// The signature and body of the first delivery that names `name`.
    fn naming(&self, name: &str) -> (String, Vec<u8>) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let seen = self.seen.lock().unwrap();
            let found = seen
                .iter()
                .find(|(_, body)| String::from_utf8_lossy(body).contains(name));
            if let Some((signature, body)) = found {
                return (signature.clone(), body.clone());
            }
            drop(seen);
            assert!(Instant::now() < deadline, "no delivery named {name}");
            thread::sleep(Duration::from_millis(100));
        }
    }
}

/// One key of each description, the one its file holds: the file's key
/// opens a session, and is refused once that one key no longer allows this
/// host.
pub(super) fn assert_keys_held(lab: &Lab, credentials: &Path, gateway: &str, context: &str) {
    assert_keys_held_in(lab, &[None], credentials, gateway, context);
}

/// `assert_keys_held` for the keys of all of `accounts` together, each the
/// lab's administrator's own where it is `None`: one key of each
/// description in all of them.
pub(super) fn assert_keys_held_in(
    lab: &Lab,
    accounts: &[Option<&str>],
    credentials: &Path,
    gateway: &str,
    context: &str,
) {
    // Without an accountId, Stalwart takes the administrator's own.
    let within = |account: Option<&str>, mut arguments: Value| {
        if let Some(account) = account {
            arguments["accountId"] = json!(account);
        }
        arguments
    };
    let listed: Vec<(Option<&str>, Value)> = accounts
        .iter()
        .flat_map(|account| {
            let listed = lab.call("x:ApiKey/get", &within(*account, json!({"ids": null})));
            let keys = listed["list"].as_array().unwrap().clone();
            keys.into_iter().map(move |key| (*account, key))
        })
        .collect();
    for (name, description) in [
        ("broker-native-key", "garrison broker"),
        ("collector-native-key", "garrison collector"),
    ] {
        let keys: Vec<&(Option<&str>, Value)> = listed
            .iter()
            .filter(|(_, key)| key["description"] == description)
            .collect();
        assert_eq!(keys.len(), 1, "{context}: keys '{description}': {keys:?}");
        let (account, key) = keys[0];
        let id = key["id"].as_str().unwrap();
        let secret = fs::read_to_string(credentials.join(name)).unwrap();
        assert_eq!(key_status(&lab.url, &secret), 200, "{context}: {name}");
        let networks = |gateway: Option<&str>| {
            let mut networks = json!({"127.0.0.1/32": true, "::1/128": true});
            if let Some(gateway) = gateway {
                networks[gateway] = json!(true);
            }
            within(*account, json!({"update": {id: {"allowedIps": networks}}}))
        };
        lab.call("x:ApiKey/set", &networks(None));
        let narrowed = key_status(&lab.url, &secret);
        lab.call("x:ApiKey/set", &networks(Some(gateway)));
        assert_eq!(
            narrowed, 403,
            "{context}: {name} holds another key than '{description}'"
        );
    }
}

/// One webhook of Garrison's, which signs a batch with its file's key.
pub(super) fn assert_webhook_held(lab: &Lab, credentials: &Path, capture: &Capture, context: &str) {
    let hooks = lab.call("x:WebHook/get", &json!({"ids": null}));
    let ours = hooks["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|hook| hook["httpHeaders"]["X-Garrison"] == "events")
        .count();
    assert_eq!(ours, 1, "{context}: Garrison's webhooks");
    let name = format!("{}.stop.example.net", unique());
    let mut session = Smtp::connect(&std::env::var("GARRISON_LAB_SMTP").unwrap());
    session.command(&format!("EHLO {name}"));
    session.command("QUIT");
    let (signature, body) = capture.naming(&name);
    let key = fs::read_to_string(credentials.join("webhook-signature-key")).unwrap();
    assert_eq!(
        signature,
        garrison_ingest::app::signature(key.trim().as_bytes(), &body),
        "{context}: the webhook signs with another key than its file's"
    );
}

/// Stalwart's exporter takes the credential of its file.
pub(super) fn assert_exporter_held(lab: &Lab, credentials: &Path, context: &str) {
    let file = fs::read(credentials.join("metrics-credential")).unwrap();
    let credential: Value = serde_json::from_slice(&file).unwrap();
    let user = format!(
        "{}:{}",
        credential["username"].as_str().unwrap(),
        credential["secret"].as_str().unwrap()
    );
    let answer = ureq::get(format!("{}/metrics/prometheus", lab.url))
        .header("Authorization", &format!("Basic {}", STANDARD.encode(user)))
        .config()
        .http_status_as_error(false)
        .build()
        .call()
        .unwrap();
    assert_eq!(
        answer.status(),
        200,
        "{context}: the exporter refuses its file's credential"
    );
}

/// Where the configuration has the macro filter at `port`, one of
/// Stalwart's entries asks it there, and setup's note names that entry;
/// where it has none, no entry asks there and no note is left.
pub(super) fn assert_milter_held(
    lab: &Lab,
    credentials: &Path,
    port: u16,
    configured: bool,
    context: &str,
) {
    let entries = lab.call("x:MtaMilter/get", &json!({"ids": null}));
    let asking: Vec<String> = entries["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["host"] == "127.0.0.1" && entry["port"] == port)
        .map(|entry| entry["id"].as_str().unwrap().to_owned())
        .collect();
    let note = fs::read_to_string(credentials.join("stalwart-milter-id"))
        .ok()
        .map(|id| id.trim().to_owned());
    if configured {
        assert_eq!(asking.len(), 1, "{context}: entries for the filter");
        assert_eq!(note.as_ref(), asking.first(), "{context}: setup's note");
    } else {
        assert_eq!(
            asking,
            Vec::<String>::new(),
            "{context}: entries for the filter"
        );
        assert_eq!(note, None, "{context}: setup's note");
    }
}

/// All three.
pub(super) fn assert_together(
    lab: &Lab,
    credentials: &Path,
    gateway: &str,
    capture: &Capture,
    context: &str,
) {
    assert_keys_held(lab, credentials, gateway, context);
    assert_webhook_held(lab, credentials, capture, context);
    assert_exporter_held(lab, credentials, context);
}
