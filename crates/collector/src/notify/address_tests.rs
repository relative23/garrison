//! Addresses that are secrets themselves, kept in files of their own: read
//! from the file the setting names, held to the rules of a written address,
//! and never shown in an error, a debug line or the stored form.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use garrison_core::config::{Config, Endpoint};
use garrison_core::credentials::{Credentials, SecretSource};
use garrison_testing::http::serve;

use super::*;
use crate::testing::{Remembered, now};

const TOPIC: &str = "https://ntfy.example.org/a-topic-nobody-guesses";

/// A file in the credentials directory, holding `data`.
fn write(credentials: &Credentials, name: &str, data: &str, mode: u32) {
    let path = credentials.directory().join(name);
    let _ = fs::remove_file(&path);
    fs::write(&path, data).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A configuration whose ntfy topic is kept in `credential:ntfy-url`, with
/// an empty token file beside it, as the installer keeps one.
fn kept(directory: &Path) -> (Config, Credentials) {
    let mut config = crate::testing::config(directory);
    config.notifications.ntfy_url =
        Some(Endpoint::File(SecretSource::Credential("ntfy-url".into())));
    let credentials = Credentials::new(&config.credentials_directory);
    fs::create_dir_all(credentials.directory()).unwrap();
    write(&credentials, "ntfy-token", "", 0o600);
    (config, credentials)
}

fn read_channels(config: &Config, credentials: &Credentials) -> Channels {
    Channels::of(config, Secrets::read(credentials, &config.notifications)).located(credentials)
}

#[test]
fn an_address_kept_in_a_file_is_read_from_it_and_never_shown() {
    let directory = tempfile::tempdir().unwrap();
    let (config, credentials) = kept(directory.path());
    write(&credentials, "ntfy-url", &format!("{TOPIC}/\n"), 0o600);
    let channels = read_channels(&config, &credentials);
    assert_eq!(channels.ntfy.as_ref().unwrap().usable(), Ok(TOPIC));
    assert_eq!(channels.unusable(), Vec::<String>::new());
    assert_eq!(channels.names(), ["ntfy at ntfy.example.org"]);
    assert!(!format!("{channels:?}").contains("nobody-guesses"));
    // The status database, which the group garrison may read, gets the
    // file's name in its place; read back, the address comes from the file.
    let stored = serde_json::to_string(&channels).unwrap();
    assert!(!stored.contains("nobody-guesses"), "{stored}");
    assert!(
        stored.contains(r#""ntfy":{"url":"","file":"credential:ntfy-url"}"#),
        "{stored}"
    );
    let back: Channels = serde_json::from_str(&stored).unwrap();
    let unread = back.ntfy.clone().unwrap().usable().unwrap_err();
    assert_eq!(unread, "the address in credential:ntfy-url was not read");
    let back = back.located(&credentials);
    assert_eq!(back.ntfy.unwrap().usable(), Ok(TOPIC));
    // A written address is stored as it is written, as before.
    let mut written = config.clone();
    written.notifications.ntfy_url = Some(Endpoint::Written(TOPIC.to_owned()));
    let stored = serde_json::to_string(&read_channels(&written, &credentials)).unwrap();
    assert!(
        stored.contains(&format!(r#""ntfy":{{"url":"{TOPIC}"}}"#)),
        "{stored}"
    );
}

#[test]
fn a_file_without_a_usable_address_is_the_channels_error() {
    let quiet = serve(Vec::new());
    let directory = tempfile::tempdir().unwrap();
    let (config, credentials) = kept(directory.path());
    for (data, mode, why) in [
        ("", 0o600, "ntfy-url is empty; write the address into it"),
        (TOPIC, 0o644, "not private"),
        (
            "http://ntfy.example.org/plain-topic",
            0o600,
            "ntfy-url must be an https:// URL",
        ),
        (
            "https://ntfy.example.org",
            0o600,
            "ntfy-url must name a topic: https://host/topic",
        ),
        (
            "https://ntfy.example.org/two words",
            0o600,
            "printable characters without spaces",
        ),
    ] {
        write(&credentials, "ntfy-url", data, mode);
        let channels = read_channels(&config, &credentials);
        let unusable = channels.unusable();
        assert_eq!(unusable.len(), 1, "{unusable:?}");
        assert!(
            unusable[0].starts_with("ntfy: notifications.ntfy_url cannot be used: "),
            "{unusable:?}"
        );
        assert!(unusable[0].contains(why), "{unusable:?}");
        assert_eq!(channels.names(), ["ntfy, whose address cannot be read"]);
        let outcome = test(&channels, now());
        let error = outcome[0].1.as_ref().unwrap_err();
        assert_eq!(&format!("ntfy: {error}"), &unusable[0]);
        if !data.is_empty() {
            assert!(!error.contains(data), "{error}");
        }
        // The Alerts page says so in every run, a message due or not.
        let observed = after_run_with(
            &channels,
            &[],
            &Remembered::default(),
            now(),
            &Arc::new(RootCertStore::empty()),
            Deadline::NONE,
        )
        .unwrap();
        assert_eq!(observed.state, State::Failed);
        assert_eq!(observed.findings, [format!("{}.", unusable[0])]);
    }
    fs::remove_file(credentials.directory().join("ntfy-url")).unwrap();
    let missing = read_channels(&config, &credentials).unusable();
    assert!(missing[0].contains("unavailable"), "{missing:?}");
    // Nothing went out without its address.
    assert_eq!(quiet.requests().len(), 0);
}

#[test]
fn an_error_names_the_server_and_never_the_whole_address() {
    // A webhook whose key is part of its address, as Slack's and Discord's are.
    let server = serve(vec!["not an HTTP answer".to_owned()]);
    let directory = tempfile::tempdir().unwrap();
    let (mut config, credentials) = kept(directory.path());
    config.notifications.ntfy_url = None;
    config.notifications.webhook_url = Some(Endpoint::Written(format!(
        "{}/services/T0/B0/key-in-the-path",
        server.url
    )));
    write(&credentials, "notify-webhook-token", "", 0o600);
    let outcome = test(&read_channels(&config, &credentials), now());
    let error = outcome[0].1.as_ref().unwrap_err();
    assert!(!error.contains("key-in-the-path"), "{error}");
    assert_eq!(
        error,
        &format!(
            "the address at {} gave no HTTP answer",
            server.url.trim_start_matches("http://")
        )
    );
    server.requests();
}
