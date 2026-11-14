//! The channels' secrets as their files hold them: an empty file means none,
//! and a file that cannot be used is that channel's error, named where an
//! operator looks for a channel that does not work.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_core::config::{Config, Endpoint, MailSettings};
use garrison_core::credentials::Credentials;
use garrison_testing::http::{answer, serve};

use super::*;
use crate::testing::{Remembered, certificates, now};

const TOKEN: &str = "tk_abcdefghijklmnopqrstuvwxyz123";

/// A configuration in `directory` that names an ntfy topic at `url`.
fn with_topic(directory: &Path, url: &str) -> (Config, Credentials) {
    let mut config = crate::testing::config(directory);
    config.notifications.ntfy_url = Some(Endpoint::Written(url.to_owned()));
    let credentials = Credentials::new(&config.credentials_directory);
    fs::create_dir_all(credentials.directory()).unwrap();
    (config, credentials)
}

/// The file `name` in the credentials directory, holding `data`.
fn secret(credentials: &Credentials, name: &str, data: &str, mode: u32) {
    let path = credentials.directory().join(name);
    let _ = fs::remove_file(&path);
    fs::write(&path, data).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

fn channels(config: &Config, credentials: &Credentials) -> Channels {
    Channels::of(config, Secrets::read(credentials, &config.notifications)).located(credentials)
}

#[test]
fn an_empty_token_file_sends_none_and_a_token_goes_as_written() {
    let server = serve(vec![answer(200, "{}"), answer(200, "{}")]);
    let directory = tempfile::tempdir().unwrap();
    let (config, credentials) = with_topic(directory.path(), &format!("{}/topic", server.url));
    // Empty, as the installer keeps it: the topic needs no token.
    secret(&credentials, "ntfy-token", "", 0o600);
    assert_eq!(
        test(&channels(&config, &credentials), now()),
        [("ntfy", Ok(()))]
    );
    // With the line end that `cat >` leaves.
    secret(&credentials, "ntfy-token", &format!("{TOKEN}\n"), 0o600);
    assert_eq!(
        test(&channels(&config, &credentials), now()),
        [("ntfy", Ok(()))]
    );
    let requests = server.requests();
    assert!(!requests[0].contains("Authorization"), "{}", requests[0]);
    assert!(
        requests[1].contains(&format!("Authorization: Bearer {TOKEN}\r\n")),
        "{}",
        requests[1]
    );
}

#[test]
fn a_token_file_that_cannot_be_used_is_the_channels_error_not_no_token() {
    let quiet = serve(Vec::new());
    let directory = tempfile::tempdir().unwrap();
    let (config, credentials) = with_topic(directory.path(), &format!("{}/topic", quiet.url));
    for (data, mode, why) in [
        (TOKEN, 0o644, "not private"),
        (
            "tk_short",
            0o600,
            "16 to 8192 printable characters without spaces",
        ),
        ("tk_abcdefghijklm nopqrstuvwxyz", 0o600, "without spaces"),
    ] {
        secret(&credentials, "ntfy-token", data, mode);
        let outcome = test(&channels(&config, &credentials), now());
        let error = outcome[0].1.as_ref().unwrap_err();
        assert!(
            error.starts_with("notifications.token cannot be used: "),
            "{error}"
        );
        assert!(error.contains(why), "{error}");
        assert!(error.contains("ntfy-token"), "{error}");
        // The secret itself never shows.
        assert!(!error.contains(data), "{error}");
    }
    // A missing file is no token either: the unit would not even start.
    fs::remove_file(credentials.directory().join("ntfy-token")).unwrap();
    let outcome = test(&channels(&config, &credentials), now());
    let error = outcome[0].1.as_ref().unwrap_err();
    assert!(error.contains("unavailable"), "{error}");
    // Nothing went out without its token.
    assert_eq!(quiet.requests().len(), 0);
}

#[test]
fn the_channels_check_names_a_secret_that_cannot_be_used_at_once() {
    let directory = tempfile::tempdir().unwrap();
    let (config, credentials) = with_topic(directory.path(), "https://ntfy.example.org/topic");
    secret(&credentials, "ntfy-token", TOKEN, 0o644);
    let memory = Remembered::default();
    let roots = Arc::new(RootCertStore::empty());
    // Nothing to tell in this run, and nothing was sent before.
    let observed = after_run_with(
        &channels(&config, &credentials),
        &[],
        &memory,
        now(),
        &roots,
        Deadline::NONE,
    )
    .unwrap();
    assert_eq!(observed.state, State::Failed);
    assert_eq!(observed.findings.len(), 1, "{:?}", observed.findings);
    assert!(
        observed.findings[0].starts_with("ntfy: notifications.token cannot be used: "),
        "{:?}",
        observed.findings
    );
    assert!(!observed.findings[0].contains(TOKEN));
}

/// A configuration that sends mail to a stand-in on `port` as well.
fn with_mail(directory: &Path, port: u16) -> (Config, Credentials) {
    let (mut config, credentials) = with_topic(directory, "https://ntfy.example.org/topic");
    config.notifications.ntfy_url = None;
    config.notifications.mail = Some(MailSettings {
        host: "localhost".to_owned(),
        port,
        user: "garrison@example.test".to_owned(),
        from: "garrison@example.test".to_owned(),
        to: "anna@example.test".to_owned(),
    });
    (config, credentials)
}

fn mailed(
    channels: &Channels,
    roots: &Arc<RootCertStore>,
) -> Vec<(&'static str, Result<(), String>)> {
    let note = Note::plain(
        "Garrison: test".to_owned(),
        "A test.".to_owned(),
        Level::Good,
    );
    channels.send_with(&note, now(), roots, Deadline::NONE)
}

#[test]
fn a_mail_password_may_be_short_and_hold_spaces() {
    let certificates = certificates();
    let roots = mail::tests::trusted(&certificates);
    let (port, received) = mail::tests::server(&certificates, "235 OK\r\n", "250 OK\r\n");
    let directory = tempfile::tempdir().unwrap();
    let (config, credentials) = with_mail(directory.path(), port);
    secret(&credentials, "notify-mail-password", "pass word 1\n", 0o600);
    assert_eq!(
        mailed(&channels(&config, &credentials), &roots),
        [("mail", Ok(()))]
    );
    let login = STANDARD.encode("\0garrison@example.test\0pass word 1");
    let lines = received.recv().unwrap();
    assert!(lines.contains(&format!("AUTH PLAIN {login}")), "{lines:?}");
}

#[test]
fn mail_without_a_usable_password_is_not_tried() {
    // Nothing listens here: a channel that tried would say so instead.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let roots = Arc::new(RootCertStore::empty());
    let directory = tempfile::tempdir().unwrap();
    let (config, credentials) = with_mail(directory.path(), port);
    for (data, why) in [
        ("", "is empty"),
        ("pass\tword", "without control characters"),
    ] {
        secret(&credentials, "notify-mail-password", data, 0o600);
        let outcome = mailed(&channels(&config, &credentials), &roots);
        let error = outcome[0].1.as_ref().unwrap_err();
        assert!(error.starts_with("notifications.mail_password "), "{error}");
        assert!(error.contains(why), "{error}");
    }
}
