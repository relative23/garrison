//! The notification channels, where the configuration names any: each can
//! send as its files stand now, and none is protected by nothing but an
//! address in `garrison.toml`, which every user of this host may read.

use garrison_collector::notify::{Channels, Secret, Secrets};
use garrison_core::config::{Config, Endpoint};
use garrison_core::credentials::Credentials;

use super::Finding;
use super::states::notify::{self as states, Open};

pub(super) fn checks(config: &Config, credentials: &Credentials) -> Vec<Finding> {
    let notifications = &config.notifications;
    if !notifications.any() {
        return Vec::new();
    }
    let channels =
        Channels::of(config, Secrets::read(credentials, notifications)).located(credentials);
    let mut findings: Vec<Finding> = channels
        .unusable()
        .into_iter()
        .map(|why| Finding::fail(states::unusable(&why)))
        .collect();
    // An address that is written here and goes with no token is all that
    // protects the channel.
    let open = [
        (
            &notifications.ntfy_url,
            channels.ntfy.as_ref().map(|ntfy| &ntfy.token),
            Open::Ntfy,
        ),
        (
            &notifications.webhook_url,
            channels.webhook.as_ref().map(|hook| &hook.token),
            Open::Webhook,
        ),
    ];
    for (endpoint, token, channel) in open {
        if let (Some(Endpoint::Written(_)), Some(Secret::Empty)) = (endpoint, token) {
            findings.push(Finding::warn(states::open(
                channel,
                credentials.directory(),
            )));
        }
    }
    if findings.is_empty() {
        findings.push(Finding::ok(states::channels(&channels.names())));
    }
    findings
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use garrison_core::credentials::SecretSource;

    use super::super::Level;
    use super::*;

    const TOPIC: &str = "https://ntfy.example.org/a-topic-nobody-guesses";

    /// A configuration in a folder of its own, with the empty files the
    /// installer keeps.
    fn host() -> (tempfile::TempDir, Config, Credentials) {
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let credentials = Credentials::new(&config.credentials_directory);
        fs::create_dir_all(credentials.directory()).unwrap();
        for name in crate::units::NOTIFICATION_FILES {
            write(&credentials, name, "");
        }
        (directory, config, credentials)
    }

    fn write(credentials: &Credentials, name: &str, data: &str) {
        let path = credentials.directory().join(name);
        fs::write(&path, data).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn levels(findings: &[Finding]) -> Vec<(Level, &str)> {
        findings
            .iter()
            .map(|finding| (finding.level, finding.state.text.as_str()))
            .collect()
    }

    #[test]
    fn no_channel_needs_no_check() {
        let (_directory, config, credentials) = host();
        assert_eq!(levels(&checks(&config, &credentials)), []);
    }

    #[test]
    fn an_open_topic_written_into_the_configuration_is_a_warning() {
        let (_directory, mut config, credentials) = host();
        config.notifications.ntfy_url = Some(Endpoint::Written(TOPIC.to_owned()));
        let found = checks(&config, &credentials);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].level, Level::Warn);
        assert!(
            found[0]
                .state
                .text
                .starts_with("the ntfy topic takes no token, and garrison.toml"),
            "{}",
            found[0].state.text
        );
        let fix = found[0].state.fix.as_deref().unwrap();
        assert!(fix.contains("ntfy-url (root, mode 0600)"), "{fix}");
        assert!(fix.contains("ntfy_url = \"credential:ntfy-url\""), "{fix}");
        assert!(!found[0].line().contains("nobody-guesses"));
        // With a token, the address alone opens nothing.
        write(
            &credentials,
            "ntfy-token",
            "tk_abcdefghijklmnopqrstuvwxyz123",
        );
        assert_eq!(
            levels(&checks(&config, &credentials)),
            [(Level::Ok, "notifications: ntfy at ntfy.example.org")]
        );
    }

    #[test]
    fn a_webhook_written_without_a_token_is_a_warning_and_one_kept_in_a_file_is_not() {
        let (_directory, mut config, credentials) = host();
        config.notifications.webhook_url = Some(Endpoint::Written(
            "https://hooks.example.org/T/B/key".to_owned(),
        ));
        let found = checks(&config, &credentials);
        assert_eq!(found[0].level, Level::Warn);
        assert!(
            found[0].state.text.contains("post to it where its key"),
            "{}",
            found[0].state.text
        );
        config.notifications.webhook_url = Some(Endpoint::File(SecretSource::Credential(
            "notify-webhook-url".into(),
        )));
        write(
            &credentials,
            "notify-webhook-url",
            "https://hooks.example.org/T/B/key\n",
        );
        assert_eq!(
            levels(&checks(&config, &credentials)),
            [(Level::Ok, "notifications: webhook at hooks.example.org")]
        );
    }

    #[test]
    fn a_channel_that_cannot_send_fails_with_the_reason() {
        let (_directory, mut config, credentials) = host();
        config.notifications.ntfy_url =
            Some(Endpoint::File(SecretSource::Credential("ntfy-url".into())));
        let found = checks(&config, &credentials);
        assert_eq!(found.len(), 1, "{:?}", levels(&found));
        assert_eq!(found[0].level, Level::Fail);
        assert!(
            found[0]
                .state
                .text
                .starts_with("notifications: ntfy: notifications.ntfy_url cannot be used: "),
            "{}",
            found[0].state.text
        );
        assert!(
            found[0]
                .state
                .text
                .ends_with("ntfy-url is empty; write the address into it")
        );
        write(&credentials, "ntfy-url", TOPIC);
        assert_eq!(
            levels(&checks(&config, &credentials)),
            [(Level::Ok, "notifications: ntfy at ntfy.example.org")]
        );
    }
}
