//! The secrets of the configuration as the units hand them to the
//! services. systemd copies each credential a unit loads (`LoadCredential=`)
//! into the service's credentials directory under the name the unit gives
//! it, and no other: a `credential:` of another name is never there, while
//! the operator commands, which read the configured directory as root,
//! would find it. So check-config refuses it, and doctor and notify-test
//! judge no channel by it.

use garrison_core::config::{Config, Endpoint};
use garrison_core::credentials::SecretSource;

use crate::units;

/// A secret setting that its units do not hand to their services.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Unloaded {
    pub(crate) setting: &'static str,
    /// The setting, and why its service would not have it.
    pub(crate) what: String,
    /// What to do.
    pub(crate) fix: String,
}

impl Unloaded {
    pub(crate) fn line(&self) -> String {
        format!("{}. {}", self.what, self.fix)
    }
}

/// What `setting` names, where it names a secret.
fn source<'a>(config: &'a Config, setting: &str) -> Option<&'a SecretSource> {
    let kept = |endpoint: &'a Option<Endpoint>| match endpoint {
        Some(Endpoint::File(source)) => Some(source),
        _ => None,
    };
    let notifications = &config.notifications;
    match setting {
        "ingest.signature_key" => Some(&config.ingest.signature_key),
        "collector.native_key" => Some(&config.collector.native_key),
        "collector.metrics_credential" => config.collector.metrics_credential.as_ref(),
        "broker.native_key" => Some(&config.broker.native_key),
        "notifications.token" => Some(&notifications.token),
        "notifications.webhook_token" => Some(&notifications.webhook_token),
        "notifications.mail_password" => Some(&notifications.mail_password),
        "notifications.ntfy_url" => kept(&notifications.ntfy_url),
        "notifications.webhook_url" => kept(&notifications.webhook_url),
        _ => None,
    }
}

/// The secret settings of `config` that their units would not hand to their
/// services, each with what to do.
pub(crate) fn unloaded(config: &Config) -> Vec<Unloaded> {
    let mut found = Vec::new();
    for (setting, readers, name) in units::SECRETS {
        let Some(SecretSource::Credential(given)) = source(config, setting) else {
            continue;
        };
        if given == name {
            continue;
        }
        let (readers, load) = match readers {
            [one] => ((*one).to_owned(), "loads"),
            more => (more.join(" and "), "load"),
        };
        found.push(Unloaded {
            setting,
            what: format!(
                "{setting} is credential:{given}, but {readers} {load} this secret only as \
                 credential:{name}"
            ),
            fix: format!(
                "Write {setting} = \"credential:{name}\" and keep the secret in {}/{name}.",
                units::CREDENTIALS
            ),
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use garrison_core::config::from_text;

    use super::*;

    const EXAMPLE: &str = include_str!("../../../deploy/config/garrison.example.toml");

    #[test]
    fn the_example_names_every_secret_as_its_units_load_it() {
        let example = from_text(EXAMPLE).unwrap();
        assert_eq!(unloaded(&example), []);
        // Every setting of the list names a secret of the configuration.
        let mut config = example;
        config.notifications.ntfy_url =
            Some(Endpoint::File(SecretSource::Credential("ntfy-url".into())));
        config.notifications.webhook_url = Some(Endpoint::File(SecretSource::Credential(
            "notify-webhook-url".into(),
        )));
        for (setting, _, _) in units::SECRETS {
            assert!(source(&config, setting).is_some(), "{setting}");
        }
    }

    #[test]
    fn another_name_is_refused_with_the_one_its_units_load() {
        let mut config = from_text(EXAMPLE).unwrap();
        config.ingest.signature_key = SecretSource::Credential("hmac".into());
        config.notifications.ntfy_url =
            Some(Endpoint::File(SecretSource::Credential("topic".into())));
        let found = unloaded(&config);
        assert_eq!(
            found.iter().map(Unloaded::line).collect::<Vec<_>>(),
            [
                "ingest.signature_key is credential:hmac, but garrison-ingest.service loads \
                 this secret only as credential:webhook-signature-key. Write \
                 ingest.signature_key = \"credential:webhook-signature-key\" and keep the secret \
                 in /etc/garrison/credentials/webhook-signature-key.",
                "notifications.ntfy_url is credential:topic, but garrison-collect.service and \
                 garrison-watch.service load this secret only as credential:ntfy-url. Write \
                 notifications.ntfy_url = \"credential:ntfy-url\" and keep the secret in \
                 /etc/garrison/credentials/ntfy-url.",
            ]
        );
        assert_eq!(
            found
                .iter()
                .map(|secret| secret.setting)
                .collect::<Vec<_>>(),
            ["ingest.signature_key", "notifications.ntfy_url"]
        );
    }
}
