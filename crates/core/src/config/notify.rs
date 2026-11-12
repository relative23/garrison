//! The `[notifications]` section: where the collector reports what its checks
//! find. Any of an ntfy topic, a webhook and a mailbox; all that are named
//! get every message.

use toml::Value;

use super::values::{Section, https_url, integer, secret_source};
use super::{ConfigError, MacroAction, MailSettings, MilterConfig, Notifications};

fn fail<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(message.into()))
}

/// A mail address as a notification uses it: one `@`, a name on each side
/// and nothing that could end a line or a command.
fn address(value: Option<&Value>, name: &str) -> Result<String, ConfigError> {
    let text = value.and_then(Value::as_str).unwrap_or_default();
    let plain = |part: &str| {
        !part.is_empty()
            && part.chars().all(|character| {
                character.is_ascii_graphic() && !"<>()[]\\,;:\"@".contains(character)
            })
    };
    match text.split_once('@') {
        Some((local, domain)) if text.len() <= 254 && plain(local) && plain(domain) => {
            Ok(text.to_owned())
        }
        _ => fail(format!("{name} must be a mail address")),
    }
}

/// A host name, as a certificate names the mail server.
fn host(value: Option<&Value>, name: &str) -> Result<String, ConfigError> {
    let text = value.and_then(Value::as_str).unwrap_or_default();
    let label = |label: &str| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
    };
    if text.len() <= 253 && text.split('.').all(label) {
        Ok(text.to_ascii_lowercase())
    } else {
        fail(format!("{name} must be the mail server's host name"))
    }
}

pub(super) fn notifications(value: Option<&Value>) -> Result<Notifications, ConfigError> {
    const KEYS: [&str; 10] = [
        "ntfy_url",
        "token",
        "webhook_url",
        "webhook_token",
        "mail_to",
        "mail_from",
        "mail_user",
        "mail_host",
        "mail_port",
        "mail_password",
    ];
    let table = Section::take(value, "notifications", &KEYS)?;
    // An ntfy topic is `https://host/topic`: the last part of the path names it.
    let ntfy_url = match table.get("ntfy_url") {
        None => None,
        Some(url) => {
            let url = https_url(Some(url), "notifications.ntfy_url")?;
            let topic = url.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            let named = !topic.is_empty()
                && !topic.contains(['.', ':', '?', '#'])
                && url.matches('/').count() >= 3;
            if !named {
                return fail("notifications.ntfy_url must name a topic: https://host/topic");
            }
            Some(url.trim_end_matches('/').to_owned())
        }
    };
    let webhook_url = match table.get("webhook_url") {
        None => None,
        Some(url) => Some(https_url(Some(url), "notifications.webhook_url")?),
    };
    // Mail is submitted signed in, so all of where, as whom and to whom is needed.
    let named = ["mail_to", "mail_from", "mail_host"].map(|key| table.get(key).is_some());
    let mail = if named.contains(&true) {
        if named.contains(&false) {
            return fail("notifications by mail need mail_to, mail_from and mail_host");
        }
        let from = address(table.get("mail_from"), "notifications.mail_from")?;
        Some(MailSettings {
            host: host(table.get("mail_host"), "notifications.mail_host")?,
            port: integer(
                table.get("mail_port"),
                Some(465),
                "notifications.mail_port",
                1,
                65535,
            )?,
            user: match table.get("mail_user") {
                None => from.clone(),
                Some(Value::String(user))
                    if (1..=254).contains(&user.len())
                        && user.chars().all(|character| character.is_ascii_graphic()) =>
                {
                    user.clone()
                }
                Some(_) => {
                    return fail("notifications.mail_user must be the account's sign-in name");
                }
            },
            from,
            to: address(table.get("mail_to"), "notifications.mail_to")?,
        })
    } else if ["mail_user", "mail_port"]
        .iter()
        .any(|key| table.get(key).is_some())
    {
        return fail("notifications by mail need mail_to, mail_from and mail_host");
    } else {
        None
    };
    Ok(Notifications {
        ntfy_url,
        token: secret_source(
            table.get("token"),
            "credential:ntfy-token",
            "notifications.token",
        )?,
        webhook_url,
        webhook_token: secret_source(
            table.get("webhook_token"),
            "credential:notify-webhook-token",
            "notifications.webhook_token",
        )?,
        mail,
        mail_password: secret_source(
            table.get("mail_password"),
            "credential:notify-mail-password",
            "notifications.mail_password",
        )?,
    })
}

/// The `[milter]` section. Its presence switches the macro milter on; every
/// setting in it has a default.
pub(super) fn milter(value: Option<&Value>) -> Result<Option<MilterConfig>, ConfigError> {
    if value.is_none() {
        return Ok(None);
    }
    let table = Section::take(
        value,
        "milter",
        &["port", "on_macro", "max_message_mib", "when_unreachable"],
    )?;
    let defer_when_unreachable = match table.get("when_unreachable").map(Value::as_str) {
        None | Some(Some("defer")) => true,
        Some(Some("accept")) => false,
        Some(_) => return fail("milter.when_unreachable is \"defer\" or \"accept\""),
    };
    let action = match table.get("on_macro").map(Value::as_str) {
        None | Some(Some("reject")) => MacroAction::Reject,
        Some(Some("tag")) => MacroAction::Tag,
        Some(_) => return fail("milter.on_macro is \"reject\" or \"tag\""),
    };
    let megabytes: u64 = integer(
        table.get("max_message_mib"),
        Some(64),
        "milter.max_message_mib",
        1,
        256,
    )?;
    Ok(Some(MilterConfig {
        port: integer(table.get("port"), Some(8096), "milter.port", 1024, 65535)?,
        action,
        max_message_bytes: megabytes * 1024 * 1024,
        defer_when_unreachable,
    }))
}
