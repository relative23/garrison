//! The `[notifications]` section: where the collector reports what its checks
//! find. Any of an ntfy topic, a webhook and a mailbox; all that are named
//! get every message.

use toml::Value;

use super::values::{Section, https_url, integer, secret_source};
use super::{
    ConfigError, Endpoint, IncompleteAction, MacroAction, MailSettings, MilterConfig, Notifications,
};

fn fail<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(message.into()))
}

/// An address as the collector's client sends it, as written: it takes all
/// up to the first `/` for the server, so a query right after the host is
/// no name it can ask, and would show in an error that names the server.
/// The error never repeats the address.
fn sendable(text: &str, name: &str) -> Result<(), ConfigError> {
    let Some(rest) = text.strip_prefix("https://") else {
        return fail(format!("{name} must be an https:// URL"));
    };
    if text
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return fail(format!(
            "{name} must be one line of printable characters without spaces"
        ));
    }
    let server = rest.split('/').next().unwrap_or_default();
    if server.contains(['?', '#', '\\']) {
        return fail(format!(
            "{name} must name its server alone before its first \"/\": write \
             https://host/?key=…, not https://host?key=…"
        ));
    }
    let host =
        |character: &char| character.is_ascii_alphanumeric() || "-._:[]".contains(*character);
    // One character, never more of the address, which may be a secret.
    if let Some(held) = server.chars().find(|character| !host(character)) {
        return fail(format!(
            "{name} must name its server in ASCII letters, digits, \"-\" and \".\", not with \
             \"{held}\": write a name in another script in its xn-- form"
        ));
    }
    Ok(())
}

/// An ntfy topic's address, `https://host/topic`: the last part of the path
/// names the topic. `name` is what an error calls the value. The collector
/// holds an address read from a file to the same rules.
pub fn ntfy_address(text: &str, name: &str) -> Result<String, ConfigError> {
    let url = https_url(Some(&Value::String(text.to_owned())), name)?;
    sendable(&url, name)?;
    let topic = url.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    let named =
        !topic.is_empty() && !topic.contains(['.', ':', '?', '#']) && url.matches('/').count() >= 3;
    if !named {
        return fail(format!("{name} must name a topic: https://host/topic"));
    }
    Ok(url.trim_end_matches('/').to_owned())
}

/// A webhook's address, which every message is posted to.
pub fn webhook_address(text: &str, name: &str) -> Result<String, ConfigError> {
    let url = https_url(Some(&Value::String(text.to_owned())), name)?;
    sendable(&url, name)?;
    Ok(url)
}

/// A channel's address as written, or the file that holds it: `credential:NAME`
/// or an absolute path, read as the channels' secrets are.
fn endpoint(
    value: Option<&Value>,
    name: &str,
    address: fn(&str, &str) -> Result<String, ConfigError>,
) -> Result<Option<Endpoint>, ConfigError> {
    match value.map(Value::as_str) {
        None => Ok(None),
        Some(Some(text)) if text.starts_with('/') || text.starts_with("credential:") => {
            Ok(Some(Endpoint::File(secret_source(value, "", name)?)))
        }
        Some(Some(text)) => Ok(Some(Endpoint::Written(address(text, name)?))),
        Some(None) => fail(format!("{name} must be an https:// URL")),
    }
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
    let ntfy_url = endpoint(
        table.get("ntfy_url"),
        "notifications.ntfy_url",
        ntfy_address,
    )?;
    let webhook_url = endpoint(
        table.get("webhook_url"),
        "notifications.webhook_url",
        webhook_address,
    )?;
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
        &[
            "port",
            "on_macro",
            "on_incomplete",
            "max_message_mib",
            "when_unreachable",
        ],
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
    let on_incomplete = match table.get("on_incomplete").map(Value::as_str) {
        None | Some(Some("tag")) => IncompleteAction::Tag,
        Some(Some("defer")) => IncompleteAction::Defer,
        Some(Some("refuse")) => IncompleteAction::Refuse,
        Some(_) => return fail("milter.on_incomplete is \"tag\", \"defer\" or \"refuse\""),
    };
    let megabytes: u64 = integer(
        table.get("max_message_mib"),
        Some(64),
        "milter.max_message_mib",
        1,
        MilterConfig::MOST_MESSAGE_MIB,
    )?;
    Ok(Some(MilterConfig {
        port: integer(table.get("port"), Some(8096), "milter.port", 1024, 65535)?,
        action,
        on_incomplete,
        max_message_bytes: megabytes * 1024 * 1024,
        defer_when_unreachable,
    }))
}
