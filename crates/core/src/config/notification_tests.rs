use super::tests::{error, table};
use super::*;

#[test]
fn notifications_need_the_address_of_a_topic() {
    assert_eq!(parse(&table()).unwrap().notifications.ntfy_url, None);
    let with = |url: &str| {
        let mut raw = table();
        raw.insert(
            "notifications".into(),
            toml::Value::Table(toml::Table::from_iter([(
                "ntfy_url".to_owned(),
                toml::Value::String(url.to_owned()),
            )])),
        );
        parse(&raw)
    };
    let set = with("https://ntfy.example.org/mailserver/").unwrap();
    assert_eq!(
        set.notifications.ntfy_url.as_deref(),
        Some("https://ntfy.example.org/mailserver")
    );
    assert_eq!(
        set.notifications.token,
        SecretSource::Credential("ntfy-token".into())
    );
    for wrong in [
        "http://ntfy.example.org/topic",
        "https://ntfy.example.org",
        "https://ntfy.example.org/",
        "https://ntfy.example.org/topic?auth=x",
    ] {
        assert_eq!(
            with(wrong).unwrap_err().0,
            if wrong.starts_with("http://") {
                "notifications.ntfy_url must be an https:// URL"
            } else {
                "notifications.ntfy_url must name a topic: https://host/topic"
            },
            "{wrong}"
        );
    }
    let mut unknown = table();
    unknown.insert(
        "notifications".into(),
        toml::Value::Table(toml::Table::from_iter([(
            "email".to_owned(),
            toml::Value::String("a@example.org".to_owned()),
        )])),
    );
    assert!(error(&unknown).contains("email"), "{}", error(&unknown));
}

fn with(pairs: &[(&str, toml::Value)]) -> Result<Config, ConfigError> {
    let mut raw = table();
    let section = pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()));
    raw.insert(
        "notifications".into(),
        toml::Value::Table(section.collect()),
    );
    parse(&raw)
}

fn text(value: &str) -> toml::Value {
    toml::Value::String(value.to_owned())
}

#[test]
fn a_webhook_is_an_https_address_with_a_token_of_its_own() {
    let set = with(&[(
        "webhook_url",
        text("https://hooks.example.org/garrison?room=7"),
    )])
    .unwrap();
    assert_eq!(
        set.notifications.webhook_url.as_deref(),
        Some("https://hooks.example.org/garrison?room=7")
    );
    assert_eq!(
        set.notifications.webhook_token,
        SecretSource::Credential("notify-webhook-token".into())
    );
    assert!(set.notifications.any());
    assert!(!parse(&table()).unwrap().notifications.any());
    assert_eq!(
        with(&[("webhook_url", text("http://hooks.example.org/x"))])
            .unwrap_err()
            .0,
        "notifications.webhook_url must be an https:// URL"
    );
}

#[test]
fn mail_needs_the_server_the_sender_and_the_recipient() {
    let full = [
        ("mail_to", text("anna@example.org")),
        ("mail_from", text("garrison@example.org")),
        ("mail_host", text("Mail.Example.org")),
    ];
    let set = with(&full).unwrap().notifications;
    assert_eq!(
        set.mail,
        Some(MailSettings {
            host: "mail.example.org".into(),
            port: 465,
            user: "garrison@example.org".into(),
            from: "garrison@example.org".into(),
            to: "anna@example.org".into(),
        })
    );
    assert_eq!(
        set.mail_password,
        SecretSource::Credential("notify-mail-password".into())
    );
    let named = with(&[
        full[0].clone(),
        full[1].clone(),
        full[2].clone(),
        ("mail_user", text("garrison")),
        ("mail_port", toml::Value::Integer(8465)),
    ]);
    let named = named.unwrap().notifications.mail.unwrap();
    assert_eq!((named.user.as_str(), named.port), ("garrison", 8465));
    for missing in 0..3 {
        let mut part = full.to_vec();
        part.remove(missing);
        assert_eq!(
            with(&part).unwrap_err().0,
            "notifications by mail need mail_to, mail_from and mail_host"
        );
    }
    assert_eq!(
        with(&[("mail_port", toml::Value::Integer(465))])
            .unwrap_err()
            .0,
        "notifications by mail need mail_to, mail_from and mail_host"
    );
    for (key, wrong, said) in [
        (
            "mail_to",
            "anna",
            "notifications.mail_to must be a mail address",
        ),
        (
            "mail_to",
            "anna@example.org\r\nRCPT TO:<x@example.net>",
            "notifications.mail_to must be a mail address",
        ),
        (
            "mail_from",
            "<garrison@example.org>",
            "notifications.mail_from must be a mail address",
        ),
        (
            "mail_host",
            "127.0.0.1:465",
            "notifications.mail_host must be the mail server's host name",
        ),
        (
            "mail_host",
            "mail example",
            "notifications.mail_host must be the mail server's host name",
        ),
        (
            "mail_user",
            "two words",
            "notifications.mail_user must be the account's sign-in name",
        ),
    ] {
        let mut pairs = full.to_vec();
        pairs.retain(|(name, _)| *name != key);
        pairs.push((key, text(wrong)));
        assert_eq!(with(&pairs).unwrap_err().0, said, "{key} = {wrong:?}");
    }
}

#[test]
fn the_milter_runs_where_its_section_is_there() {
    assert_eq!(parse(&table()).unwrap().milter, None);
    let with = |pairs: &[(&str, toml::Value)]| {
        let mut raw = table();
        let section = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()));
        raw.insert("milter".into(), toml::Value::Table(section.collect()));
        parse(&raw)
    };
    assert_eq!(
        with(&[]).unwrap().milter,
        Some(MilterConfig {
            port: 8096,
            action: MacroAction::Reject,
            max_message_bytes: 64 * 1024 * 1024,
            defer_when_unreachable: true,
        })
    );
    let set = with(&[
        ("port", toml::Value::Integer(9001)),
        ("on_macro", text("tag")),
        ("max_message_mib", toml::Value::Integer(10)),
        ("when_unreachable", text("accept")),
    ]);
    assert_eq!(
        set.unwrap().milter,
        Some(MilterConfig {
            port: 9001,
            action: MacroAction::Tag,
            max_message_bytes: 10 * 1024 * 1024,
            defer_when_unreachable: false,
        })
    );
    assert_eq!(
        with(&[("on_macro", text("quarantine"))]).unwrap_err().0,
        "milter.on_macro is \"reject\" or \"tag\""
    );
    assert!(with(&[("when_unreachable", text("drop"))]).is_err());
    assert!(with(&[("port", toml::Value::Integer(25))]).is_err());
    assert!(with(&[("max_message_mib", toml::Value::Integer(0))]).is_err());
    assert!(with(&[("max_message_mib", toml::Value::Integer(256))]).is_ok());
    assert!(with(&[("max_message_mib", toml::Value::Integer(257))]).is_err());
    assert!(with(&[("action", text("reject"))]).is_err());
}
