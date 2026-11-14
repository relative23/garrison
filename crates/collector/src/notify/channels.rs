//! The channels a notification goes out on: an ntfy topic, a webhook, a
//! mailbox. All that are configured get every message.

use std::sync::Arc;
use std::time::Instant;

use garrison_core::config::{Config, Notifications};
use garrison_core::credentials::{Credentials, SecretSource};
use garrison_core::files::{Form, ProtectedFileError};
use garrison_core::time;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::mail::{self, Mail};
use crate::context::Deadline;
use crate::fetch::{self, Request};

/// A channel's secret as its file holds it.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum Secret {
    /// The file is empty: the channel sends none.
    #[default]
    Empty,
    Text(String),
    /// The file cannot be used, and why; never what it holds.
    Unusable(String),
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Nothing of a secret belongs in a log or a panic message.
        formatter.write_str(match self {
            Secret::Empty => "Secret::Empty",
            Secret::Text(_) => "Secret::Text(..)",
            Secret::Unusable(_) => "Secret::Unusable(..)",
        })
    }
}

impl Secret {
    /// The secret that `setting` names, read in its form.
    fn read(credentials: &Credentials, source: &SecretSource, setting: &str, form: Form) -> Self {
        match credentials.read_optional_secret(source, form) {
            Ok(None) => Secret::Empty,
            Ok(Some(text)) => Secret::Text(text),
            Err(error) => Secret::Unusable(unusable(setting, form, &error)),
        }
    }

    /// What to send: the secret, nothing for an empty file, or why the
    /// channel cannot send at all.
    pub(crate) fn text(&self) -> Result<&str, String> {
        match self {
            Secret::Empty => Ok(""),
            Secret::Text(text) => Ok(text),
            Secret::Unusable(why) => Err(why.clone()),
        }
    }
}

/// Why the file `setting` names cannot be used. The error names the file
/// and what is wrong with it, never what it holds.
fn unusable(setting: &str, form: Form, error: &ProtectedFileError) -> String {
    let wanted = match (error, form) {
        (ProtectedFileError::InvalidSecret(_), Form::Token) => {
            ". A token is one line of 16 to 8192 printable characters without spaces"
        }
        (ProtectedFileError::InvalidSecret(_), Form::Password) => {
            ". A password is one line of text without control characters, at most 8192 bytes"
        }
        _ => "",
    };
    format!("{setting} cannot be used: {error}{wanted}")
}

/// An address with the token that goes with it; an empty file sends none.
#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Address {
    pub url: String,
    /// Read from its credential, never kept with the address.
    #[serde(skip)]
    pub token: Secret,
}

impl std::fmt::Debug for Address {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Address")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// What the channels need beside their addresses.
#[derive(Clone, Default)]
pub struct Secrets {
    pub ntfy: Secret,
    pub webhook: Secret,
    pub mail: Secret,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Nothing of a secret belongs in a log or a panic message.
        formatter.debug_struct("Secrets").finish_non_exhaustive()
    }
}

impl Secrets {
    /// The secrets of a configuration. An empty file means that a topic or
    /// a webhook needs no token; a file that cannot be used is that
    /// channel's error, and so is an empty password, since mail is always
    /// submitted signed in.
    #[must_use]
    pub fn read(credentials: &Credentials, notifications: &Notifications) -> Self {
        Self::from_sources(
            credentials,
            [
                &notifications.token,
                &notifications.webhook_token,
                &notifications.mail_password,
            ],
        )
    }

    /// The secrets the units load by name, for a watch whose configuration
    /// does not load: the three settings' defaults.
    #[must_use]
    pub fn loaded(credentials: &Credentials) -> Self {
        let [ntfy, webhook, mail] = ["ntfy-token", "notify-webhook-token", "notify-mail-password"]
            .map(|name| SecretSource::Credential(name.to_owned()));
        Self::from_sources(credentials, [&ntfy, &webhook, &mail])
    }

    fn from_sources(credentials: &Credentials, [ntfy, webhook, mail]: [&SecretSource; 3]) -> Self {
        const PASSWORD: &str = "notifications.mail_password";
        let mail = match Secret::read(credentials, mail, PASSWORD, Form::Password) {
            Secret::Empty => Secret::Unusable(format!(
                "{PASSWORD} is empty, and mail is submitted signed in: write the account's \
                 password into the file it names"
            )),
            secret => secret,
        };
        Secrets {
            ntfy: Secret::read(credentials, ntfy, "notifications.token", Form::Token),
            webhook: Secret::read(
                credentials,
                webhook,
                "notifications.webhook_token",
                Form::Token,
            ),
            mail,
        }
    }
}

/// Where notifications go. Its stored form holds no secret.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Channels {
    /// This installation's own host name, which every message carries.
    pub host: String,
    pub ntfy: Option<Address>,
    pub webhook: Option<Address>,
    pub mail: Option<Mail>,
}

/// How a message is marked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Failed,
    Warning,
    Good,
}

/// One message, in the form every channel can carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub title: String,
    pub text: String,
    pub level: Level,
    pub failed: Vec<String>,
    pub warnings: Vec<String>,
    pub recovered: Vec<String>,
}

impl Note {
    /// A message that lists no checks.
    #[must_use]
    pub fn plain(title: String, text: String, level: Level) -> Self {
        Note {
            title,
            text,
            level,
            failed: Vec::new(),
            warnings: Vec::new(),
            recovered: Vec::new(),
        }
    }
}

/// `host` of `https://host/...`.
pub(crate) fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split('/').next().unwrap_or(rest)
}

/// Send `body` as JSON to `url`, done by `until`; an empty token sends none.
fn post(
    url: &str,
    token: &str,
    body: &serde_json::Value,
    roots: &Arc<RootCertStore>,
    until: Instant,
) -> Result<u16, String> {
    let authorization = format!("Bearer {token}");
    let mut headers = vec![("Content-Type", "application/json")];
    if !token.is_empty() {
        headers.push(("Authorization", authorization.as_str()));
    }
    let body = body.to_string();
    let request = Request {
        method: "POST",
        url,
        headers: &headers,
        body: body.as_bytes(),
    };
    Ok(fetch::send_until(&request, roots, until)?.status)
}

impl Channels {
    /// The channels of a configuration, with their secrets.
    #[must_use]
    pub fn of(config: &Config, secrets: Secrets) -> Self {
        let notifications = &config.notifications;
        let channels = Channels {
            host: host_of(&config.deployment.public_origin).to_owned(),
            ntfy: notifications.ntfy_url.clone().map(|url| Address {
                url,
                token: Secret::Empty,
            }),
            webhook: notifications.webhook_url.clone().map(|url| Address {
                url,
                token: Secret::Empty,
            }),
            mail: notifications.mail.as_ref().map(|mail| Mail {
                host: mail.host.clone(),
                port: mail.port,
                user: mail.user.clone(),
                password: Secret::Empty,
                from: mail.from.clone(),
                to: mail.to.clone(),
            }),
        };
        channels.with(secrets)
    }

    /// These channels with their secrets, which the stored form leaves out.
    #[must_use]
    pub fn with(mut self, secrets: Secrets) -> Self {
        if let Some(ntfy) = &mut self.ntfy {
            ntfy.token = secrets.ntfy;
        }
        if let Some(webhook) = &mut self.webhook {
            webhook.token = secrets.webhook;
        }
        if let Some(mail) = &mut self.mail {
            mail.password = secrets.mail;
        }
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ntfy.is_none() && self.webhook.is_none() && self.mail.is_none()
    }

    /// The channels that cannot send, as their secret's file stands now,
    /// each with why: `ntfy: notifications.token cannot be used: …`.
    #[must_use]
    pub fn unusable(&self) -> Vec<String> {
        [
            ("ntfy", self.ntfy.as_ref().map(|ntfy| &ntfy.token)),
            ("webhook", self.webhook.as_ref().map(|hook| &hook.token)),
            ("mail", self.mail.as_ref().map(|mail| &mail.password)),
        ]
        .into_iter()
        .filter_map(|(channel, secret)| match secret {
            Some(Secret::Unusable(why)) => Some(format!("{channel}: {why}")),
            _ => None,
        })
        .collect()
    }

    /// Each channel as a page names it, without anything secret.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if let Some(ntfy) = &self.ntfy {
            names.push(format!("ntfy at {}", host_of(&ntfy.url)));
        }
        if let Some(webhook) = &self.webhook {
            names.push(format!("webhook at {}", host_of(&webhook.url)));
        }
        if let Some(mail) = &self.mail {
            names.push(format!("mail to {}", mail.to));
        }
        names
    }

    /// Send `note` on every channel and say how each one took it.
    #[must_use]
    pub fn send(
        &self,
        note: &Note,
        now: time::Timestamp,
    ) -> Vec<(&'static str, Result<(), String>)> {
        self.send_with(note, now, &fetch::roots(), Deadline::NONE)
    }

    /// The same within `deadline`: each channel has what a request has, or
    /// what is left of the deadline if that is less, and a channel whose
    /// turn comes after it is not tried.
    pub(crate) fn send_with(
        &self,
        note: &Note,
        now: time::Timestamp,
        roots: &Arc<RootCertStore>,
        deadline: Deadline,
    ) -> Vec<(&'static str, Result<(), String>)> {
        let in_time = || {
            if deadline.expired() {
                return Err("not tried: the collection run's time was used up".to_owned());
            }
            Ok(deadline.by(fetch::WITHIN))
        };
        let mut outcomes = Vec::new();
        if let Some(ntfy) = &self.ntfy {
            let sent = in_time().and_then(|until| to_ntfy(ntfy, note, roots, until));
            outcomes.push(("ntfy", sent));
        }
        if let Some(webhook) = &self.webhook {
            let body = json!({
                "source": "garrison",
                "host": self.host,
                "title": note.title,
                "message": note.text,
                "level": match note.level {
                    Level::Failed => "failed",
                    Level::Warning => "warning",
                    Level::Good => "ok",
                },
                "failed": note.failed,
                "warnings": note.warnings,
                "recovered": note.recovered,
                "sentAt": time::isoformat(now),
            });
            let sent = in_time()
                .and_then(|until| post(&webhook.url, webhook.token.text()?, &body, roots, until))
                .and_then(|status| {
                    if (200..300).contains(&status) {
                        Ok(())
                    } else {
                        Err(format!("it answered {status}"))
                    }
                });
            outcomes.push(("webhook", sent));
        }
        if let Some(mail) = &self.mail {
            let text = format!("{}\n\nSent by Garrison on {}.\n", note.text, self.host);
            let sent = in_time().and_then(|until| {
                mail::submit_until(mail, &self.host, &note.title, &text, now, roots, until)
            });
            outcomes.push(("mail", sent));
        }
        outcomes
    }
}

/// ntfy's JSON publishing: the topic is the last part of the address.
fn to_ntfy(
    ntfy: &Address,
    note: &Note,
    roots: &Arc<RootCertStore>,
    until: Instant,
) -> Result<(), String> {
    let (base, topic) = ntfy
        .url
        .rsplit_once('/')
        .ok_or("the address names no topic")?;
    let (priority, tag) = match note.level {
        Level::Failed => (4, "rotating_light"),
        Level::Warning => (3, "warning"),
        Level::Good => (3, "white_check_mark"),
    };
    let body = json!({
        "topic": topic,
        "title": note.title,
        "message": note.text,
        "priority": priority,
        "tags": [tag],
    });
    match post(&format!("{base}/"), ntfy.token.text()?, &body, roots, until)? {
        200 => Ok(()),
        status => Err(format!("it answered {status}")),
    }
}

/// Whether any channel took the message, and what the others said.
#[must_use]
pub fn taken(outcomes: &[(&'static str, Result<(), String>)]) -> (bool, Option<String>) {
    let problems: Vec<String> = outcomes
        .iter()
        .filter_map(|(channel, outcome)| {
            outcome
                .as_ref()
                .err()
                .map(|error| format!("{channel}: {error}"))
        })
        .collect();
    let any = outcomes.iter().any(|(_, outcome)| outcome.is_ok());
    (any, (!problems.is_empty()).then(|| problems.join("; ")))
}
