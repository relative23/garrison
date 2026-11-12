//! The channels a notification goes out on: an ntfy topic, a webhook, a
//! mailbox. All that are configured get every message.

use std::sync::Arc;

use garrison_core::config::{Config, Notifications};
use garrison_core::credentials::Credentials;
use garrison_core::time;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::mail::{self, Mail};
use crate::fetch::{self, Request};

/// An address with the token that goes with it; an empty token sends none.
#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Address {
    pub url: String,
    /// Read from its credential, never kept with the address.
    #[serde(skip)]
    pub token: String,
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
    pub ntfy: String,
    pub webhook: String,
    pub mail: String,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Nothing of a secret belongs in a log or a panic message.
        formatter.debug_struct("Secrets").finish_non_exhaustive()
    }
}

impl Secrets {
    /// The secrets of a configuration. One that is missing or unreadable
    /// reads as none: a topic or a webhook may need no token.
    #[must_use]
    pub fn read(credentials: &Credentials, notifications: &Notifications) -> Self {
        let read = |source| {
            credentials
                .read_secret(source)
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        Secrets {
            ntfy: read(&notifications.token),
            webhook: read(&notifications.webhook_token),
            mail: read(&notifications.mail_password),
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

/// Send `body` as JSON to `url`; an empty token sends none.
fn post(
    url: &str,
    token: &str,
    body: &serde_json::Value,
    roots: &Arc<RootCertStore>,
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
    Ok(fetch::send(&request, roots)?.status)
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
                token: String::new(),
            }),
            webhook: notifications.webhook_url.clone().map(|url| Address {
                url,
                token: String::new(),
            }),
            mail: notifications.mail.as_ref().map(|mail| Mail {
                host: mail.host.clone(),
                port: mail.port,
                user: mail.user.clone(),
                password: String::new(),
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
        self.send_with(note, now, &fetch::roots())
    }

    pub(crate) fn send_with(
        &self,
        note: &Note,
        now: time::Timestamp,
        roots: &Arc<RootCertStore>,
    ) -> Vec<(&'static str, Result<(), String>)> {
        let mut outcomes = Vec::new();
        if let Some(ntfy) = &self.ntfy {
            outcomes.push(("ntfy", to_ntfy(ntfy, note, roots)));
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
            let sent = post(&webhook.url, &webhook.token, &body, roots).and_then(|status| {
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
            outcomes.push((
                "mail",
                mail::submit(mail, &self.host, &note.title, &text, now, roots),
            ));
        }
        outcomes
    }
}

/// ntfy's JSON publishing: the topic is the last part of the address.
fn to_ntfy(ntfy: &Address, note: &Note, roots: &Arc<RootCertStore>) -> Result<(), String> {
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
    match post(&format!("{base}/"), &ntfy.token, &body, roots)? {
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
