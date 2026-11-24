//! The channels a notification goes out on: an ntfy topic, a webhook, a
//! mailbox. All that are configured get every message.

use std::sync::Arc;
use std::time::Instant;

use garrison_core::config::{self, Config};
use garrison_core::credentials::Credentials;
use garrison_core::time;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::mail::{self, Mail};
use super::secrets::{Address, Secret, Secrets};
use crate::context::Deadline;
use crate::fetch::{self, Needs, Request};

/// Where notifications go. Its stored form holds no secret, and no address
/// that is kept in a file.
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

/// The name of a channel of `kind` whose address cannot be read now, as
/// while its file is written anew: where it points is not known.
pub(super) fn unread(kind: &str) -> String {
    format!("{kind}, whose address cannot be read")
}

/// The server of an address, `host` or `host:port`, never more of it: what
/// an earlier release kept for the watch may hold a query right after it.
pub(crate) fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split(['/', '?', '#', '\\']).next().unwrap_or(rest)
}

/// An error of a request to `url` that names its server alone, where the
/// client named the whole address or all up to its first `/`.
fn named_by_server(error: &str, url: &str) -> String {
    let server = host_of(url);
    let error = error.replace(url, &format!("the address at {server}"));
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    match rest.split('/').next() {
        Some(taken) if taken != server && !taken.is_empty() => error.replace(taken, server),
        _ => error,
    }
}

/// Send `body` as JSON to `url`, done by `until`; an empty token sends none.
/// An error names the server, not the whole address: a webhook's may carry
/// its key, and the error goes to the journal and onto the Alerts page.
///
/// The status is all a channel reads of the answer. A receiver that ends
/// TLS without its closing notice and gives its answer no length, as
/// Python's `http.server` behind `ssl` does, has taken the message once its
/// head arrived: a message counted as lost would be sent again every run.
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
        needs: Needs::Head,
    };
    fetch::send_until(&request, roots, until)
        .map(|answer| answer.status)
        .map_err(|error| match url {
            "" => error,
            url => named_by_server(&error, url),
        })
}

impl Channels {
    /// The channels of a configuration, with their secrets. An address that
    /// is kept in a file is read by [`Channels::located`].
    #[must_use]
    pub fn of(config: &Config, secrets: Secrets) -> Self {
        let notifications = &config.notifications;
        let channels = Channels {
            host: host_of(&config.deployment.public_origin).to_owned(),
            ntfy: notifications.ntfy_url.as_ref().map(Address::configured),
            webhook: notifications.webhook_url.as_ref().map(Address::configured),
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

    /// These channels with every address that is kept in a file read from
    /// it, as the configuration and the stored form name it.
    #[must_use]
    pub fn located(mut self, credentials: &Credentials) -> Self {
        if let Some(ntfy) = &mut self.ntfy {
            ntfy.read(credentials, "notifications.ntfy_url", config::ntfy_address);
        }
        if let Some(webhook) = &mut self.webhook {
            webhook.read(
                credentials,
                "notifications.webhook_url",
                config::webhook_address,
            );
        }
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ntfy.is_none() && self.webhook.is_none() && self.mail.is_none()
    }

    /// The channels that cannot send, as the files of their addresses and
    /// secrets stand now, each with why: `ntfy: notifications.token cannot
    /// be used: …`.
    #[must_use]
    pub fn unusable(&self) -> Vec<String> {
        let mut found = Vec::new();
        for (channel, address) in [("ntfy", &self.ntfy), ("webhook", &self.webhook)] {
            let Some(address) = address else {
                continue;
            };
            if let Some(why) = &address.unusable {
                found.push(format!("{channel}: {why}"));
            }
            if let Secret::Unusable(why) = &address.token {
                found.push(format!("{channel}: {why}"));
            }
        }
        if let Some(Secret::Unusable(why)) = self.mail.as_ref().map(|mail| &mail.password) {
            found.push(format!("mail: {why}"));
        }
        found
    }

    /// Each channel as a page names it, without anything secret: the server
    /// of an address, never the rest of it.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.named().into_iter().map(|(_, name)| name).collect()
    }

    /// The same, each with its kind, as [`Channels::send`] names it.
    #[must_use]
    pub fn named(&self) -> Vec<(&'static str, String)> {
        let mut named = Vec::new();
        for (channel, address) in [("ntfy", &self.ntfy), ("webhook", &self.webhook)] {
            if let Some(address) = address {
                let name = match address.usable() {
                    Ok(url) => format!("{channel} at {}", host_of(url)),
                    Err(_) => unread(channel),
                };
                named.push((channel, name));
            }
        }
        if let Some(mail) = &self.mail {
            named.push(("mail", format!("mail to {}", mail.to)));
        }
        named
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
                .and_then(|until| {
                    post(
                        webhook.usable()?,
                        webhook.token.text()?,
                        &body,
                        roots,
                        until,
                    )
                })
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
        .usable()?
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
