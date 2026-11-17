//! The macro milter, where the configuration has it or setup's note says
//! that Stalwart was told of it: the filter answers as a milter, and
//! Stalwart asks it as the configuration has it, which doctor asks Stalwart
//! itself with the collector's API key, as the collector reads Stalwart's
//! milters. And the other way round: a filter Stalwart still asks although
//! the configuration dropped it, which makes Stalwart defer mail once the
//! filter stops.

use std::fs;
use std::time::Duration;

use garrison_collector::providers::stalwart::answers::{Fixed, Stages, Tolerant, Written};
use garrison_core::config::Config;
use garrison_core::credentials::Credentials;
use garrison_stalwart::jmap::JmapClient;
use garrison_stalwart::{Error, SUPPORTED};
use serde::Deserialize;
use serde_json::Value;

use super::Finding;
use crate::units;

const SETUP: &str = "Run `garrison stalwart setup`.";
/// How long a milter has to answer the opening doctor sends.
const WITHIN: Duration = Duration::from_secs(3);
/// What doctor reads of each of Stalwart's milters.
const PROPERTIES: [&str; 6] = ["id", "host", "port", "enable", "stages", "tempFailOnError"];

/// One of Stalwart's milters, read as the collector reads them.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    id: String,
    #[serde(default)]
    host: Written,
    #[serde(default)]
    port: Written,
    #[serde(default)]
    enable: Fixed,
    #[serde(default)]
    stages: Tolerant<Stages>,
    #[serde(default)]
    temp_fail_on_error: Fixed,
}

impl Entry {
    /// The port it asks, where it names one.
    fn port(&self) -> Option<u16> {
        match &self.port.0 {
            Some(Value::Number(number)) => {
                number.as_u64().and_then(|port| u16::try_from(port).ok())
            }
            Some(Value::String(text)) => text.parse().ok(),
            _ => None,
        }
    }

    /// Whether it asks the filter where setup enters it: 127.0.0.1 at
    /// `port`.
    fn asks(&self, port: u16) -> bool {
        self.host.0.as_ref().and_then(Value::as_str) == Some("127.0.0.1")
            && self.port() == Some(port)
    }

    /// Where it asks, as Stalwart holds it.
    fn address(&self) -> String {
        format!("{}:{}", self.host.text(), self.port.text())
    }

    /// What Stalwart does with `mail` while the filter does not answer.
    fn meanwhile(&self, mail: &str) -> String {
        match self.temp_fail_on_error.0 {
            Some(true) => format!("defers {mail}"),
            Some(false) => format!("takes {mail} unscanned"),
            None => format!("decides by conditions of its own what to do with {mail}"),
        }
    }
}

/// What `answered` says of the filter on `port`.
pub(super) fn answering(port: u16, answered: Result<(), String>) -> Finding {
    match answered {
        Ok(()) => Finding::ok(format!("the macro milter answers on 127.0.0.1:{port}")),
        Err(error) => Finding::fail(
            format!("the macro milter does not answer on 127.0.0.1:{port}: {error}"),
            format!("journalctl -u {} -n 50 shows why.", units::MILTER),
        ),
    }
}

/// Stalwart's milters, asked with the collector's API key, or why they
/// could not be asked.
fn asked(config: &Config, credentials: &Credentials) -> Result<Vec<Entry>, String> {
    let key = credentials
        .read_secret(&config.collector.native_key)
        .map_err(|error| format!("the collector's API key: {error}"))?;
    let url = &config.deployment.stalwart_url;
    JmapClient::new(url, &key)
        .get::<Entry>("MtaMilter", None, &PROPERTIES)
        .map_err(|error| match error {
            Error::Unavailable(why) => format!("Stalwart did not answer at {url} ({why})"),
            Error::Limited(why) => {
                format!("Stalwart refused the question for its rate limit ({why}); ask again in a minute")
            }
            Error::Denied(_) | Error::InvalidToken(_) | Error::Misconfigured(_) => {
                "Stalwart refused the collector's API key; `garrison stalwart setup` gives it the \
                 permissions it needs"
                    .to_owned()
            }
            Error::Unreadable(why) => format!(
                "Stalwart answered in a form this release of Garrison does not read ({why}); \
                 {SUPPORTED}"
            ),
        })
}

/// Where Stalwart asks `entry` in vain, what follows: nothing answers there
/// on this host, so Stalwart does with all incoming mail what the entry says.
fn vain(entry: &Entry, answers: &dyn Fn(u16) -> bool) -> String {
    let here = matches!(
        entry.host.0.as_ref().and_then(Value::as_str),
        Some("127.0.0.1" | "localhost")
    );
    match entry.port() {
        Some(port) if here && !answers(port) => format!(
            ", where nothing answers: Stalwart {}",
            entry.meanwhile("all incoming mail")
        ),
        _ => String::new(),
    }
}

/// Stalwart's side of a filter the configuration has on `port`, deferring
/// mail while it does not answer where `defer` says so: one entry asks it
/// there about every message, switched on, as the configuration has it.
fn configured(
    port: u16,
    defer: bool,
    noted: Option<&str>,
    entries: &[Entry],
    answers: &dyn Fn(u16) -> bool,
) -> Vec<Finding> {
    let at: Vec<&Entry> = entries.iter().filter(|entry| entry.asks(port)).collect();
    let noted = noted.and_then(|id| entries.iter().find(|entry| entry.id == id));
    let mut findings = Vec::new();
    if let Some(stale) = noted.filter(|entry| !entry.asks(port)) {
        findings.push(Finding::fail(
            format!(
                "Stalwart asks the macro milter at {}, but the configuration has it on \
                 127.0.0.1:{port}{}",
                stale.address(),
                vain(stale, answers)
            ),
            SETUP,
        ));
    } else if at.is_empty() {
        findings.push(Finding::warn(
            format!(
                "Stalwart has no entry for the macro milter on 127.0.0.1:{port} and asks it \
                 nothing"
            ),
            SETUP,
        ));
    }
    if at.len() > 1 {
        findings.push(Finding::warn(
            format!(
                "Stalwart has {} entries for the macro milter on 127.0.0.1:{port}",
                at.len()
            ),
            SETUP,
        ));
    }
    let Some(entry) = noted
        .filter(|entry| entry.asks(port))
        .or_else(|| at.first().copied())
    else {
        return findings;
    };
    let switched = match entry.enable.0 {
        Some(true) => None,
        Some(false) => Some("is switched off"),
        None => Some("is switched on only under conditions of its own"),
    };
    if let Some(switched) = switched {
        findings.push(Finding::warn(
            format!("Stalwart's entry for the macro milter on 127.0.0.1:{port} {switched}"),
            SETUP,
        ));
    }
    if entry.stages.0.data.0 != Some(true) {
        findings.push(Finding::warn(
            format!(
                "Stalwart does not ask the macro milter on 127.0.0.1:{port} once a message's data \
                 has arrived, so it sees no attachment"
            ),
            SETUP,
        ));
    }
    if entry.temp_fail_on_error.0 != Some(defer) {
        let wanted = if defer { "defer" } else { "accept" };
        findings.push(Finding::warn(
            format!(
                "Stalwart {} while the macro milter does not answer, though when_unreachable \
                 is \"{wanted}\"",
                entry.meanwhile("mail")
            ),
            SETUP,
        ));
    }
    if findings.is_empty() {
        findings.push(Finding::ok(format!(
            "Stalwart asks the macro milter on 127.0.0.1:{port} about every message and {} \
             while it does not answer",
            entry.meanwhile("mail")
        )));
    }
    findings
}

/// Stalwart's side where the configuration no longer has the filter but
/// setup's note says Stalwart was told of it.
fn dropped(noted: Option<&str>, asked: Result<&[Entry], &str>) -> Finding {
    let fix =
        format!("{SETUP} It takes the filter out of Stalwart; until then mail may be deferred.");
    let entries = match asked {
        Ok(entries) => entries,
        Err(why) => {
            return Finding::fail(
                format!(
                    "setup's note says Stalwart asks the macro milter, which the configuration no \
                     longer has; Stalwart could not be asked: {why}"
                ),
                fix,
            );
        }
    };
    match noted.and_then(|id| entries.iter().find(|entry| entry.id == id)) {
        Some(entry) => Finding::fail(
            format!(
                "Stalwart still asks the macro milter at {}, which the configuration no longer \
                 has",
                entry.address()
            ),
            fix,
        ),
        None => Finding::warn(
            "setup's note names a macro milter entry that Stalwart no longer has, so the \
             installer keeps the filter running and uninstall refuses",
            "Run `garrison stalwart setup`, which removes the note.",
        ),
    }
}

pub(super) fn checks(config: &Config, credentials: &Credentials) -> Vec<Finding> {
    let note = config.credentials_directory.join(units::MILTER_ENTRY);
    let kept = fs::symlink_metadata(&note).is_ok();
    // An empty note names no entry, though the installer reads it as one.
    let noted = fs::read_to_string(&note)
        .ok()
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty());
    let mut findings = Vec::new();
    if let Some(milter) = &config.milter {
        findings.push(answering(
            milter.port,
            garrison_milter::answers(milter.port, WITHIN),
        ));
    }
    if config.milter.is_none() && !kept {
        return findings;
    }
    let asked = asked(config, credentials);
    let asked = asked.as_deref().map_err(String::as_str);
    let answers = |port| garrison_milter::answers(port, WITHIN).is_ok();
    match (&config.milter, asked) {
        (Some(milter), Ok(entries)) => findings.extend(configured(
            milter.port,
            milter.defer_when_unreachable,
            noted.as_deref(),
            entries,
            &answers,
        )),
        (Some(milter), Err(why)) => findings.push(Finding::unknown(format!(
            "whether Stalwart asks the macro milter on 127.0.0.1:{}: {why}",
            milter.port
        ))),
        (None, asked) => findings.push(dropped(noted.as_deref(), asked)),
    }
    findings
}

#[cfg(test)]
mod tests;
