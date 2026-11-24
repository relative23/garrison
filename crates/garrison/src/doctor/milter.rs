//! The macro milter: where the configuration has it, the filter answers as
//! a milter and Stalwart asks it as the configuration has it; where it does
//! not, Stalwart no longer asks it. And whatever the configuration has,
//! every entry Stalwart asks where no milter answers, which makes Stalwart
//! defer mail. doctor asks Stalwart with the collector's API key, as the
//! collector reads Stalwart's milters, and tells the filter's entries from
//! others by the rules setup acts by (`entries`).

use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::credentials::Credentials;
use garrison_stalwart::jmap::JmapClient;
use garrison_stalwart::{Error, SUPPORTED};

use super::Finding;
use crate::units;
use entries::Entry;

pub(crate) mod entries;

const SETUP: &str = "Run `garrison stalwart setup`.";
/// The fix of a line setup mends where Stalwart also asks in vain an entry
/// that is not the filter's, which setup refuses to leave so.
const AFTER: &str =
    "Run `garrison stalwart setup` once the milters named above are out of Stalwart.";
/// How long a milter has to answer the opening doctor sends.
pub(crate) const WITHIN: Duration = Duration::from_secs(3);
/// What doctor reads of each of Stalwart's milters.
const PROPERTIES: [&str; 6] = ["id", "host", "port", "enable", "stages", "tempFailOnError"];

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
            // A key it does not know and one without the permission alike:
            // the line on the key says which.
            Error::Denied(_) | Error::InvalidToken(_) | Error::Misconfigured(_) => {
                "Stalwart refused the collector's API key".to_owned()
            }
            Error::Unreadable(why) => format!(
                "Stalwart answered in a form this release of Garrison does not read ({why}); \
                 {SUPPORTED}"
            ),
        })
}

/// Whether `entry` is one of `entries`.
fn among(entry: &Entry, entries: &[&Entry]) -> bool {
    entries.iter().any(|other| other.id == entry.id)
}

/// What follows where Stalwart asks `entry`, one of `vain`, in vain: it does
/// with all incoming mail what the entry says.
fn unanswered(entry: &Entry, vain: &[&Entry]) -> String {
    if among(entry, vain) {
        format!(
            ", where nothing answers: Stalwart {}",
            entry.meanwhile("all incoming mail")
        )
    } else {
        String::new()
    }
}

/// An entry Stalwart asks in vain that is not the filter's: setup leaves
/// it, and refuses to run while it is there.
fn stranded(entry: &Entry) -> Finding {
    let what = format!(
        "Stalwart asks a milter at {} (entry {}), where nothing answers: Stalwart {}",
        entry.address(),
        entry.id,
        entry.meanwhile("all incoming mail")
    );
    if entry.temp_fail_on_error.0 == Some(false) {
        Finding::warn(what, entries::REMOVE)
    } else {
        Finding::fail(what, entries::REMOVE)
    }
}

/// Stalwart's side of a filter the configuration has on `port`, deferring
/// mail while it does not answer where `defer` says so: one of the filter's
/// entries asks it there, where it answers, about every message, switched
/// on, as the configuration has it. `vain`: the entries Stalwart asks in
/// vain; `fix` is what mends it.
fn configured(
    (port, defer): (u16, bool),
    ours: &[&Entry],
    vain: &[&Entry],
    fix: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for stale in ours
        .iter()
        .filter(|entry| !entry.asks(port) || among(entry, vain))
    {
        let elsewhere = if stale.asks(port) {
            String::new()
        } else {
            format!(", but the configuration has it on 127.0.0.1:{port}")
        };
        findings.push(Finding::fail(
            format!(
                "Stalwart asks the macro milter at {}{elsewhere}{}",
                stale.address(),
                unanswered(stale, vain)
            ),
            fix,
        ));
    }
    let at: Vec<&&Entry> = ours
        .iter()
        .filter(|entry| entry.asks(port) && !among(entry, vain))
        .collect();
    if at.is_empty() && findings.is_empty() {
        findings.push(Finding::warn(
            format!(
                "Stalwart has no entry for the macro milter on 127.0.0.1:{port} and asks it \
                 nothing"
            ),
            fix,
        ));
    }
    if at.len() > 1 {
        findings.push(Finding::warn(
            format!(
                "Stalwart has {} entries for the macro milter on 127.0.0.1:{port}",
                at.len()
            ),
            fix,
        ));
    }
    let Some(entry) = at.first() else {
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
            fix,
        ));
    }
    if entry.stages.0.data.0 != Some(true) {
        findings.push(Finding::warn(
            format!(
                "Stalwart does not ask the macro milter on 127.0.0.1:{port} once a message's data \
                 has arrived, so it sees no attachment"
            ),
            fix,
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
            fix,
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

/// Stalwart's side where the configuration no longer has the filter: none
/// of the filter's entries is left.
fn dropped(ours: &[&Entry], vain: &[&Entry], fix: &str) -> Vec<Finding> {
    ours.iter()
        .map(|entry| {
            Finding::fail(
                format!(
                    "Stalwart still asks the macro milter at {}, which the configuration no \
                     longer has{}",
                    entry.address(),
                    unanswered(entry, vain)
                ),
                format!(
                    "{fix} It takes the filter out of Stalwart; until then mail may be deferred."
                ),
            )
        })
        .collect()
}

/// What doctor says of Stalwart's `entries`, where garrison.toml has the
/// filter on a port and defers mail while it does not answer (`filter`) or
/// does not have it, the running filter listens on `listening` and a milter
/// answers where `answers` says so.
fn judged(
    filter: Option<(u16, bool)>,
    entries: &[Entry],
    listening: &[u16],
    answers: &dyn Fn(&Entry) -> bool,
) -> Vec<Finding> {
    let ours = entries::ours(entries, filter.map(|(port, _)| port), listening);
    let vain = entries::vain(entries, answers);
    let mut findings: Vec<Finding> = vain
        .iter()
        .filter(|entry| !among(entry, &ours))
        .map(|entry| stranded(entry))
        .collect();
    let fix = if findings.is_empty() { SETUP } else { AFTER };
    match filter {
        Some(filter) => findings.extend(configured(filter, &ours, &vain, fix)),
        None => findings.extend(dropped(&ours, &vain, fix)),
    }
    findings
}

/// What doctor says where Stalwart's milters could not be asked (`why`).
fn unasked(port: Option<u16>, why: &str) -> Finding {
    match port {
        Some(port) => Finding::unknown(format!(
            "whether Stalwart asks the macro milter on 127.0.0.1:{port}: {why}"
        )),
        None => Finding::unknown(format!(
            "whether Stalwart asks a milter where nothing answers: {why}"
        )),
    }
}

pub(super) fn checks(config: &Config, credentials: &Credentials) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(milter) = &config.milter {
        findings.push(answering(
            milter.port,
            garrison_milter::answers(milter.port, WITHIN),
        ));
    }
    let filter = config
        .milter
        .as_ref()
        .map(|milter| (milter.port, milter.defer_when_unreachable));
    match asked(config, credentials) {
        Ok(entries) => {
            let listening = entries::listening().unwrap_or_default();
            let answers = |entry: &Entry| entry.answers(WITHIN);
            findings.extend(judged(filter, &entries, &listening, &answers));
        }
        Err(why) => findings.push(unasked(filter.map(|(port, _)| port), &why)),
    }
    findings
}

#[cfg(test)]
mod tests;
