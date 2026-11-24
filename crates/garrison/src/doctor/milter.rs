//! The macro milter: where the configuration has it, the filter answers as
//! a milter and Stalwart asks it as the configuration has it; where it does
//! not, Stalwart no longer asks it. And whatever the configuration has,
//! every entry Stalwart asks on this host where nothing answers, which makes
//! Stalwart defer mail. doctor asks Stalwart with the collector's API key,
//! as the collector reads Stalwart's milters, and tells the filter's entries
//! from others by the rules setup acts by (`entries`).

use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::credentials::Credentials;
use garrison_stalwart::jmap::JmapClient;
use garrison_stalwart::{Error, SUPPORTED};

use super::Finding;
use crate::units;
use entries::{Entry, Note};

pub(crate) mod entries;

const SETUP: &str = "Run `garrison stalwart setup`.";
/// The fix of a line setup mends where Stalwart also asks in vain an entry
/// setup cannot tell for the filter's, which setup refuses to leave so.
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
fn unanswered(entry: &Entry, answers: &dyn Fn(u16) -> bool) -> String {
    match entry.port() {
        Some(port) if entry.here() && !answers(port) => format!(
            ", where nothing answers: Stalwart {}",
            entry.meanwhile("all incoming mail")
        ),
        _ => String::new(),
    }
}

/// An entry Stalwart asks in vain that setup cannot tell for the filter's:
/// setup leaves it, and refuses to run while it is there.
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
/// entries asks it there about every message, switched on, as the
/// configuration has it. `fix` is what mends it.
fn configured(
    (port, defer): (u16, bool),
    ours: &[&Entry],
    fix: &str,
    answers: &dyn Fn(u16) -> bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for stale in ours.iter().filter(|entry| !entry.asks(port)) {
        findings.push(Finding::fail(
            format!(
                "Stalwart asks the macro milter at {}, but the configuration has it on \
                 127.0.0.1:{port}{}",
                stale.address(),
                unanswered(stale, answers)
            ),
            fix,
        ));
    }
    let at: Vec<&&Entry> = ours.iter().filter(|entry| entry.asks(port)).collect();
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
/// of the filter's entries is left, and no note keeps the filter running.
fn dropped(note: &Note, ours: &[&Entry], fix: &str, answers: &dyn Fn(u16) -> bool) -> Vec<Finding> {
    let mut findings: Vec<Finding> = ours
        .iter()
        .map(|entry| {
            Finding::fail(
                format!(
                    "Stalwart still asks the macro milter at {}, which the configuration no \
                     longer has{}",
                    entry.address(),
                    unanswered(entry, answers)
                ),
                format!(
                    "{fix} It takes the filter out of Stalwart; until then mail may be deferred."
                ),
            )
        })
        .collect();
    let named = match note {
        _ if !findings.is_empty() => None,
        Note::Named(_) => Some("names a macro milter entry that Stalwart no longer has"),
        Note::Empty => Some("names no macro milter entry"),
        Note::Missing | Note::Pending(_) => None,
    };
    if let Some(named) = named {
        findings.push(Finding::warn(
            format!(
                "setup's note {named}, so the installer keeps the filter running and uninstall \
                 refuses"
            ),
            if fix == SETUP {
                "Run `garrison stalwart setup`, which removes the note."
            } else {
                AFTER
            },
        ));
    }
    findings
}

/// What doctor says of Stalwart's `entries`, where garrison.toml has the
/// filter on a port and defers mail while it does not answer (`filter`) or
/// does not have it, setup's note says `note`, the running filter listens
/// on `listening` and a milter answers on each port `answers` takes.
fn judged(
    filter: Option<(u16, bool)>,
    note: &Note,
    entries: &[Entry],
    listening: &[u16],
    answers: &dyn Fn(u16) -> bool,
) -> Vec<Finding> {
    let ours = entries::ours(entries, note.id(), filter.map(|(port, _)| port), listening);
    let theirs = entries
        .iter()
        .filter(|entry| !ours.iter().any(|our| our.id == entry.id));
    let mut findings: Vec<Finding> = entries::vain(theirs, answers)
        .into_iter()
        .map(stranded)
        .collect();
    let fix = if findings.is_empty() { SETUP } else { AFTER };
    if matches!(note, Note::Pending(_)) {
        findings.push(Finding::fail(
            "setup's last run changed Stalwart's entry for the macro milter and stopped before \
             Stalwart read its settings again, so Stalwart may still ask the filter as before",
            fix,
        ));
        return findings;
    }
    match filter {
        Some(filter) => findings.extend(configured(filter, &ours, fix, answers)),
        None => findings.extend(dropped(note, &ours, fix, answers)),
    }
    findings
}

/// What doctor says where Stalwart's milters could not be asked (`why`).
fn unasked(port: Option<u16>, note: &Note, why: &str) -> Finding {
    match (port, note) {
        (Some(port), _) => Finding::unknown(format!(
            "whether Stalwart asks the macro milter on 127.0.0.1:{port}: {why}"
        )),
        (None, Note::Missing) => Finding::unknown(format!(
            "whether Stalwart asks a milter on this host where nothing answers: {why}"
        )),
        (None, _) => Finding::fail(
            format!(
                "setup's note says Stalwart may ask the macro milter, which the configuration no \
                 longer has; Stalwart could not be asked: {why}"
            ),
            format!(
                "{SETUP} It takes the filter out of Stalwart; until then mail may be deferred."
            ),
        ),
    }
}

pub(super) fn checks(config: &Config, credentials: &Credentials) -> Vec<Finding> {
    let note = Note::read(&config.credentials_directory.join(units::MILTER_ENTRY));
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
    let answers = |port| garrison_milter::answers(port, WITHIN).is_ok();
    match asked(config, credentials) {
        Ok(entries) => findings.extend(judged(
            filter,
            &note,
            &entries,
            &entries::listening(),
            &answers,
        )),
        Err(why) => findings.push(unasked(filter.map(|(port, _)| port), &note, &why)),
    }
    findings
}

#[cfg(test)]
mod tests;
