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

use super::Finding;
use super::states::milter as states;
use entries::Entry;

pub(crate) mod entries;

/// How long a milter has to answer the opening doctor sends.
pub(crate) const WITHIN: Duration = Duration::from_secs(3);
/// What doctor reads of each of Stalwart's milters.
const PROPERTIES: [&str; 6] = ["id", "host", "port", "enable", "stages", "tempFailOnError"];

/// What `answered` says of the filter on `port`.
pub(super) fn answering(port: u16, answered: Result<(), String>) -> Finding {
    match answered {
        Ok(()) => Finding::ok(states::answers(port)),
        Err(error) => Finding::fail(states::silent(port, &error)),
    }
}

/// Stalwart's milters, asked with the collector's API key, or why they
/// could not be asked.
fn asked(config: &Config, credentials: &Credentials) -> Result<Vec<Entry>, String> {
    let key = credentials
        .read_secret(&config.collector.native_key)
        .map_err(states::key_unread)?;
    let url = &config.deployment.stalwart_url;
    JmapClient::new(url, &key)
        .get::<Entry>("MtaMilter", None, &PROPERTIES)
        .map_err(|error| states::unasked(url, error))
}

/// Whether `entry` is one of `entries`.
fn among(entry: &Entry, entries: &[&Entry]) -> bool {
    entries.iter().any(|other| other.id == entry.id)
}

/// An entry Stalwart asks in vain that is not the filter's: setup leaves
/// it, and refuses to run while it is there.
fn stranded(entry: &Entry) -> Finding {
    if entry.temp_fail_on_error.0 == Some(false) {
        Finding::warn(states::stranded_unscanned(entry))
    } else {
        Finding::fail(states::stranded(entry))
    }
}

/// Stalwart's side of a filter the configuration has on `port`, deferring
/// mail while it does not answer where `defer` says so: one of the filter's
/// entries asks it there, where it answers, about every message, switched
/// on, as the configuration has it. `vain`: the entries Stalwart asks in
/// vain; `others`, whether one of them is not the filter's, which setup
/// refuses to leave so.
fn configured(
    (port, defer): (u16, bool),
    ours: &[&Entry],
    vain: &[&Entry],
    others: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for stale in ours
        .iter()
        .filter(|entry| !entry.asks(port) || among(entry, vain))
    {
        findings.push(Finding::fail(if among(stale, vain) {
            let elsewhere = (!stale.asks(port)).then_some(port);
            states::unanswered(stale, elsewhere, others)
        } else {
            states::moved(stale, port, others)
        }));
    }
    let at: Vec<&&Entry> = ours
        .iter()
        .filter(|entry| entry.asks(port) && !among(entry, vain))
        .collect();
    if at.is_empty() && findings.is_empty() {
        findings.push(Finding::warn(states::no_entry(port, others)));
    }
    if at.len() > 1 {
        findings.push(Finding::warn(states::several(at.len(), port, others)));
    }
    let Some(entry) = at.first() else {
        return findings;
    };
    match entry.enable.0 {
        Some(true) => {}
        Some(false) => findings.push(Finding::warn(states::off(port, others))),
        None => findings.push(Finding::warn(states::conditional(port, others))),
    }
    if entry.stages.0.data.0 != Some(true) {
        findings.push(Finding::warn(states::before_data(port, others)));
    }
    if entry.temp_fail_on_error.0 != Some(defer) {
        findings.push(Finding::warn(states::when_unreachable(
            entry, defer, others,
        )));
    }
    if findings.is_empty() {
        findings.push(Finding::ok(states::asked(entry, port)));
    }
    findings
}

/// Stalwart's side where the configuration no longer has the filter: none
/// of the filter's entries is left.
fn dropped(ours: &[&Entry], vain: &[&Entry], others: bool) -> Vec<Finding> {
    ours.iter()
        .map(|entry| Finding::fail(states::dropped(entry, among(entry, vain), others)))
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
    let others = !findings.is_empty();
    match filter {
        Some(filter) => findings.extend(configured(filter, &ours, &vain, others)),
        None => findings.extend(dropped(&ours, &vain, others)),
    }
    findings
}

/// What doctor says where Stalwart's milters could not be asked (`why`).
fn unasked(port: Option<u16>, why: &str) -> Finding {
    Finding::unknown(match port {
        Some(port) => states::entry_unknown(port, why),
        None => states::stranded_unknown(why),
    })
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
