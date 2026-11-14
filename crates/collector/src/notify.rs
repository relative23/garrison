//! Telling an operator when a check changes its state: through an ntfy
//! topic, a webhook, a mailbox, or several of them.
//!
//! After every run the collector holds its observations against what it told
//! before. A check that is not in order in two runs in a row, failing or
//! warning or one after the other, is told once; a warning that then fails
//! in two runs in a row is told again as a failure. Its return to order is
//! told whenever something was told of it, whatever it was last. A check
//! that turns unknown, or is missing from a run because what it asks is
//! away, is neither: nothing is known of it, so nothing is said and it
//! keeps its place. Only what Garrison itself observes is told, with the
//! title and first finding of the observation; the message goes out on
//! every channel the operator configured.

pub mod channels;
pub mod mail;

use std::collections::BTreeMap;
use std::sync::Arc;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, State};
use garrison_core::time;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};

pub use channels::{Address, Channels, Level, Note, Secret, Secrets, taken};

use crate::context::{Deadline, Memory};
use crate::fetch;

const OPEN: &str = "notify.open";
const SENT: &str = "notify.sent";
const PROBLEM: &str = "notify.problem";
/// The runs in a row a check must not be in order in before it is told, and
/// fail in before a warning that was told is told again as a failure.
const RUNS: u32 = 2;
/// A check that no run reports any more is forgotten after so many runs: a
/// day of them. Until then it may be away with what it asks, and come back.
const FORGOTTEN: u32 = 1440;
const MOST_LINES: usize = 20;

/// A check that is not in order, as the status database keeps it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct Open {
    /// What the last run that reported it found: `failed` or `warning`, and
    /// `ok` only until its return is told.
    state: String,
    title: String,
    detail: String,
    /// The runs in a row it was not in order, failing or warning.
    runs: u32,
    /// The runs in a row it failed.
    #[serde(default)]
    failed_runs: u32,
    /// Whether anything was told of it.
    told: bool,
    /// The most severe state that was told: `failed` or `warning`.
    #[serde(default)]
    told_as: Option<String>,
    /// What this run has to tell of it, until the message is out.
    #[serde(default)]
    due: Option<String>,
    /// The runs in a row that did not report it.
    #[serde(default)]
    missing: u32,
}

impl Open {
    /// The most severe state that was told. An entry kept before `told_as`
    /// existed was told as the state it has.
    fn severity_told(&self) -> Option<&str> {
        match (&self.told_as, self.told) {
            (Some(told_as), _) => Some(told_as.as_str()),
            (None, true) => Some(self.state.as_str()),
            (None, false) => None,
        }
    }
}

type Opens = BTreeMap<String, Open>;

/// What a run has to tell.
#[derive(Debug, Default, PartialEq, Eq)]
struct News {
    failed: Vec<String>,
    warnings: Vec<String>,
    recovered: Vec<String>,
}

impl News {
    fn is_empty(&self) -> bool {
        self.failed.is_empty() && self.warnings.is_empty() && self.recovered.is_empty()
    }
}

fn named(state: State) -> Option<&'static str> {
    match state {
        State::Failed => Some("failed"),
        State::Warning => Some("warning"),
        _ => None,
    }
}

/// A check that is not in order in this run, after what was kept of it.
fn not_in_order(observation: &Observation, state: &str, before: Option<&Open>) -> Open {
    // A return that could not be told yet begins anew, but stays told.
    let lasting = before.filter(|before| before.state != "ok");
    let failed = state == "failed";
    let mut entry = Open {
        state: state.to_owned(),
        title: observation.title.clone(),
        detail: observation.findings.first().cloned().unwrap_or_default(),
        runs: lasting.map_or(1, |before| before.runs.saturating_add(1)),
        failed_runs: match (failed, lasting) {
            (false, _) => 0,
            (true, None) => 1,
            (true, Some(before)) => before.failed_runs.saturating_add(1),
        },
        told: before.is_some_and(|before| before.told),
        told_as: before.and_then(|before| before.severity_told().map(str::to_owned)),
        due: None,
        missing: 0,
    };
    entry.due = match entry.told_as.as_deref() {
        // Not in order twice in a row: told as what it is now.
        None if entry.runs >= RUNS => Some(state.to_owned()),
        // Told as a warning, and failing for as long as a failure must.
        Some("warning") if entry.failed_runs >= RUNS => Some("failed".to_owned()),
        _ => None,
    };
    entry
}

/// The checks that are open after this run, and what to tell of it. Nothing
/// counts as told yet: [`told`] does that once the message is out.
fn compare(open: &Opens, observations: &[Observation]) -> (Opens, News) {
    let mut next = Opens::new();
    let mut news = News::default();
    let mut reported = std::collections::BTreeSet::new();
    for observation in observations {
        // The channel does not tell of itself.
        if observation.id.starts_with("notifications.") {
            continue;
        }
        reported.insert(observation.id.as_str());
        let before = open.get(&observation.id);
        match (named(observation.state), before) {
            (Some(state), before) => {
                let entry = not_in_order(observation, state, before);
                if let Some(due) = &entry.due {
                    let line = if entry.detail.is_empty() {
                        entry.title.clone()
                    } else {
                        format!("{}: {}", entry.title, entry.detail)
                    };
                    if due == "failed" {
                        news.failed.push(line);
                    } else {
                        news.warnings.push(line);
                    }
                }
                next.insert(observation.id.clone(), entry);
            }
            (None, Some(before)) if observation.state == State::Ok => {
                // Whatever it was last: something was told, so is its return.
                if before.told {
                    news.recovered.push(before.title.clone());
                    // Kept until the message is out, then dropped.
                    next.insert(
                        observation.id.clone(),
                        Open {
                            state: "ok".to_owned(),
                            due: None,
                            missing: 0,
                            ..before.clone()
                        },
                    );
                }
            }
            // Unknown: what was open stays as it was.
            (None, Some(before)) => {
                next.insert(
                    observation.id.clone(),
                    Open {
                        due: None,
                        missing: 0,
                        ..before.clone()
                    },
                );
            }
            (None, None) => {}
        }
    }
    // A check no observation of this run stands for is away with what it
    // asks, Stalwart's API for one: like an unknown one it keeps its place,
    // and with it its return. One that stays away is forgotten in the end.
    for (id, before) in open {
        if reported.contains(id.as_str()) || before.missing >= FORGOTTEN {
            continue;
        }
        if before.state == "ok" {
            // Its return is still to be told.
            news.recovered.push(before.title.clone());
        }
        next.insert(
            id.clone(),
            Open {
                due: None,
                missing: before.missing.saturating_add(1),
                ..before.clone()
            },
        );
    }
    (next, news)
}

/// What is open under a renamed check's old id counts for its new id, so a
/// rename neither tells a problem again nor drops its return.
fn carried_over(mut open: Opens, renamed: &[(&str, &str)]) -> Opens {
    for (old, new) in renamed {
        if let Some(entry) = open.remove(*old) {
            open.entry((*new).to_owned()).or_insert(entry);
        }
    }
    open
}

/// The open checks once the news is out: what was told is marked with what
/// it was told as, what is in order again is dropped.
fn told(open: Opens) -> Opens {
    open.into_iter()
        .filter(|(_, entry)| entry.state != "ok")
        .map(|(id, mut entry)| {
            if let Some(due) = entry.due.take() {
                entry.told = true;
                entry.told_as = Some(due);
            }
            (id, entry)
        })
        .collect()
}

/// The message a run has to send, as every channel can carry it.
fn note(host: &str, news: &News) -> Note {
    let mut counts = Vec::new();
    for (count, one, more) in [
        (news.failed.len(), "failed", "failed"),
        (news.warnings.len(), "warning", "warnings"),
        (news.recovered.len(), "in order again", "in order again"),
    ] {
        if count > 0 {
            counts.push(format!("{count} {}", if count == 1 { one } else { more }));
        }
    }
    let mut lines: Vec<String> = Vec::new();
    for (label, items) in [
        ("Failed", &news.failed),
        ("Warning", &news.warnings),
        ("In order again", &news.recovered),
    ] {
        lines.extend(items.iter().map(|item| {
            let line = format!("{label}: {item}");
            line.chars().take(300).collect::<String>()
        }));
    }
    let more = lines.len().saturating_sub(MOST_LINES);
    lines.truncate(MOST_LINES);
    if more > 0 {
        lines.push(format!("and {more} more; see Garrison."));
    }
    let level = if !news.failed.is_empty() {
        Level::Failed
    } else if !news.warnings.is_empty() {
        Level::Warning
    } else {
        Level::Good
    };
    Note {
        title: format!("Garrison on {host}: {}", counts.join(", ")),
        text: lines.join("\n"),
        level,
        failed: news.failed.clone(),
        warnings: news.warnings.clone(),
        recovered: news.recovered.clone(),
    }
}

/// A message that says the channels work, for `garrison notify-test`: how
/// each configured channel took it.
#[must_use]
pub fn test(channels: &Channels, now: time::Timestamp) -> Vec<(&'static str, Result<(), String>)> {
    channels.send(
        &Note::plain(
            format!("Garrison on {}: test", channels.host),
            "This is a test. Garrison sends a message here when one of its checks fails or \
             warns, and when it is in order again."
                .to_owned(),
            Level::Good,
        ),
        now,
    )
}

/// Tell what this run changed and return the observation of the channels for
/// the Alerts page; `None` where no channel is configured.
pub fn after_run(
    channels: &Channels,
    observations: &[Observation],
    memory: &dyn Memory,
    now: time::Timestamp,
    deadline: Deadline,
) -> Option<Observation> {
    after_run_with(
        channels,
        observations,
        memory,
        now,
        &fetch::roots(),
        deadline,
    )
}

fn after_run_with(
    channels: &Channels,
    observations: &[Observation],
    memory: &dyn Memory,
    now: time::Timestamp,
    roots: &Arc<RootCertStore>,
    deadline: Deadline,
) -> Option<Observation> {
    if channels.is_empty() {
        return None;
    }
    let open: Opens = memory
        .recall(OPEN)
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    let open = carried_over(open, garrison_core::observations::RENAMED);
    let (next, news) = compare(&open, observations);
    let mut problem = memory.recall(PROBLEM).filter(|text| !text.is_empty());
    let kept = if news.is_empty() {
        next
    } else {
        let outcomes = channels.send_with(&note(&channels.host, &news), now, roots, deadline);
        let (any, failures) = taken(&outcomes);
        if let Some(failures) = &failures {
            log::warn!("A notification did not go out: {failures}");
        }
        memory.keep(PROBLEM, failures.as_deref().unwrap_or_default());
        problem = failures;
        if any {
            // Told once a channel took it: the others are not sent it again,
            // and the page shows which of them did not take it.
            memory.keep(SENT, &now.as_second().to_string());
            told(next)
        } else {
            // Nothing counts as told: the next run tries again.
            next
        }
    };
    if let Ok(text) = serde_json::to_string(&kept) {
        memory.keep(OPEN, &text);
    }
    let waiting = kept.values().filter(|entry| entry.state != "ok").count();
    let last = memory
        .recall(SENT)
        .and_then(|text| text.parse().ok())
        .and_then(|second| time::Timestamp::from_second(second).ok())
        .map(time::isoformat);
    // Channels that are named have not yet carried a message: only one that
    // went out shows that they work.
    let never = "No message has gone out on these channels yet, so it is not known whether one \
                 would arrive. `garrison notify-test` sends a test message; this check is in \
                 order once the first notification has gone out.";
    // A channel whose secret cannot be used cannot send, whatever it did
    // before: that is known in every run, without a message to send.
    let mut findings: Vec<String> = channels
        .unusable()
        .into_iter()
        .map(|line| format!("{line}."))
        .collect();
    let state = match (&problem, &last) {
        (Some(problem), _) => {
            findings.push(format!("The last notification did not go out: {problem}."));
            State::Failed
        }
        _ if !findings.is_empty() => State::Failed,
        (None, None) => {
            findings.push(never.to_owned());
            State::Unknown
        }
        (None, Some(_)) => State::Ok,
    };
    let names = channels.names().join(", ");
    Observation::new(
        "notifications.channels",
        "notifications",
        "Notifications",
        [ModuleId::Alerts],
        Evidence::Probe,
        state,
        time::isoformat(now),
        names.clone(),
    )
    .ok()
    .map(|observation| {
        observation
            .with_scope(
                "Garrison sends a message on these channels when one of its checks fails or \
                 warns in two runs in a row, and when it is in order again.",
            )
            .with_fields(vec![
                Field::text("Channels", names),
                Field::new("Checks not in order", waiting, Format::Number),
                Field::new("Last notification", last, Format::Datetime),
            ])
            .with_findings(findings)
            .with_max_age(180)
    })
}

#[cfg(test)]
mod secret_tests;
#[cfg(test)]
mod state_tests;
#[cfg(test)]
mod tests;
