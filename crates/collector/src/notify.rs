//! Telling an operator when a check changes its state: through an ntfy
//! topic, a webhook, a mailbox, or several of them.
//!
//! After every run the collector holds its observations against what it told
//! before. A check that fails or warns in two runs in a row is told once; so
//! is its return to order. A check that turns unknown is neither: nothing is
//! known of it, so nothing is said. Only what Garrison itself observes is
//! told, with the title and first finding of the observation; the message
//! goes out on every channel the operator configured.

pub mod channels;
pub mod mail;

use std::collections::BTreeMap;
use std::sync::Arc;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, State};
use garrison_core::time;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};

pub use channels::{Address, Channels, Level, Note, Secrets, taken};

use crate::context::Memory;
use crate::fetch;

const OPEN: &str = "notify.open";
const SENT: &str = "notify.sent";
const PROBLEM: &str = "notify.problem";
/// The runs in a row a check must fail or warn in before it is told.
const RUNS: u32 = 2;
const MOST_LINES: usize = 20;

/// A check that is not in order, as the status database keeps it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct Open {
    /// `failed` or `warning`.
    state: String,
    title: String,
    detail: String,
    runs: u32,
    told: bool,
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

/// The checks that are open after this run, and what to tell of it. Nothing
/// counts as told yet: [`told`] does that once the message is out.
fn compare(open: &Opens, observations: &[Observation]) -> (Opens, News) {
    let mut next = Opens::new();
    let mut news = News::default();
    for observation in observations {
        // The channel does not tell of itself.
        if observation.id.starts_with("notifications.") {
            continue;
        }
        let before = open.get(&observation.id);
        match (named(observation.state), before) {
            (Some(state), before) => {
                let detail = observation.findings.first().cloned().unwrap_or_default();
                let same = before.filter(|before| before.state == state);
                let entry = Open {
                    state: state.to_owned(),
                    title: observation.title.clone(),
                    detail,
                    runs: same.map_or(1, |before| before.runs.saturating_add(1)),
                    told: same.is_some_and(|before| before.told),
                };
                if !entry.told && entry.runs >= RUNS {
                    let line = if entry.detail.is_empty() {
                        entry.title.clone()
                    } else {
                        format!("{}: {}", entry.title, entry.detail)
                    };
                    if state == "failed" {
                        news.failed.push(line);
                    } else {
                        news.warnings.push(line);
                    }
                }
                next.insert(observation.id.clone(), entry);
            }
            (None, Some(before)) if observation.state == State::Ok => {
                if before.told {
                    news.recovered.push(before.title.clone());
                    // Kept until the message is out, then dropped.
                    next.insert(
                        observation.id.clone(),
                        Open {
                            state: "ok".to_owned(),
                            ..before.clone()
                        },
                    );
                }
            }
            // Unknown: what was open stays as it was.
            (None, Some(before)) => {
                next.insert(observation.id.clone(), before.clone());
            }
            (None, None) => {}
        }
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

/// The open checks once the news is out: what was told is marked, what is in
/// order again is dropped.
fn told(open: Opens) -> Opens {
    open.into_iter()
        .filter(|(_, entry)| entry.state != "ok")
        .map(|(id, mut entry)| {
            entry.told = entry.told || entry.runs >= RUNS;
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
) -> Option<Observation> {
    after_run_with(channels, observations, memory, now, &fetch::roots())
}

fn after_run_with(
    channels: &Channels,
    observations: &[Observation],
    memory: &dyn Memory,
    now: time::Timestamp,
    roots: &Arc<RootCertStore>,
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
        let outcomes = channels.send_with(&note(&channels.host, &news), now, roots);
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
    let state = if problem.is_some() {
        State::Failed
    } else {
        State::Ok
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
            .with_findings(
                problem
                    .map(|problem| format!("The last notification did not go out: {problem}."))
                    .into_iter()
                    .collect(),
            )
            .with_max_age(180)
    })
}

#[cfg(test)]
mod tests;
