//! The channels' card on the Alerts page: whether each channel took the last
//! notification, and whether its address and secret can be used as their
//! files stand now.
//!
//! What the last notification did is kept for each kind of channel with the
//! name the page showed it by then ("webhook at hooks.example.org") and the
//! notification's time, and judged against the channels configured now: a
//! channel taken out of the configuration, or named otherwise now, is no
//! longer judged by it, and one named since has carried no message yet, so
//! whether one would arrive is not known. A channel whose address could not
//! be read then, or cannot now, as while its file is written anew, is the
//! one of its kind. The next notification replaces it. `garrison
//! notify-test`, which runs as root, does not: only the collector writes the
//! status database.

use std::collections::{BTreeMap, BTreeSet};

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, Required, State};
use garrison_core::time;
use serde::{Deserialize, Serialize};

use super::Channels;
use super::channels::unread;
use crate::context::Memory;

/// Where it is kept.
const LAST: &str = "notify.last";
/// The failures of the last notification on one line, as a release before
/// this one kept them and reads them: kept beside it for a return to one.
const PROBLEM: &str = "notify.problem";
/// Where the second of the last notification a channel took is kept.
pub(super) const SENT: &str = "notify.sent";

/// The configured channels by kind and name, as [`Channels::named`] gives
/// them.
type Named = [(&'static str, String)];

/// What the last notification did on one channel.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
struct Took {
    /// The channel's name as the page showed it then.
    name: String,
    /// `None` where the channel took it, else why not, as `webhook: it
    /// answered 500`.
    failed: Option<String>,
}

/// What the last notification did on each channel, by its kind.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct Last {
    /// When it was sent, a Unix second; none where a release before this
    /// one kept what it did, which it kept without a time.
    at: Option<i64>,
    channels: BTreeMap<String, Took>,
}

impl Last {
    /// What the notification sent at `at` did on each of the `named`
    /// channels, from the `outcomes` of each kind.
    pub(super) fn sent(
        at: i64,
        named: &Named,
        outcomes: &[(&'static str, Result<(), String>)],
    ) -> Self {
        let channels = named
            .iter()
            .filter_map(|(kind, name)| {
                let (_, outcome) = outcomes.iter().find(|(sent, _)| sent == kind)?;
                let failed = outcome.as_ref().err().map(|why| format!("{kind}: {why}"));
                let name = name.clone();
                Some(((*kind).to_owned(), Took { name, failed }))
            })
            .collect();
        Last {
            at: Some(at),
            channels,
        }
    }

    /// What is kept, of the channels configured now alone; or what a release
    /// before this one kept: the failures on one line, by kind, and whether
    /// a channel took the message.
    pub(super) fn recalled(memory: &dyn Memory, named: &Named) -> Option<Self> {
        let last = match memory.recall(LAST) {
            // What does not read is none, as before the first notification.
            Some(text) => serde_json::from_str(&text).ok()?,
            None => Last::earlier(memory, named)?,
        };
        Some(last.of(named))
    }

    /// What a release before this one kept: which channels did not take the
    /// last notification, but not its words for why, which may name all of
    /// a channel's address.
    fn earlier(memory: &dyn Memory, named: &Named) -> Option<Self> {
        let problem = memory.recall(PROBLEM).unwrap_or_default();
        let taken = memory.recall(SENT).is_some();
        if problem.is_empty() && !taken {
            return None;
        }
        let failed = by_kind(&problem);
        let channels = named
            .iter()
            .filter_map(|(kind, name)| {
                let failed = if failed.contains(kind) {
                    Some(Some(format!("{kind}: it did not take it")))
                } else {
                    taken.then_some(None)
                };
                let name = name.clone();
                failed.map(|failed| ((*kind).to_owned(), Took { name, failed }))
            })
            .collect();
        Some(Last { at: None, channels })
    }

    /// The same, of the channels configured now alone.
    pub(super) fn of(mut self, named: &Named) -> Self {
        self.channels.retain(|kind, took| {
            named
                .iter()
                .any(|(now, name)| now == kind && same(kind, &took.name, name))
        });
        self
    }

    /// Whether the notification went out on the channel of `kind`.
    fn carried(&self, kind: &str) -> bool {
        self.channels.contains_key(kind)
    }

    /// Why the channels that did not take it did not, in the order they are
    /// configured, on one line; empty where each took it.
    fn failures(&self, named: &Named) -> String {
        let failed: Vec<&str> = named
            .iter()
            .filter_map(|(kind, _)| self.channels.get(*kind)?.failed.as_deref())
            .collect();
        failed.join("; ")
    }

    /// The names of the channels that did not take it, in their order.
    fn failed(&self, named: &Named) -> Vec<String> {
        named
            .iter()
            .filter(|(kind, _)| {
                self.channels
                    .get(*kind)
                    .is_some_and(|took| took.failed.is_some())
            })
            .map(|(_, name)| name.clone())
            .collect()
    }

    /// Keep it, and its failures for a release before this one, where they
    /// changed: the collector runs every minute.
    pub(super) fn keep(&self, memory: &dyn Memory, named: &Named) {
        let text = serde_json::to_string(self).unwrap_or_default();
        if memory.recall(LAST).as_deref() != Some(text.as_str()) {
            memory.keep(LAST, &text);
        }
        let failures = self.failures(named);
        if memory.recall(PROBLEM).unwrap_or_default() != failures {
            memory.keep(PROBLEM, &failures);
        }
    }
}

/// Whether the channel of `kind` that was named `then` is the one named
/// `now`: the same name, or one of them is of an address that could not be
/// read, so that where it pointed is not known.
fn same(kind: &str, then: &str, now: &str) -> bool {
    let unread = unread(kind);
    then == now || then == unread || now == unread
}

/// With no channel configured, what the last notification did is forgotten,
/// so that a channel named again is not judged by what one of its name did
/// before; nothing is kept where nothing was.
pub(super) fn forget(memory: &dyn Memory) {
    let kept = memory.recall(LAST).is_some()
        || memory
            .recall(PROBLEM)
            .is_some_and(|problem| !problem.is_empty());
    if kept {
        Last::default().keep(memory, &[]);
    }
}

/// The kinds of channel whose failure a line that a release before this one
/// kept names: `ntfy: …; webhook: …`. A kind begins the line or follows `; `.
fn by_kind(line: &str) -> BTreeSet<&'static str> {
    ["ntfy", "webhook", "mail"]
        .into_iter()
        .filter(|kind| {
            let prefix = format!("{kind}: ");
            line.starts_with(&prefix) || line.contains(&format!("; {prefix}"))
        })
        .collect()
}

/// Channels that are named have not yet carried a message: only one that
/// went out shows that they work.
const NEVER: &str = "No message has gone out on these channels yet, so it is not known whether \
                     one would arrive. `garrison notify-test` sends a test message; this check is \
                     in order once the first notification has gone out.";

/// The card of `channels` after this run: what `last` did on each, and how
/// many checks are not in order (`waiting`).
pub(super) fn card(
    channels: &Channels,
    named: &Named,
    last: Option<&Last>,
    waiting: usize,
    memory: &dyn Memory,
    now: time::Timestamp,
) -> Option<Observation> {
    let sent = memory
        .recall(SENT)
        .and_then(|text| text.parse().ok())
        .and_then(|second| time::Timestamp::from_second(second).ok())
        .map(time::isoformat);
    // A channel whose secret cannot be used cannot send, whatever it did
    // before: that is known in every run, without a message to send.
    let mut findings: Vec<String> = channels
        .unusable()
        .into_iter()
        .map(|line| format!("{line}."))
        .collect();
    let failures = last.map(|last| last.failures(named)).unwrap_or_default();
    if let Some(last) = last.filter(|_| !failures.is_empty()) {
        let at = last.at.and_then(|at| time::Timestamp::from_second(at).ok());
        findings.push(match at {
            Some(at) => format!(
                "The notification of {} did not go out: {failures}.",
                time::isoformat(at)
            ),
            None => format!(
                "The last notification did not go out on {}. `garrison notify-test` shows \
                 whether one goes out now.",
                last.failed(named).join(", ")
            ),
        });
    }
    let unsent: Vec<&str> = named
        .iter()
        .filter(|(kind, _)| last.is_none_or(|last| !last.carried(kind)))
        .map(|(_, name)| name.as_str())
        .collect();
    let state = if !findings.is_empty() {
        State::Failed
    } else if unsent.len() == named.len() {
        findings.push(NEVER.to_owned());
        State::Unknown
    } else if !unsent.is_empty() {
        findings.push(format!(
            "No message has gone out on {} yet, so it is not known whether one would arrive \
             there. `garrison notify-test` sends a test message; this check is in order once a \
             notification has gone out on each.",
            unsent.join(", ")
        ));
        State::Unknown
    } else {
        State::Ok
    };
    let shown: Vec<&str> = named.iter().map(|(_, name)| name.as_str()).collect();
    let shown = shown.join(", ");
    Observation::new(Required {
        id: "notifications.channels",
        provider: "notifications",
        title: "Notifications",
        modules: [ModuleId::Alerts],
        evidence: Evidence::Probe,
        state,
        checked_at: &time::isoformat(now),
        source: &shown,
    })
    .ok()
    .map(|observation| {
        observation
            .with_scope(
                "Garrison sends a message on these channels when one of its checks fails or \
                 warns in two runs in a row, and when it is in order again.",
            )
            .with_fields(vec![
                Field::text("Channels", shown),
                Field::new("Checks not in order", waiting, Format::Number),
                Field::new("Last notification", sent, Format::Datetime),
            ])
            .with_findings(findings)
            .with_max_age(180)
    })
}
