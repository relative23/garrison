//! Sending addresses: what signed-in accounts handed in under each sender
//! address during the last day, against that address's own average of the
//! two weeks before.
//!
//! An account whose password was guessed or stolen shows in what it sends:
//! many times its usual volume, a burst within one hour, or a large share of
//! recipients that do not exist. Each of these is a warning, with the
//! address and the figures; Garrison blocks nothing. The figures come from
//! the event history, read every ten minutes.
//!
//! The events name the sender address of a message, not the account that
//! signed in to hand it in. So the check counts by address: an account that
//! sends under two of its addresses shows as two rows, each with its own
//! usual volume. The observation keeps the id it always had,
//! `senders.accounts`.

use std::collections::BTreeSet;
use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{
    Column, Evidence, Field, Format, Observation, Required, State, Table,
};
use garrison_core::sqlite::reading;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::context::{Collected, Context, Provider, Report};
use crate::kept::{Kept, cached};
use crate::options::{Checked, Options};

mod read;

const QUEUED: &str = "queue.authenticated-message-queued";
const BOUNCED: &str = "delivery.dsn-perm-fail";
const DAY: i64 = 86_400;
/// The days before the last one that make an address's usual volume, and how
/// many of them the history must hold before a usual volume is named.
const USUAL_DAYS: i64 = 14;
const KNOWN_DAYS: i64 = 3;
/// The history is read this often.
const EVERY: i64 = 600;
const MAX_EVENTS: usize = 200_000;
const ROWS: usize = 20;
const MEMORY: &str = "senders.accounts";
/// Bounces count once they are this share of an address's recipients.
const BOUNCE_SHARE: u64 = 5;

/// What was sent under one address in the last day.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
struct Sender {
    address: String,
    messages: u64,
    recipients: u64,
    /// Its recipients a day before that; `None` while the history is short.
    usual: Option<u64>,
    busiest_hour: u64,
    bounces: u64,
    /// The IP addresses its mail was handed in from.
    clients: u64,
}

/// Where more mail was handed in than is read, what of it was read whole.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
struct Cut {
    /// The whole days before the last one that were read, which the usual
    /// volumes are of.
    days: i64,
    /// Whether the last day was read whole.
    last_day: bool,
}

/// What the status database keeps of the last reading.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
struct Read {
    senders: Vec<Sender>,
    /// Where more mail was handed in than is read.
    #[serde(default)]
    cut: Option<Cut>,
    /// Whether more bounces came in the last day than are counted.
    #[serde(default)]
    bounces_cut: bool,
    problem: Option<String>,
    /// Why the history does not hold the last day, where it does not.
    #[serde(default)]
    uncovered: Option<String>,
    /// Why no usual volume is named, where the days before have a gap.
    #[serde(default)]
    unusual_unknown: Option<String>,
    /// Events left out, as a value in them is of another type than the
    /// receiver writes.
    #[serde(default)]
    unreadable: u64,
}

#[derive(Debug)]
pub struct Senders {
    modules: BTreeSet<ModuleId>,
    /// The newest submissions, and bounces, that a reading takes.
    most: usize,
    /// Below this many recipients in a day nothing counts as unusual.
    min_recipients: u64,
    /// So many times an address's usual volume is a warning.
    factor: u64,
    /// So many recipients within one hour are a warning.
    burst: u64,
    /// So many bounces in a day are a warning, where they are a fifth of the recipients.
    bounces: u64,
}

impl Senders {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(
            raw,
            &["modules", "min_recipients", "factor", "burst", "bounces"],
        )?;
        let number = |key: &str, default: i64| {
            options
                .integer(key, default, 1, 1_000_000)
                .map(|value| u64::try_from(value).unwrap_or(1))
        };
        Ok(Senders {
            modules: options.modules(&["attacks"])?,
            most: MAX_EVENTS,
            min_recipients: number("min_recipients", 50)?,
            factor: number("factor", 5)?,
            burst: number("burst", 100)?,
            bounces: number("bounces", 10)?,
        })
    }

    /// For tests: take at most `most` submissions and bounces in a reading.
    #[cfg(test)]
    #[must_use]
    pub fn reading_at_most(mut self, most: usize) -> Self {
        self.most = most;
        self
    }

    /// Why an address's day is unusual; nothing where it is not.
    fn reasons(&self, sender: &Sender) -> Vec<String> {
        let mut reasons = Vec::new();
        if let Some(usual) = sender.usual
            && sender.recipients >= self.min_recipients
            && sender.recipients >= self.factor.saturating_mul(usual.max(1))
        {
            reasons.push(if usual == 0 {
                format!(
                    "{} recipients in 24 hours from an address that sent nothing in the {USUAL_DAYS} days before",
                    sender.recipients
                )
            } else {
                format!(
                    "{} recipients in 24 hours, where {usual} a day is usual",
                    sender.recipients
                )
            });
        }
        if sender.busiest_hour >= self.burst {
            reasons.push(format!(
                "{} recipients within one hour",
                sender.busiest_hour
            ));
        }
        if sender.bounces >= self.bounces
            && sender.bounces.saturating_mul(BOUNCE_SHARE) >= sender.recipients
        {
            reasons.push(format!(
                "{} of {} recipients bounced",
                sender.bounces, sender.recipients
            ));
        }
        reasons
    }

    /// The last reading, or a new one where that is due: every ten minutes.
    fn known(context: &Context<'_>, most: usize) -> Kept<Read> {
        let problem = |problem: String| Read {
            problem: Some(problem),
            ..Read::default()
        };
        cached(
            context,
            MEMORY,
            |_, _| EVERY,
            |_| match reading(&context.events_database, Duration::from_secs(2)) {
                Ok(Some(db)) => {
                    Self::read(&db, context.now.as_second(), most).unwrap_or_else(|error| {
                        problem(format!("the event history could not be read: {error}"))
                    })
                }
                Ok(None) => problem("no events are recorded yet".to_owned()),
                Err(error) => problem(format!("the event history could not be opened: {error}")),
            },
        )
    }
}

/// A number with a space between its thousands, as `200 000`.
fn spaced(number: usize) -> String {
    let digits = number.to_string();
    let mut text = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            text.push(' ');
        }
        text.push(digit);
    }
    text
}

impl Senders {
    /// Each address of `read` with why its day is unusual, with the limits as
    /// configured now, also over a reading kept from before: what needs a
    /// look first, then the busiest; names settle the rest.
    fn judged<'a>(&self, read: &'a Read) -> Vec<(&'a Sender, Vec<String>)> {
        let mut judged: Vec<(&Sender, Vec<String>)> = read
            .senders
            .iter()
            .map(|sender| (sender, self.reasons(sender)))
            .collect();
        judged.sort_by(|(left, why), (right, other)| {
            why.is_empty()
                .cmp(&other.is_empty())
                .then_with(|| right.recipients.cmp(&left.recipients))
                .then_with(|| left.address.cmp(&right.address))
        });
        judged
    }

    /// What a reading that left mail out says of it.
    fn cut_findings(&self, read: &Read) -> Vec<String> {
        let most = spaced(self.most);
        let mut findings = Vec::new();
        match &read.cut {
            Some(cut) if !cut.last_day => findings.push(format!(
                "More mail was handed in during the last 24 hours than is read: the figures are \
                 those of the newest {most} messages, and no usual volume is named."
            )),
            Some(cut) if cut.days < KNOWN_DAYS => findings.push(format!(
                "More mail was handed in in these 15 days than is read: no usual volume is named, \
                 since the newest {most} messages hold {} whole days before the last one.",
                cut.days
            )),
            Some(cut) => findings.push(format!(
                "More mail was handed in in these 15 days than is read: the usual volumes are those \
                 of the {} whole days before the last one that the newest {most} messages hold.",
                cut.days
            )),
            None => {}
        }
        if read.bounces_cut {
            findings.push(format!(
                "More bounces came in the last 24 hours than are counted here, which counts the \
                 newest {most}."
            ));
        }
        findings
    }
}

impl Provider for Senders {
    fn name(&self) -> &'static str {
        "senders"
    }

    fn ids(&self) -> Vec<String> {
        vec!["senders.accounts".to_owned()]
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let kept = Self::known(context, self.most);
        let read = &kept.answer;
        let judged = self.judged(read);
        let unusual: Vec<&(&Sender, Vec<String>)> = judged
            .iter()
            .filter(|(_, reasons)| !reasons.is_empty())
            .collect();
        let mut findings: Vec<String> = unusual
            .iter()
            .take(5)
            .map(|(sender, reasons)| format!("{}: {}.", sender.address, reasons.join("; ")))
            .collect();
        if unusual.len() > 5 {
            findings.push(format!("And {} more addresses.", unusual.len() - 5));
        }
        let state = match (&read.problem, unusual.is_empty()) {
            (Some(problem), _) => {
                findings = vec![format!("The sending addresses are not known: {problem}.")];
                State::Unknown
            }
            (None, false) => State::Warning,
            // A quiet day only over a history that holds the day.
            (None, true) if read.uncovered.is_some() => State::Unknown,
            // Nor over a day that was read in part.
            (None, true)
                if read.bounces_cut
                    || read.cut.as_ref().is_some_and(|cut| !cut.last_day)
                    || read.unreadable > 0 =>
            {
                State::Partial
            }
            (None, true) => State::Ok,
        };
        if let Some(reason) = read.uncovered.as_ref().filter(|_| read.problem.is_none()) {
            findings.push(format!(
                "The event history is not current: {reason}. Mail that was handed in may be \
                 missing here."
            ));
        }
        if let Some(reason) = &read.unusual_unknown {
            findings.push(format!("No usual volume is named: {reason}."));
        }
        findings.extend(self.cut_findings(read));
        findings
            .extend(super::history::left_out(read.unreadable).filter(|_| read.problem.is_none()));
        let column = |label: &str, format| Column {
            label: label.to_owned(),
            format,
        };
        let observation = Observation::new(Required {
            id: "senders.accounts",
            provider: self.name(),
            title: "Sending addresses",
            modules: self.modules.iter().copied(),
            evidence: Evidence::Probe,
            state,
            checked_at: &context.checked_at(),
            source: "event history",
        })?
        .with_scope(
            "Mail that signed-in accounts handed in during the last 24 hours, by sender address, \
             against each address's own average of the 14 days before. An account that sends \
             under several addresses shows once for each. Read every ten minutes; nothing is \
             blocked.",
        )
        .with_fields(vec![
            Field::new("Addresses that sent", read.senders.len(), Format::Number),
            Field::new("Unusual", unusual.len(), Format::Number),
            Field::new("Read", kept.asked(), Format::Datetime),
        ])
        .with_table(Table {
            columns: vec![
                column("Sender address", Format::Text),
                column("Messages", Format::Number),
                column("Recipients", Format::Number),
                column("Usual a day", Format::Number),
                column("Busiest hour", Format::Number),
                column("Bounces", Format::Number),
                column("IP addresses", Format::Number),
            ],
            rows: judged
                .iter()
                .take(ROWS)
                .map(|(sender, _)| {
                    vec![
                        json!(sender.address),
                        json!(sender.messages),
                        json!(sender.recipients),
                        json!(sender.usual),
                        json!(sender.busiest_hour),
                        json!(sender.bounces),
                        json!(sender.clients),
                    ]
                })
                .collect(),
        })
        .with_findings(findings);
        // The card is as old as the reading it is made from.
        Ok(Report::of(kept.dated(observation)))
    }
}

#[cfg(test)]
mod tests;
