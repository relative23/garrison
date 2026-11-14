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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{
    Column, Evidence, Field, Format, Observation, Required, State, Table,
};
use garrison_core::sqlite::reading;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::history;
use crate::context::{Collected, Context, Provider, Report};
use crate::kept::{Kept, cached};
use crate::options::{Checked, Options};

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
    reasons: Vec<String>,
}

/// What the status database keeps of the last reading.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
struct Read {
    senders: Vec<Sender>,
    /// More events were recorded than were read.
    truncated: bool,
    problem: Option<String>,
    /// Why the history does not hold the last day, where it does not.
    #[serde(default)]
    uncovered: Option<String>,
    /// Why no usual volume is named, where the days before have a gap.
    #[serde(default)]
    unusual_unknown: Option<String>,
}

#[derive(Debug)]
pub struct Senders {
    modules: BTreeSet<ModuleId>,
    /// Below this many recipients in a day nothing counts as unusual.
    min_recipients: u64,
    /// So many times an address's usual volume is a warning.
    factor: u64,
    /// So many recipients within one hour are a warning.
    burst: u64,
    /// So many bounces in a day are a warning, where they are a fifth of the recipients.
    bounces: u64,
}

#[derive(Default)]
struct Sums {
    messages: u64,
    recipients: u64,
    before: u64,
    hours: BTreeMap<i64, u64>,
    clients: BTreeSet<String>,
    bounces: u64,
}

/// The address an event names as its sender, in lower case; `None` for a
/// bounce's empty sender. It is the message's sender address, not the
/// account that signed in: the event does not name that one.
fn sender_address(fields: &Value) -> Option<String> {
    let from = fields["from"]
        .as_str()?
        .trim_matches(['<', '>'])
        .to_lowercase();
    (!from.is_empty()).then_some(from)
}

fn recipients(fields: &Value) -> u64 {
    match &fields["to"] {
        Value::Array(items) => items.len() as u64,
        Value::String(_) => 1,
        _ => 0,
    }
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
            min_recipients: number("min_recipients", 50)?,
            factor: number("factor", 5)?,
            burst: number("burst", 100)?,
            bounces: number("bounces", 10)?,
        })
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

    /// Read the last 15 days of the history at `now`.
    fn read(&self, db: &Connection, now: i64) -> rusqlite::Result<Read> {
        let since = now - (USUAL_DAYS + 1) * DAY;
        let today = now - DAY;
        // A day's volume is in order only over a history that holds the day.
        let uncovered = history::uncovered(db, today, now);
        // Events lost in the days before would make every average too low,
        // and an ordinary day an outlier: then no usual volume is named.
        let unusual_unknown = uncovered
            .is_none()
            .then(|| history::uncovered(db, since, today))
            .flatten();
        let begins: Option<i64> =
            db.query_row("SELECT MIN(created_at) FROM events", [], |row| row.get(0))?;
        // The whole days before the last one that the history holds.
        let known = begins.map_or(0, |begins| (today - begins.max(since)) / DAY);
        let known = if unusual_unknown.is_some() { 0 } else { known };
        let mut sums: HashMap<String, Sums> = HashMap::new();
        let limit = i64::try_from(MAX_EVENTS + 1).unwrap_or(i64::MAX);
        let mut statement = db.prepare(
            "SELECT created_at,fields FROM events WHERE type=?1 AND created_at>=?2 \
             AND created_at<=?3 ORDER BY seq DESC LIMIT ?4",
        )?;
        let mut truncated = false;
        let mut rows = statement.query((QUEUED, since, now, limit))?;
        let mut read = 0;
        while let Some(row) = rows.next()? {
            if read == MAX_EVENTS {
                truncated = true;
                break;
            }
            read += 1;
            let at: i64 = row.get(0)?;
            let text: String = row.get(1)?;
            let Ok(fields) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            let Some(address) = sender_address(&fields) else {
                continue;
            };
            let count = recipients(&fields);
            let entry = sums.entry(address).or_default();
            if at >= today {
                entry.messages += 1;
                entry.recipients += count;
                *entry.hours.entry((now - at) / 3600).or_default() += count;
                entry
                    .clients
                    .extend(fields["remoteIp"].as_str().map(str::to_owned));
            } else {
                entry.before += count;
            }
        }
        drop(rows);
        let mut rows = statement.query((BOUNCED, today, now, limit))?;
        while let Some(row) = rows.next()? {
            let text: String = row.get(1)?;
            let sender = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|fields| sender_address(&fields));
            if let Some(entry) = sender.and_then(|sender| sums.get_mut(&sender)) {
                entry.bounces += 1;
            }
        }
        let mut senders: Vec<Sender> = sums
            .into_iter()
            .filter(|(_, sums)| sums.messages > 0)
            .map(|(address, sums)| {
                let mut sender = Sender {
                    address,
                    messages: sums.messages,
                    recipients: sums.recipients,
                    usual: (known >= KNOWN_DAYS)
                        .then(|| sums.before / u64::try_from(known).unwrap_or(1).max(1)),
                    busiest_hour: sums.hours.values().copied().max().unwrap_or(0),
                    bounces: sums.bounces,
                    clients: sums.clients.len() as u64,
                    reasons: Vec::new(),
                };
                sender.reasons = self.reasons(&sender);
                sender
            })
            .collect();
        // What needs a look first, then the busiest; names settle the rest.
        senders.sort_by(|left, right| {
            let (quiet, other) = (left.reasons.is_empty(), right.reasons.is_empty());
            quiet
                .cmp(&other)
                .then_with(|| right.recipients.cmp(&left.recipients))
                .then_with(|| left.address.cmp(&right.address))
        });
        Ok(Read {
            senders,
            truncated,
            problem: None,
            uncovered,
            unusual_unknown,
        })
    }

    /// The last reading, or a new one where that is due: every ten minutes.
    fn known(&self, context: &Context<'_>) -> Kept<Read> {
        let problem = |problem: String| Read {
            problem: Some(problem),
            ..Read::default()
        };
        cached(
            context,
            MEMORY,
            |_, _| EVERY,
            |_| match reading(&context.events_database, Duration::from_secs(2)) {
                Ok(Some(db)) => self
                    .read(&db, context.now.as_second())
                    .unwrap_or_else(|error| {
                        problem(format!("the event history could not be read: {error}"))
                    }),
                Ok(None) => problem("no events are recorded yet".to_owned()),
                Err(error) => problem(format!("the event history could not be opened: {error}")),
            },
        )
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
        let kept = self.known(context);
        let read = &kept.answer;
        let unusual: Vec<&Sender> = read
            .senders
            .iter()
            .filter(|sender| !sender.reasons.is_empty())
            .collect();
        let mut findings: Vec<String> = unusual
            .iter()
            .take(5)
            .map(|sender| format!("{}: {}.", sender.address, sender.reasons.join("; ")))
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
        if read.truncated {
            findings.push("More mail was handed in than is counted here.".to_owned());
        }
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
            rows: read
                .senders
                .iter()
                .take(ROWS)
                .map(|sender| {
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
