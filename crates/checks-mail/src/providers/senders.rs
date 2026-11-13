//! Sending accounts: what each signed-in account handed in during the last
//! day, against its own average of the two weeks before.
//!
//! An account whose password was guessed or stolen shows in what it sends:
//! many times its usual volume, a burst within one hour, or a large share of
//! recipients that do not exist. Each of these is a warning, with the account
//! and the figures; Garrison blocks nothing. The figures come from the event
//! history, read every ten minutes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Column, Evidence, Field, Format, Observation, State, Table};
use garrison_core::sqlite::reading;
use garrison_core::time;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::context::{Collected, Context, Provider, Report};
use crate::options::{Checked, Options};

const QUEUED: &str = "queue.authenticated-message-queued";
const BOUNCED: &str = "delivery.dsn-perm-fail";
const DAY: i64 = 86_400;
/// The days before the last one that make an account's usual volume, and how
/// many of them the history must hold before a usual volume is named.
const USUAL_DAYS: i64 = 14;
const KNOWN_DAYS: i64 = 3;
/// The history is read this often.
const EVERY: i64 = 600;
const MAX_EVENTS: usize = 200_000;
const ROWS: usize = 20;
const MEMORY: &str = "senders.accounts";
/// Bounces count once they are this share of an account's recipients.
const BOUNCE_SHARE: u64 = 5;

/// What one account sent in the last day.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
struct Sender {
    account: String,
    messages: u64,
    recipients: u64,
    /// Its recipients a day before that; `None` while the history is short.
    usual: Option<u64>,
    busiest_hour: u64,
    bounces: u64,
    /// The addresses it handed mail in from.
    addresses: u64,
    reasons: Vec<String>,
}

/// What the status database keeps of the last reading.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
struct Read {
    at: i64,
    senders: Vec<Sender>,
    /// More events were recorded than were read.
    truncated: bool,
    problem: Option<String>,
}

#[derive(Debug)]
pub struct Senders {
    modules: BTreeSet<ModuleId>,
    /// Below this many recipients in a day nothing counts as unusual.
    min_recipients: u64,
    /// So many times an account's usual volume is a warning.
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
    addresses: BTreeSet<String>,
    bounces: u64,
}

/// The account an event names as its sender, in lower case; `None` for a
/// bounce's empty sender.
fn account(fields: &Value) -> Option<String> {
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

    /// Why an account's day is unusual; nothing where it is not.
    fn reasons(&self, sender: &Sender) -> Vec<String> {
        let mut reasons = Vec::new();
        if let Some(usual) = sender.usual
            && sender.recipients >= self.min_recipients
            && sender.recipients >= self.factor.saturating_mul(usual.max(1))
        {
            reasons.push(if usual == 0 {
                format!(
                    "{} recipients in 24 hours from an account that sent nothing in the {USUAL_DAYS} days before",
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
        let begins: Option<i64> =
            db.query_row("SELECT MIN(created_at) FROM events", [], |row| row.get(0))?;
        // The whole days before the last one that the history holds.
        let known = begins.map_or(0, |begins| (today - begins.max(since)) / DAY);
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
            let Some(account) = account(&fields) else {
                continue;
            };
            let count = recipients(&fields);
            let entry = sums.entry(account).or_default();
            if at >= today {
                entry.messages += 1;
                entry.recipients += count;
                *entry.hours.entry((now - at) / 3600).or_default() += count;
                entry
                    .addresses
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
                .and_then(|fields| account(&fields));
            if let Some(entry) = sender.and_then(|sender| sums.get_mut(&sender)) {
                entry.bounces += 1;
            }
        }
        let mut senders: Vec<Sender> = sums
            .into_iter()
            .filter(|(_, sums)| sums.messages > 0)
            .map(|(account, sums)| {
                let mut sender = Sender {
                    account,
                    messages: sums.messages,
                    recipients: sums.recipients,
                    usual: (known >= KNOWN_DAYS)
                        .then(|| sums.before / u64::try_from(known).unwrap_or(1).max(1)),
                    busiest_hour: sums.hours.values().copied().max().unwrap_or(0),
                    bounces: sums.bounces,
                    addresses: sums.addresses.len() as u64,
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
                .then_with(|| left.account.cmp(&right.account))
        });
        Ok(Read {
            at: now,
            senders,
            truncated,
            problem: None,
        })
    }

    /// The last reading, or a new one where that is due.
    fn known(&self, context: &Context<'_>) -> Read {
        let now = context.now.as_second();
        let kept: Option<Read> = context
            .memory
            .recall(MEMORY)
            .and_then(|text| serde_json::from_str(&text).ok());
        if let Some(kept) = kept.filter(|kept| (0..EVERY).contains(&(now - kept.at))) {
            return kept;
        }
        let read = match reading(&context.events_database, Duration::from_secs(2)) {
            Ok(Some(db)) => self.read(&db, now).unwrap_or_else(|error| Read {
                at: now,
                problem: Some(format!("the event history could not be read: {error}")),
                ..Read::default()
            }),
            Ok(None) => Read {
                at: now,
                problem: Some("no events are recorded yet".to_owned()),
                ..Read::default()
            },
            Err(error) => Read {
                at: now,
                problem: Some(format!("the event history could not be opened: {error}")),
                ..Read::default()
            },
        };
        if let Ok(text) = serde_json::to_string(&read) {
            context.memory.keep(MEMORY, &text);
        }
        read
    }
}

impl Provider for Senders {
    fn name(&self) -> &'static str {
        "senders"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let read = self.known(context);
        let unusual: Vec<&Sender> = read
            .senders
            .iter()
            .filter(|sender| !sender.reasons.is_empty())
            .collect();
        let mut findings: Vec<String> = unusual
            .iter()
            .take(5)
            .map(|sender| format!("{}: {}.", sender.account, sender.reasons.join("; ")))
            .collect();
        if unusual.len() > 5 {
            findings.push(format!("And {} more accounts.", unusual.len() - 5));
        }
        let state = match (&read.problem, unusual.is_empty()) {
            (Some(problem), _) => {
                findings = vec![format!("The sending accounts are not known: {problem}.")];
                State::Unknown
            }
            (None, false) => State::Warning,
            (None, true) => State::Ok,
        };
        if read.truncated {
            findings.push("More mail was handed in than is counted here.".to_owned());
        }
        let column = |label: &str, format| Column {
            label: label.to_owned(),
            format,
        };
        let at = time::Timestamp::from_second(read.at)
            .ok()
            .map(time::isoformat);
        let observation = Observation::new(
            "senders.accounts",
            self.name(),
            "Sending accounts",
            self.modules.iter().copied(),
            Evidence::Probe,
            state,
            context.checked_at(),
            "event history",
        )?
        .with_scope(
            "Mail that signed-in accounts handed in during the last 24 hours, against each \
             account's own average of the 14 days before. Read every ten minutes; nothing is blocked.",
        )
        .with_fields(vec![
            Field::new("Accounts that sent", read.senders.len(), Format::Number),
            Field::new("Unusual", unusual.len(), Format::Number),
            Field::new("Read", at, Format::Datetime),
        ])
        .with_table(Table {
            columns: vec![
                column("Account", Format::Text),
                column("Messages", Format::Number),
                column("Recipients", Format::Number),
                column("Usual a day", Format::Number),
                column("Busiest hour", Format::Number),
                column("Bounces", Format::Number),
                column("Addresses", Format::Number),
            ],
            rows: read
                .senders
                .iter()
                .take(ROWS)
                .map(|sender| {
                    vec![
                        json!(sender.account),
                        json!(sender.messages),
                        json!(sender.recipients),
                        json!(sender.usual),
                        json!(sender.busiest_hour),
                        json!(sender.bounces),
                        json!(sender.addresses),
                    ]
                })
                .collect(),
        })
        .with_findings(findings)
        .with_max_age(180);
        Ok(Report::of(observation))
    }
}

#[cfg(test)]
mod tests;
