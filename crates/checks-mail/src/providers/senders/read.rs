//! Reading the last 15 days of the event history for the sending addresses:
//! what was handed in under each address, and the bounces of the last day.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::Connection;
use serde_json::Value;

use super::{BOUNCED, DAY, KNOWN_DAYS, MAX_EVENTS, QUEUED, Read, Sender, Senders, USUAL_DAYS};
use crate::providers::history;

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
    /// Read the last 15 days of the history at `now`.
    pub(super) fn read(db: &Connection, now: i64) -> rusqlite::Result<Read> {
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
        let senders: Vec<Sender> = sums
            .into_iter()
            .filter(|(_, sums)| sums.messages > 0)
            .map(|(address, sums)| Sender {
                address,
                messages: sums.messages,
                recipients: sums.recipients,
                usual: (known >= KNOWN_DAYS)
                    .then(|| sums.before / u64::try_from(known).unwrap_or(1).max(1)),
                busiest_hour: sums.hours.values().copied().max().unwrap_or(0),
                bounces: sums.bounces,
                clients: sums.clients.len() as u64,
            })
            .collect();
        Ok(Read {
            senders,
            truncated,
            problem: None,
            uncovered,
            unusual_unknown,
        })
    }
}
