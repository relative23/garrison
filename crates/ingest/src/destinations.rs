//! Delivery problems by destination: where outgoing mail is delayed or
//! bounces, and why, summed over a stretch of the event history, with the
//! messages that still wait.
//!
//! The list of deliveries shows one message at a time. This summary answers
//! the question behind a complaint: is one domain refusing our mail, is one
//! cause behind many failures, and how long has the oldest message waited.
//! Deliveries into this server's own mailboxes are left out.

use std::collections::{BTreeSet, HashMap};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::event_type::EventType;
use crate::queries::Result;

/// The newest events of one type that are read.
pub const MAX_EVENTS: usize = 100_000;
/// The rows of each list.
pub const MAX_ROWS: usize = 50;
const MAX_CAUSE: usize = 120;
/// A message that neither completed nor failed for good counts as waiting
/// for this long after it was queued; Stalwart gives up on older ones.
const LONGEST_WAIT: i64 = 7 * 86_400;
const FINISHED: [EventType; 3] = [
    EventType::DeliveryCompleted,
    EventType::DeliveryFailed,
    EventType::DeliveryDoubleBounce,
];

/// One domain mail was sent to and had a problem with.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Destination {
    pub domain: String,
    /// Recipients a server of the domain accepted.
    pub delivered: u64,
    /// Attempts that ended with a temporary failure.
    pub delays: u64,
    /// Recipients that failed for good.
    pub bounces: u64,
    pub last_problem: i64,
    /// The cause named most often, shortened.
    pub cause: String,
    /// The hosts of the domain that were tried.
    pub hosts: Vec<String>,
}

/// One cause of delays or bounces, as the events word it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cause {
    pub cause: String,
    pub delays: u64,
    pub bounces: u64,
    /// The domains it was seen at.
    pub domains: u64,
    pub last_seen: i64,
}

/// A queued message without a recorded end.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Waiting {
    pub queue_id: String,
    pub queued_at: i64,
    pub last_event: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Totals {
    pub delivered: u64,
    pub delays: u64,
    pub bounces: u64,
    /// Domains with a delay or a bounce, also beyond the rows of the list.
    pub destinations: u64,
    pub waiting: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Destinations {
    pub since: i64,
    pub until: i64,
    /// More events of a type were recorded in the stretch than were read.
    pub truncated: bool,
    pub totals: Totals,
    /// Domains with problems, those with most first.
    pub destinations: Vec<Destination>,
    pub causes: Vec<Cause>,
    /// The messages that wait longest first.
    pub waiting: Vec<Waiting>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fields {
    to: Option<serde_json::Value>,
    hostname: Option<serde_json::Value>,
    details: Option<String>,
    queue_name: Option<String>,
}

/// The domain of an address, in lower case; `None` for text without one.
pub fn domain(address: &str) -> Option<String> {
    let (_, domain) = address.trim_matches(['<', '>']).rsplit_once('@')?;
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// A cause without what differs from message to message: addresses, queue
/// identifiers and long numbers go, so that one cause is one row.
pub fn cause(details: &str) -> String {
    let words: Vec<&str> = details
        .split_whitespace()
        .filter(|word| {
            let digits = word.bytes().filter(u8::is_ascii_digit).count();
            // An identifier: more than five digits, and mostly digits.
            let identifier = digits > 5 && digits * 2 > word.len();
            !word.contains('@') && !identifier
        })
        .collect();
    let text = words.join(" ");
    let text = text.trim_end_matches(['.', ':', ' ']);
    if text.is_empty() {
        "No cause recorded".to_owned()
    } else {
        text.chars().take(MAX_CAUSE).collect()
    }
}

#[derive(Default)]
struct Seen {
    destination: Destination,
    causes: HashMap<String, u64>,
    hosts: BTreeSet<String>,
}

#[derive(Default)]
struct Named {
    cause: Cause,
    domains: BTreeSet<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Delivered,
    Delay,
    Bounce,
}

#[derive(Default)]
struct Sums {
    truncated: bool,
    totals: Totals,
    domains: HashMap<String, Seen>,
    causes: HashMap<String, Named>,
}

impl Sums {
    fn read(
        &mut self,
        db: &Connection,
        kind: EventType,
        stretch: (i64, i64),
        outcome: Outcome,
    ) -> Result<()> {
        let mut statement = db.prepare_cached(
            "SELECT created_at,fields FROM events WHERE type=?1 AND created_at>=?2 \
             AND created_at<=?3 ORDER BY seq DESC LIMIT ?4",
        )?;
        let limit = i64::try_from(MAX_EVENTS + 1).unwrap_or(i64::MAX);
        let mut rows = statement.query((kind.as_str(), stretch.0, stretch.1, limit))?;
        let mut read = 0;
        while let Some(row) = rows.next()? {
            if read == MAX_EVENTS {
                self.truncated = true;
                break;
            }
            read += 1;
            let at: i64 = row.get(0)?;
            let text: String = row.get(1)?;
            let Ok(fields) = serde_json::from_str::<Fields>(&text) else {
                continue;
            };
            // Mail for this server's own mailboxes has no destination to judge.
            if fields.queue_name.as_deref() == Some("local") {
                continue;
            }
            let recipients = texts(fields.to.as_ref());
            let hosts = texts(fields.hostname.as_ref());
            for recipient in &recipients {
                if let Some(domain) = domain(recipient) {
                    self.count(&domain, at, outcome, fields.details.as_deref(), &hosts);
                }
            }
        }
        Ok(())
    }

    fn count(
        &mut self,
        domain: &str,
        at: i64,
        outcome: Outcome,
        details: Option<&str>,
        hosts: &[String],
    ) {
        let seen = self.domains.entry(domain.to_owned()).or_default();
        seen.hosts.extend(hosts.iter().cloned());
        let destination = &mut seen.destination;
        match outcome {
            Outcome::Delivered => {
                self.totals.delivered += 1;
                destination.delivered += 1;
                return;
            }
            Outcome::Delay => {
                self.totals.delays += 1;
                destination.delays += 1;
            }
            Outcome::Bounce => {
                self.totals.bounces += 1;
                destination.bounces += 1;
            }
        }
        destination.last_problem = destination.last_problem.max(at);
        let cause = cause(details.unwrap_or_default());
        *seen.causes.entry(cause.clone()).or_default() += 1;
        let named = self.causes.entry(cause).or_default();
        if outcome == Outcome::Delay {
            named.cause.delays += 1;
        } else {
            named.cause.bounces += 1;
        }
        named.cause.last_seen = named.cause.last_seen.max(at);
        named.domains.insert(domain.to_owned());
    }
}

/// A field that holds one text or a list of them.
fn texts(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::String(text)) => vec![text.clone()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The messages queued within the longest wait before `until` that no event
/// ended, oldest first, and how many there are.
fn waiting(db: &Connection, until: i64) -> Result<(u64, Vec<Waiting>)> {
    let finished: Vec<String> = FINISHED
        .iter()
        .map(|kind| format!("'{}'", kind.as_str()))
        .collect();
    let open = format!(
        "FROM queues q WHERE q.first_seen>=?1 AND q.first_seen<=?2 AND NOT EXISTS \
         (SELECT 1 FROM events e WHERE e.queue_id=q.queue_id AND e.type IN ({}))",
        finished.join(",")
    );
    let stretch = (until - LONGEST_WAIT, until);
    let count: i64 = db.query_row(&format!("SELECT count(*) {open}"), stretch, |row| {
        row.get(0)
    })?;
    let mut statement = db.prepare(&format!(
        "SELECT q.queue_id,q.first_seen,q.last_seen {open} ORDER BY q.first_seen,q.queue_id LIMIT {MAX_ROWS}"
    ))?;
    let rows = statement.query_map(stretch, |row| {
        Ok(Waiting {
            queue_id: row.get(0)?,
            queued_at: row.get(1)?,
            last_event: row.get(2)?,
        })
    })?;
    let waiting = rows.collect::<rusqlite::Result<Vec<Waiting>>>()?;
    Ok((u64::try_from(count).unwrap_or(0), waiting))
}

/// Deliveries, delays and bounces between `since` and `until` by the domain
/// they went to and by their cause, and the messages that wait at `until`.
pub fn destinations(db: &Connection, since: i64, until: i64) -> Result<Destinations> {
    let mut sums = Sums::default();
    let stretch = (since, until);
    sums.read(
        db,
        EventType::DeliveryDsnSuccess,
        stretch,
        Outcome::Delivered,
    )?;
    sums.read(db, EventType::DeliveryDsnTempFail, stretch, Outcome::Delay)?;
    sums.read(db, EventType::DeliveryDsnPermFail, stretch, Outcome::Bounce)?;
    let mut destinations: Vec<Destination> = sums
        .domains
        .into_iter()
        .filter(|(_, seen)| seen.destination.delays + seen.destination.bounces > 0)
        .map(|(domain, seen)| {
            // The cause named most often; among equals the first by name.
            let mut causes: Vec<(String, u64)> = seen.causes.into_iter().collect();
            causes.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
            Destination {
                domain,
                cause: causes
                    .into_iter()
                    .next()
                    .map(|(cause, _)| cause)
                    .unwrap_or_default(),
                hosts: seen.hosts.into_iter().take(3).collect(),
                ..seen.destination
            }
        })
        .collect();
    let mut totals = sums.totals;
    totals.destinations = destinations.len() as u64;
    destinations.sort_by(|left, right| {
        (right.bounces + right.delays, right.last_problem)
            .cmp(&(left.bounces + left.delays, left.last_problem))
            .then_with(|| left.domain.cmp(&right.domain))
    });
    destinations.truncate(MAX_ROWS);
    let mut causes: Vec<Cause> = sums
        .causes
        .into_iter()
        .map(|(cause, named)| Cause {
            cause,
            domains: named.domains.len() as u64,
            ..named.cause
        })
        .collect();
    causes.sort_by(|left, right| {
        (right.bounces + right.delays, right.last_seen)
            .cmp(&(left.bounces + left.delays, left.last_seen))
            .then_with(|| left.cause.cmp(&right.cause))
    });
    causes.truncate(MAX_ROWS);
    let (count, waiting) = waiting(db, until)?;
    totals.waiting = count;
    Ok(Destinations {
        since,
        until,
        truncated: sums.truncated,
        totals,
        destinations,
        causes,
        waiting,
    })
}

#[cfg(test)]
mod tests;
