//! Reading the last 15 days of the event history for the sending addresses:
//! what was handed in under each address, and the bounces of the last day.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::Connection;
use rusqlite::types::ValueRef;
use serde_json::Value;

use super::{BOUNCED, Cut, DAY, KNOWN_DAYS, QUEUED, Read, Sender, Senders, USUAL_DAYS};
use crate::providers::history;

#[derive(Default)]
struct Sums {
    messages: u64,
    recipients: u64,
    /// The recipients of each day before the last one, the day before it 1.
    before: BTreeMap<i64, u64>,
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

/// A row's time and fields, where both are as the receiver writes them.
fn readable(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<(i64, Value)>> {
    Ok(match (row.get_ref(1)?, history::fields(row.get_ref(2)?)) {
        (ValueRef::Integer(at), Some(fields)) => Some((at, fields)),
        _ => None,
    })
}

fn recipients(fields: &Value) -> u64 {
    match &fields["to"] {
        Value::Array(items) => items.len() as u64,
        Value::String(_) => 1,
        _ => 0,
    }
}

impl Senders {
    /// Read the last 15 days of the history at `now`, the newest `most`
    /// submissions of them and as many bounces.
    pub(super) fn read(db: &Connection, now: i64, most: usize) -> rusqlite::Result<Read> {
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
        let begins = Self::begins(db)?;
        // The whole days before the last one that the history holds.
        let known = begins.map_or(0, |begins| (today - begins.max(since)) / DAY);
        let known = if unusual_unknown.is_some() { 0 } else { known };
        let mut sums: HashMap<String, Sums> = HashMap::new();
        let limit = i64::try_from(most + 1).unwrap_or(i64::MAX);
        // A time that is no number sorts above every number: such an event
        // is read, to be counted as left out.
        let mut statement = db.prepare(
            "SELECT seq,created_at,fields FROM events WHERE type=?1 AND created_at>=?2 \
             AND (created_at<=?3 OR typeof(created_at) IN ('text','blob')) ORDER BY seq DESC \
             LIMIT ?4",
        )?;
        let mut unreadable = 0;
        // The number of the oldest submission read, where there are more.
        let mut left_below = None;
        let mut oldest = None;
        let mut rows = statement.query((QUEUED, since, now, limit))?;
        let mut read = 0;
        while let Some(row) = rows.next()? {
            if read == most {
                left_below = oldest;
                break;
            }
            read += 1;
            let seq: i64 = row.get(0)?;
            oldest = Some(seq);
            let Some((at, fields)) = readable(row)? else {
                unreadable += 1;
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
                *entry.before.entry((today - at - 1) / DAY + 1).or_default() += count;
            }
        }
        drop(rows);
        let cut = match left_below {
            Some(seq) => Some(Self::read_whole(db, (since, today, now), seq)?),
            None => None,
        }
        // A cut that took no whole day the history holds took nothing of
        // the usual volume.
        .filter(|cut| !cut.last_day || cut.days < known);
        // The usual volume is of whole days that the history holds and that
        // were read.
        let days = cut.as_ref().map_or(known, |cut| cut.days);
        let (bounces_cut, unread_bounces) =
            Self::bounces(&mut statement, (today, now), most, &mut sums)?;
        unreadable += unread_bounces;
        let senders: Vec<Sender> = sums
            .into_iter()
            .filter(|(_, sums)| sums.messages > 0)
            .map(|(address, sums)| Sender {
                address,
                messages: sums.messages,
                recipients: sums.recipients,
                usual: (days >= KNOWN_DAYS).then(|| {
                    let recipients: u64 = sums.before.range(1..=days).map(|(_, count)| count).sum();
                    recipients / u64::try_from(days).unwrap_or(1).max(1)
                }),
                busiest_hour: sums.hours.values().copied().max().unwrap_or(0),
                bounces: sums.bounces,
                clients: sums.clients.len() as u64,
            })
            .collect();
        Ok(Read {
            senders,
            cut,
            bounces_cut,
            problem: None,
            uncovered,
            unusual_unknown,
            unreadable,
        })
    }

    /// The bounces from `today` to `now`, at most `most`, counted to the
    /// senders in `sums` by `statement`; whether more came, and how many could
    /// not be read.
    fn bounces(
        statement: &mut rusqlite::Statement<'_>,
        (today, now): (i64, i64),
        most: usize,
        sums: &mut HashMap<String, Sums>,
    ) -> rusqlite::Result<(bool, u64)> {
        let limit = i64::try_from(most + 1).unwrap_or(i64::MAX);
        let mut rows = statement.query((BOUNCED, today, now, limit))?;
        let (mut bounced, mut unreadable) = (0, 0);
        while let Some(row) = rows.next()? {
            if bounced == most {
                return Ok((true, unreadable));
            }
            bounced += 1;
            let Some((_, fields)) = readable(row)? else {
                unreadable += 1;
                continue;
            };
            let sender = sender_address(&fields);
            if let Some(entry) = sender.and_then(|sender| sums.get_mut(&sender)) {
                entry.bounces += 1;
            }
        }
        Ok((false, unreadable))
    }

    /// The time of the history's oldest event, of those whose time is a
    /// whole second. The first look takes it from the index; only where that
    /// time is of another type is the history searched.
    fn begins(db: &Connection) -> rusqlite::Result<Option<i64>> {
        let oldest = db.query_row("SELECT MIN(created_at) FROM events", [], |row| {
            Ok(match row.get_ref(0)? {
                ValueRef::Integer(at) => Some(Some(at)),
                ValueRef::Null => Some(None),
                _ => None,
            })
        })?;
        match oldest {
            Some(oldest) => Ok(oldest),
            None => db.query_row(
                "SELECT MIN(created_at) FROM events WHERE typeof(created_at)='integer'",
                [],
                |row| row.get(0),
            ),
        }
    }

    /// What of the 15 days `since` to `now`, the last day from `today`, was
    /// read whole, where the submissions numbered below `seq` were not. The
    /// history is read by its numbers, which batches that come late put out
    /// of time's order, so the days read whole are those after the newest of
    /// the submissions left.
    fn read_whole(
        db: &Connection,
        (since, today, now): (i64, i64, i64),
        seq: i64,
    ) -> rusqlite::Result<Cut> {
        let left: Option<i64> = db.query_row(
            "SELECT MAX(CASE WHEN typeof(created_at)='integer' THEN created_at END) FROM events \
             WHERE type=?1 AND created_at>=?2 AND created_at<=?3 AND seq<?4",
            (QUEUED, since, now, seq),
            |row| row.get(0),
        )?;
        Ok(match left {
            Some(newest) if newest >= today => Cut {
                days: 0,
                last_day: false,
            },
            Some(newest) => Cut {
                days: ((today - newest - 1) / DAY).min(USUAL_DAYS),
                last_day: true,
            },
            None => Cut {
                days: USUAL_DAYS,
                last_day: true,
            },
        })
    }
}
