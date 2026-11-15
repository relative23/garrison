//! What the event history covers: since when it is recorded, where it
//! begins, where events may be missing inside it, and whether the receiver is
//! alive. The web service shows this above every view of the history.

use garrison_core::recording::{
    self, EVENT_LIMIT, FAILING_SINCE, HEARTBEAT_AT, LAST_BATCH_AT, RECORDING_SINCE, RETENTION_DAYS,
};
use rusqlite::Connection;

use crate::answers::{Coverage, Gap, Limit, Receiver, Trimmed};
use crate::queries::{QueryError, Result};

pub const LIMITATIONS: [&str; 3] = [
    "Only events recorded after the webhook was enabled are available; earlier activity \
     cannot be reconstructed.",
    "Queue completion means a receiving server accepted the message, not inbox placement.",
    "Sessions group events by Stalwart's span ID; only SMTP session milestones are recorded.",
];

/// The newest windows of lost events that the answer lists.
const LISTED_GAPS: u32 = 20;

impl From<recording::Error> for QueryError {
    fn from(error: recording::Error) -> Self {
        match error {
            recording::Error::Invalid => QueryError::Unreadable(
                "A number the event receiver keeps about the history cannot be read".to_owned(),
            ),
            recording::Error::Sqlite(error) => QueryError::Sqlite(error),
        }
    }
}

/// A number the receiver keeps about itself, or `None` before it wrote one.
fn meta(db: &Connection, key: &str) -> Result<Option<i64>> {
    Ok(recording::number(db, key)?)
}

/// A time the receiver keeps about itself; one that is no time, in a
/// damaged history, cannot be read.
fn moment(db: &Connection, key: &str) -> Result<Option<i64>> {
    Ok(recording::time_of(db, key)?)
}

/// Where a size limit made the history begin.
fn trimmed(db: &Connection) -> Result<Option<Trimmed>> {
    Ok(recording::trimmed(db)?.map(|(until, reason)| Trimmed {
        until,
        limit: if reason == EVENT_LIMIT {
            Limit::Events
        } else {
            Limit::Bytes
        },
    }))
}

/// What the history covers, and whether the receiver is alive.
pub fn read(db: Option<&Connection>, now: i64) -> Result<Coverage> {
    let Some(db) = db else {
        return Ok(Coverage {
            available: false,
            receiver: Receiver::Unavailable,
            heartbeat_at: None,
            recording_since: None,
            last_batch_at: None,
            failing_since: None,
            retention_days: None,
            event_count: 0,
            trimmed: None,
            gap_count: 0,
            gaps: Vec::new(),
            limitations: LIMITATIONS.to_vec(),
        });
    };
    let total: i64 = db.query_row("SELECT count(*) FROM events", [], |row| row.get(0))?;
    let heartbeat = moment(db, HEARTBEAT_AT)?;
    let gaps = recording::gaps(db, LISTED_GAPS)?
        .into_iter()
        .map(|recording::Gap { start, end, reason }| Gap { start, end, reason })
        .collect();
    let gap_count = recording::gap_count(db)?;
    // The receiver writes a heartbeat every 30 seconds while it runs. One
    // that runs may still store nothing: it keeps since when.
    let running = heartbeat.is_some_and(|beat| now - beat <= 90);
    let failing_since = meta(db, FAILING_SINCE)?;
    Ok(Coverage {
        available: true,
        receiver: match (running, failing_since) {
            (false, _) => Receiver::Stale,
            (true, Some(_)) => Receiver::Refusing,
            (true, None) => Receiver::Running,
        },
        failing_since,
        heartbeat_at: heartbeat,
        recording_since: meta(db, RECORDING_SINCE)?,
        last_batch_at: meta(db, LAST_BATCH_AT)?,
        retention_days: meta(db, RETENTION_DAYS)?,
        event_count: total,
        trimmed: trimmed(db)?,
        gap_count,
        gaps,
        limitations: LIMITATIONS.to_vec(),
    })
}

#[cfg(test)]
mod tests;
