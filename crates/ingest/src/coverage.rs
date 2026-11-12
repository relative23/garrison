//! What the event history covers: since when it is recorded, where it
//! begins, where events may be missing inside it, and whether the receiver is
//! alive. The web service shows this above every view of the history.

use rusqlite::{Connection, OptionalExtension};

use crate::answers::{Coverage, Gap, Limit, Receiver, Trimmed};
use crate::queries::{QueryError, Result};
use crate::store::{EVENT_LIMIT, STORAGE_BUDGET};

pub const LIMITATIONS: [&str; 3] = [
    "Only events recorded after the webhook was enabled are available; earlier activity \
     cannot be reconstructed.",
    "Queue completion means a receiving server accepted the message, not inbox placement.",
    "Sessions group events by Stalwart's span ID; only SMTP session milestones are recorded.",
];

/// A number the receiver keeps about itself, or `None` before it wrote one.
fn meta(db: &Connection, key: &str) -> Result<Option<i64>> {
    let text: Option<String> = db
        .query_row("SELECT value FROM metadata WHERE key=?", [key], |row| {
            row.get(0)
        })
        .optional()?;
    match text {
        Some(text) => serde_json::from_str(&text).map_err(|_| QueryError::Invalid),
        None => Ok(None),
    }
}

/// Where a size limit made the history begin. The store keeps one window per
/// limit; the one that ends last decides.
fn trimmed(db: &Connection) -> Result<Option<Trimmed>> {
    let window: Option<(i64, String)> = db
        .query_row(
            "SELECT end_at,reason FROM gaps WHERE reason IN (?,?) ORDER BY end_at DESC LIMIT 1",
            [EVENT_LIMIT, STORAGE_BUDGET],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(window.map(|(until, reason)| Trimmed {
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
            retention_days: None,
            event_count: 0,
            trimmed: None,
            gap_count: 0,
            gaps: Vec::new(),
            limitations: LIMITATIONS.to_vec(),
        });
    };
    let total: i64 = db.query_row("SELECT count(*) FROM events", [], |row| row.get(0))?;
    let heartbeat = meta(db, "heartbeatAt")?;
    // A window of a size limit lies before the history, not inside it.
    let mut statement = db.prepare(
        "SELECT start_at,end_at,reason FROM gaps WHERE reason NOT IN (?,?) \
         ORDER BY end_at DESC LIMIT 20",
    )?;
    let gaps = statement
        .query_map([EVENT_LIMIT, STORAGE_BUDGET], |row| {
            Ok(Gap {
                start: row.get(0)?,
                end: row.get(1)?,
                reason: row.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let gap_count: i64 = db.query_row(
        "SELECT count(*) FROM gaps WHERE reason NOT IN (?,?)",
        [EVENT_LIMIT, STORAGE_BUDGET],
        |row| row.get(0),
    )?;
    // The receiver writes a heartbeat every 30 seconds while it runs.
    let running = heartbeat.is_some_and(|beat| now - beat <= 90);
    Ok(Coverage {
        available: true,
        receiver: if running {
            Receiver::Running
        } else {
            Receiver::Stale
        },
        heartbeat_at: heartbeat,
        recording_since: meta(db, "recordingSince")?,
        last_batch_at: meta(db, "lastBatchAt")?,
        retention_days: meta(db, "retentionDays")?,
        event_count: total,
        trimmed: trimmed(db)?,
        gap_count,
        gaps,
        limitations: LIMITATIONS.to_vec(),
    })
}

#[cfg(test)]
mod tests;
