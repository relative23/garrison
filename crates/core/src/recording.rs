//! What the event receiver records about its own recording.
//!
//! Beside the events, the events database holds when the receiver last ran
//! (it writes a heartbeat every 30 seconds), since when it records, and the
//! windows in which events were lost. The receiver alone writes these, in
//! its own transactions. Everyone who reads the history asks here what it
//! covers: the web service above every view of it, and the checks before
//! they take a quiet history for a quiet server.

use std::fmt;

use rusqlite::{Connection, OptionalExtension, params};

use crate::time;

/// The two tables this module reads, as the receiver creates them.
pub const GAPS_TABLE: &str = "CREATE TABLE gaps(
        id INTEGER PRIMARY KEY,
        start_at INTEGER NOT NULL,
        end_at INTEGER NOT NULL,
        reason TEXT NOT NULL
    )";
pub const METADATA_TABLE: &str = "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)";

/// When the receiver last ran: written at its start, every 30 seconds while
/// it runs, and with every batch.
pub const HEARTBEAT_AT: &str = "heartbeatAt";
pub const RECORDING_SINCE: &str = "recordingSince";
pub const LAST_BATCH_AT: &str = "lastBatchAt";
pub const RETENTION_DAYS: &str = "retentionDays";

/// Since when the receiver runs but stores no batch whole, while that
/// lasts, and why (1: batches refused, 2: events that cannot be read).
pub const FAILING_SINCE: &str = "failingSince";
pub const FAILING_KIND: &str = "failingKind";

/// The reasons a window in `gaps` may lack events. The receiver was away for
/// longer than Stalwart keeps undelivered events.
pub const OFFLINE: &str = "receiver-offline";
/// The receiver ran and refused Stalwart's batches for longer than Stalwart
/// keeps them: the signature key did not match, or storing failed.
pub const REFUSED: &str = "batches-refused";
/// Events of a recorded type arrived in a form the receiver could not read,
/// or dated as no event that arrives then can be.
pub const UNREADABLE: &str = "events-unreadable";
/// The oldest events were removed to keep the event limit.
pub const EVENT_LIMIT: &str = "capacity-events";
/// The oldest events were removed to keep the storage budget.
pub const STORAGE_BUDGET: &str = "capacity-bytes";

/// A check takes the receiver for away once its heartbeat is older than
/// this: ten heartbeats, so a restart of the receiver passes unnoticed.
pub const QUIET_AFTER: i64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A value the receiver keeps about itself is not what it writes.
    #[error("a value the event receiver keeps about itself cannot be read")]
    Invalid,
    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// A number the receiver keeps about itself, or `None` before it wrote one.
pub fn number(db: &Connection, key: &str) -> Result<Option<i64>, Error> {
    let text: Option<String> = db
        .query_row("SELECT value FROM metadata WHERE key=?", [key], |row| {
            row.get(0)
        })
        .optional()?;
    match text {
        Some(text) => serde_json::from_str(&text).map_err(|_| Error::Invalid),
        None => Ok(None),
    }
}

/// A time the receiver keeps about itself, in seconds, or `None` before it
/// wrote one. It writes its clock's seconds, so a number that is no time, as
/// a damaged or hand-edited database may hold, is not what it writes.
pub fn time_of(db: &Connection, key: &str) -> Result<Option<i64>, Error> {
    match number(db, key)? {
        Some(second) if time::Timestamp::from_second(second).is_err() => Err(Error::Invalid),
        known => Ok(known),
    }
}

/// Keep a number about the recording. Only the receiver calls this, inside
/// the transaction that it belongs to.
pub fn set(db: &Connection, key: &str, value: i64) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value.to_string()],
    )?;
    Ok(())
}

/// A window in which events may be missing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gap {
    pub start: i64,
    pub end: i64,
    pub reason: String,
}

/// The newest windows inside the history in which events were lost, at most
/// `limit` of them. A window of a size limit lies before the history, not
/// inside it, and is not among them.
pub fn gaps(db: &Connection, limit: u32) -> rusqlite::Result<Vec<Gap>> {
    let mut statement = db.prepare(
        "SELECT start_at,end_at,reason FROM gaps WHERE reason NOT IN (?,?) \
         ORDER BY end_at DESC LIMIT ?",
    )?;
    statement
        .query_map(params![EVENT_LIMIT, STORAGE_BUDGET, limit], |row| {
            Ok(Gap {
                start: row.get(0)?,
                end: row.get(1)?,
                reason: row.get(2)?,
            })
        })?
        .collect()
}

/// How many windows inside the history lack events.
pub fn gap_count(db: &Connection) -> rusqlite::Result<i64> {
    db.query_row(
        "SELECT count(*) FROM gaps WHERE reason NOT IN (?,?)",
        [EVENT_LIMIT, STORAGE_BUDGET],
        |row| row.get(0),
    )
}

/// Where a size limit made the history begin, and which limit: the store
/// keeps one window per limit, and the one that ends last decides.
pub fn trimmed(db: &Connection) -> rusqlite::Result<Option<(i64, String)>> {
    db.query_row(
        "SELECT end_at,reason FROM gaps WHERE reason IN (?,?) ORDER BY end_at DESC LIMIT 1",
        [EVENT_LIMIT, STORAGE_BUDGET],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

/// Why the history cannot stand for a stretch of time up to now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uncovered {
    /// The receiver has not reported since then, or never: what happened
    /// after is not in the history, or not yet.
    Quiet { since: Option<i64> },
    /// Events of this window were lost while the receiver was away.
    Lost { start: i64, end: i64 },
    /// The receiver runs, but has stored no batch whole since then.
    Refusing { since: i64 },
}

fn moment(second: i64) -> String {
    time::Timestamp::from_second(second).map_or_else(|_| second.to_string(), time::isoformat)
}

impl fmt::Display for Uncovered {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Uncovered::Quiet { since: Some(since) } => write!(
                formatter,
                "the event receiver has not reported since {}",
                moment(*since)
            ),
            Uncovered::Quiet { since: None } => {
                write!(formatter, "the event receiver has never reported")
            }
            Uncovered::Lost { start, end } => write!(
                formatter,
                "events between {} and {} were lost while the event receiver was away",
                moment(*start),
                moment(*end)
            ),
            Uncovered::Refusing { since } => write!(
                formatter,
                "the event receiver runs, but has not stored Stalwart's events since {}",
                moment(*since)
            ),
        }
    }
}

/// Whether the history holds what happened from `since` until `now`: the
/// receiver reported within `patience` seconds, and no window of lost events
/// reaches into that time. `None` says it does. A history that only begins
/// after `since`, because recording began then or a size limit removed what
/// was before, is not judged here: it is complete from where it begins. A
/// heartbeat at no time is an error: neither a report nor a silence.
pub fn uncovered(
    db: &Connection,
    since: i64,
    now: i64,
    patience: i64,
) -> Result<Option<Uncovered>, Error> {
    let heartbeat = time_of(db, HEARTBEAT_AT)?;
    if heartbeat.is_none_or(|beat| now - beat > patience) {
        return Ok(Some(Uncovered::Quiet { since: heartbeat }));
    }
    if let Some(since) = number(db, FAILING_SINCE)? {
        return Ok(Some(Uncovered::Refusing { since }));
    }
    let lost: Option<(i64, i64)> = db
        .query_row(
            "SELECT start_at,end_at FROM gaps WHERE reason NOT IN (?1,?2) \
             AND end_at>?3 AND start_at<?4 ORDER BY end_at DESC LIMIT 1",
            params![EVENT_LIMIT, STORAGE_BUDGET, since, now],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(lost.map(|(start, end)| Uncovered::Lost { start, end }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_794_571_200;
    const DAY: i64 = 86_400;

    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(&format!("{GAPS_TABLE};{METADATA_TABLE};"))
            .unwrap();
        db
    }

    fn gap(db: &Connection, start: i64, end: i64, reason: &str) {
        db.execute(
            "INSERT INTO gaps(start_at,end_at,reason) VALUES(?,?,?)",
            params![start, end, reason],
        )
        .unwrap();
    }

    fn week(db: &Connection) -> Option<Uncovered> {
        uncovered(db, NOW - 7 * DAY, NOW, QUIET_AFTER).unwrap()
    }

    #[test]
    fn a_receiver_that_reported_lately_covers_the_time_without_lost_events() {
        let db = database();
        // Never: a database the receiver made and then did not start on.
        assert_eq!(week(&db), Some(Uncovered::Quiet { since: None }));
        set(&db, HEARTBEAT_AT, NOW - QUIET_AFTER).unwrap();
        assert_eq!(week(&db), None);
        set(&db, HEARTBEAT_AT, NOW - QUIET_AFTER - 1).unwrap();
        assert_eq!(
            week(&db),
            Some(Uncovered::Quiet {
                since: Some(NOW - QUIET_AFTER - 1)
            })
        );
        assert_eq!(number(&db, HEARTBEAT_AT).unwrap(), Some(NOW - 301));
        assert_eq!(number(&db, LAST_BATCH_AT).unwrap(), None);
    }

    #[test]
    fn lost_events_inside_the_time_asked_about_leave_it_uncovered() {
        let db = database();
        set(&db, HEARTBEAT_AT, NOW).unwrap();
        // Before the week, and what a size limit removed: not inside it.
        gap(&db, NOW - 10 * DAY, NOW - 8 * DAY, OFFLINE);
        gap(&db, NOW - 9 * DAY, NOW - DAY, EVENT_LIMIT);
        gap(&db, NOW - 9 * DAY, NOW - 2 * DAY, STORAGE_BUDGET);
        assert_eq!(week(&db), None);
        assert_eq!(gap_count(&db).unwrap(), 1);
        assert_eq!(
            trimmed(&db).unwrap(),
            Some((NOW - DAY, EVENT_LIMIT.to_owned()))
        );
        // One that ends inside the week, and one wholly inside it.
        gap(&db, NOW - 8 * DAY, NOW - 6 * DAY, OFFLINE);
        assert_eq!(
            week(&db),
            Some(Uncovered::Lost {
                start: NOW - 8 * DAY,
                end: NOW - 6 * DAY
            })
        );
        gap(&db, NOW - 2 * DAY, NOW - DAY, OFFLINE);
        assert_eq!(
            week(&db),
            Some(Uncovered::Lost {
                start: NOW - 2 * DAY,
                end: NOW - DAY
            })
        );
        // While the receiver runs and stores nothing, no time up to now is
        // covered, whatever its heartbeat says.
        set(&db, FAILING_SINCE, NOW - 60).unwrap();
        assert_eq!(
            uncovered(&db, NOW - DAY, NOW, QUIET_AFTER).unwrap(),
            Some(Uncovered::Refusing { since: NOW - 60 })
        );
        assert_eq!(
            Uncovered::Refusing { since: NOW }.to_string(),
            "the event receiver runs, but has not stored Stalwart's events since \
             2026-11-13T12:00:00+00:00"
        );
        db.execute("DELETE FROM metadata WHERE key='failingSince'", [])
            .unwrap();
        // The last day alone has none.
        assert_eq!(uncovered(&db, NOW - DAY, NOW, QUIET_AFTER).unwrap(), None);
        let listed = gaps(&db, 2).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].end, NOW - DAY);
        assert_eq!(listed[0].reason, OFFLINE);
        assert_eq!(gap_count(&db).unwrap(), 3);
    }

    #[test]
    fn the_reasons_read_as_a_finding_says_them() {
        assert_eq!(
            Uncovered::Quiet { since: Some(NOW) }.to_string(),
            "the event receiver has not reported since 2026-11-13T12:00:00+00:00"
        );
        assert_eq!(
            Uncovered::Quiet { since: None }.to_string(),
            "the event receiver has never reported"
        );
        assert_eq!(
            Uncovered::Lost {
                start: NOW,
                end: NOW + 3600
            }
            .to_string(),
            "events between 2026-11-13T12:00:00+00:00 and 2026-11-13T13:00:00+00:00 were lost \
             while the event receiver was away"
        );
    }

    /// A damaged or hand-edited database may hold a heartbeat at a time no
    /// clock gives: whether the history is current is then not known.
    #[test]
    fn a_heartbeat_at_no_time_leaves_the_history_not_known() {
        for beat in [i64::MIN, -377_705_023_202, 253_402_207_201, i64::MAX] {
            let db = database();
            set(&db, HEARTBEAT_AT, beat).unwrap();
            let judged = uncovered(&db, NOW - 7 * DAY, NOW, QUIET_AFTER);
            assert!(matches!(judged, Err(Error::Invalid)), "{beat}: {judged:?}");
            assert!(matches!(time_of(&db, HEARTBEAT_AT), Err(Error::Invalid)));
        }
        // The first and the last second a clock gives are times.
        for beat in [-377_705_023_201, 253_402_207_200] {
            let db = database();
            set(&db, HEARTBEAT_AT, beat).unwrap();
            assert_eq!(time_of(&db, HEARTBEAT_AT).unwrap(), Some(beat));
        }
        assert_eq!(time_of(&database(), HEARTBEAT_AT).unwrap(), None);
    }

    #[test]
    fn a_value_the_receiver_did_not_write_is_an_error_not_a_number() {
        let db = database();
        db.execute("INSERT INTO metadata VALUES('heartbeatAt','soon')", [])
            .unwrap();
        assert!(matches!(number(&db, HEARTBEAT_AT), Err(Error::Invalid)));
        assert!(matches!(
            uncovered(&db, 0, NOW, QUIET_AFTER),
            Err(Error::Invalid)
        ));
        // Without the tables there is nothing to read from.
        let empty = Connection::open_in_memory().unwrap();
        assert!(matches!(
            uncovered(&empty, 0, NOW, QUIET_AFTER),
            Err(Error::Sqlite(_))
        ));
    }
}
