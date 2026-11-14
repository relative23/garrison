//! The event history database. Only the ingest service writes it.
//!
//! Stalwart buffers undelivered webhook batches for `discardAfter`
//! milliseconds. If the receiver is down for longer, older buffered events are
//! lost; the store records that window as a gap instead of pretending the
//! history is complete.
//!
//! A size limit removes the oldest events before their retention ends. That
//! is no gap inside the history: the history begins later. The store keeps
//! one window per limit and widens it, so a reader finds where the history
//! begins and which limit moved it there.
//!
//! Retention and the limits go by the time an event says it happened, so
//! that time is believed only where it can be true of an event that arrives
//! now (`taking`).

use std::path::Path;
use std::sync::Mutex;

use garrison_core::config::Database;
use garrison_core::{recording, sqlite, time};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;

mod failing;
mod taking;

use failing::Failing;
use taking::{Arrival, Taken, insert};

pub use failing::Health;
pub use sqlite::SqliteError;

/// The schema version this release writes; `self-check` accepts up to it.
pub const SCHEMA_VERSION: usize = MIGRATIONS.len();

const MIGRATIONS: [sqlite::Migration; 1] = [&[
    "CREATE TABLE events(
        seq INTEGER PRIMARY KEY,
        event_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        received_at INTEGER NOT NULL,
        type TEXT NOT NULL,
        category TEXT NOT NULL,
        span_id TEXT,
        queue_id TEXT,
        fields TEXT NOT NULL,
        UNIQUE(event_id, created_at, type)
    )",
    "CREATE INDEX events_created ON events(created_at)",
    "CREATE INDEX events_queue ON events(queue_id, created_at) WHERE queue_id IS NOT NULL",
    "CREATE INDEX events_span ON events(span_id, created_at) WHERE span_id IS NOT NULL",
    // The events of a type in the order the lists show them, newest number
    // first, with their time: a page of one type is read from the index as
    // far as the page goes, with or without a time range.
    "CREATE INDEX events_type ON events(type, seq, created_at)",
    "CREATE TABLE queues(
        queue_id TEXT PRIMARY KEY,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        event_count INTEGER NOT NULL
    )",
    "CREATE INDEX queues_last ON queues(last_seen)",
    "CREATE TABLE spans(
        span_id TEXT PRIMARY KEY,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        event_count INTEGER NOT NULL,
        protocol TEXT NOT NULL
    )",
    "CREATE INDEX spans_last ON spans(last_seen)",
    // What the receiver records about its own recording; whoever reads the
    // history asks `garrison_core::recording` what it covers.
    recording::GAPS_TABLE,
    recording::METADATA_TABLE,
]];

/// The reasons a window in `gaps` may lack events.
pub use recording::{EVENT_LIMIT, OFFLINE, STORAGE_BUDGET};

const MAX_TIME_TEXT: usize = 40;
const MAX_EVENT_ID: usize = 40;
/// Retention runs after this many new events, besides the periodic run.
const CLEANUP_AFTER: u64 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub retention_days: u32,
    pub max_events: u32,
    pub max_bytes: i64,
    pub discard_after_seconds: i64,
}

impl Limits {
    pub fn new(retention_days: u32, max_events: u32, max_bytes: i64) -> Self {
        Limits {
            retention_days,
            max_events,
            max_bytes,
            discard_after_seconds: 3600,
        }
    }
}

/// `createdAt` of an event: ISO 8601 with an offset, as whole seconds.
pub fn parse_time(value: &Value) -> Option<i64> {
    let text = value.as_str().filter(|text| text.len() <= MAX_TIME_TEXT)?;
    time::parse(text).map(time::Timestamp::as_second)
}

#[derive(Debug)]
pub struct EventStore {
    limits: Limits,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    db: Connection,
    inserted_since_cleanup: u64,
    /// Since when no batch was stored whole, while that lasts.
    failing: Option<Failing>,
    /// Counted since this process started.
    health: Health,
}

/// What one batch did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub stored: u64,
    /// Everything that was not stored, for whatever reason.
    pub skipped: u64,
    /// Of the skipped: stored already, by a batch that came before.
    pub duplicate: u64,
    /// Of the skipped: of a type that is recorded, but not readable.
    pub unreadable: u64,
}

impl EventStore {
    pub fn open(path: &Path, limits: Limits) -> Result<Self, SqliteError> {
        let db = sqlite::open_database(path, &MIGRATIONS, Database::Events)?;
        let page_size: i64 = db.pragma_query_value(None, "page_size", |row| row.get(0))?;
        // A hard ceiling above the soft budget that `enforce_limits` keeps.
        db.pragma_update(None, "max_page_count", limits.max_bytes * 2 / page_size)?;
        Ok(EventStore {
            limits,
            state: Mutex::new(State {
                db,
                inserted_since_cleanup: 0,
                failing: None,
                health: Health::default(),
            }),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while holding the lock leaves SQLite consistent: every write
        // is a transaction that rolls back when it is dropped.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record the receiver's start and any window in which events may have been lost.
    pub fn start(&self, now: i64) -> Result<(), SqliteError> {
        let mut guard = self.state();
        let state = &mut *guard;
        let transaction = state
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(last) = meta(&transaction, "heartbeatAt")?.and_then(|value| value.as_i64()) {
            let lost_until = now - self.limits.discard_after_seconds;
            if lost_until > last {
                transaction.execute(
                    "INSERT INTO gaps(start_at,end_at,reason) VALUES(?,?,?)",
                    params![last, lost_until, OFFLINE],
                )?;
            }
        }
        if meta(&transaction, "recordingSince")?.is_none() {
            set_meta(&transaction, "recordingSince", now)?;
        }
        set_meta(&transaction, "heartbeatAt", now)?;
        set_meta(
            &transaction,
            "retentionDays",
            i64::from(self.limits.retention_days),
        )?;
        // A run that ended while it stored nothing: that time is not over.
        let kept = failing::kept(&transaction);
        transaction.commit()?;
        state.failing = state.failing.or(kept);
        Ok(())
    }

    /// A batch was refused at `now`: its signature did not match, or it
    /// could not be stored. The receiver remembers since when; the database
    /// is told if it takes it, which a full or read-only one does not.
    pub fn refused(&self, now: i64) -> u64 {
        let mut state = self.state();
        state.health.refused += 1;
        let count = state.health.refused;
        if state.failing.is_some() {
            return count;
        }
        let failing = Failing {
            since: now,
            kind: failing::Kind::Refused,
        };
        state.failing = Some(failing);
        if let Err(error) = failing::keep(&state.db, failing) {
            log::warn!("The event store did not take since when batches are refused: {error}");
        }
        count
    }

    /// What the receiver counted since it started.
    pub fn health(&self) -> Health {
        let state = self.state();
        Health {
            failing_since: state.failing.map(|failing| failing.since),
            ..state.health
        }
    }

    pub fn heartbeat(&self, now: i64) -> Result<(), SqliteError> {
        let state = self.state();
        set_meta(&state.db, "heartbeatAt", now)?;
        Ok(())
    }

    /// Store one webhook batch atomically.
    pub fn ingest(&self, events: &[Value], received: i64) -> Result<Outcome, SqliteError> {
        let mut guard = self.state();
        let state = &mut *guard;
        let was = state.failing;
        let mut outcome = Outcome::default();
        let arrival = Arrival {
            at: received,
            kept_from: received - self.retention(),
        };
        let transaction = state
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for event in events {
            match insert(&transaction, event, arrival)? {
                Taken::Stored => outcome.stored += 1,
                Taken::Duplicate => outcome.duplicate += 1,
                Taken::Unreadable => outcome.unreadable += 1,
                Taken::NotRecorded => {}
            }
        }
        outcome.skipped = events.len() as u64 - outcome.stored;
        set_meta(&transaction, "lastBatchAt", received)?;
        set_meta(&transaction, "heartbeatAt", received)?;
        // Events that could not be read are gone, since Stalwart is answered
        // "stored": from now on something is missing. A batch that reads
        // whole ends that, and what was lost until then becomes a gap.
        let failing = match (was, outcome.unreadable > 0) {
            (None, true) => {
                let began = Failing {
                    since: received,
                    kind: failing::Kind::Unreadable,
                };
                failing::keep(&transaction, began)?;
                Some(began)
            }
            (Some(failing), false) => {
                failing::ended(
                    &transaction,
                    failing,
                    received,
                    self.limits.discard_after_seconds,
                )?;
                None
            }
            (unchanged, _) => unchanged,
        };
        transaction.commit()?;
        if outcome.unreadable > 0 && was.is_none() {
            log::error!(
                "{} events of a recorded type could not be read, or are dated as no event \
                 that arrives now can be, and are lost; Stalwart may write them differently \
                 now, or its clock is wrong",
                outcome.unreadable
            );
        }
        state.failing = failing;
        state.health.unreadable += outcome.unreadable;
        state.health.duplicate += outcome.duplicate;
        state.inserted_since_cleanup += outcome.stored;
        if state.inserted_since_cleanup >= CLEANUP_AFTER {
            // The batch is committed either way; a failed cleanup runs again later.
            if let Err(error) = self.enforce(state, received) {
                log::error!("Event retention failed: {error}");
            }
        }
        Ok(outcome)
    }

    /// The seconds for which an event is kept.
    fn retention(&self) -> i64 {
        i64::from(self.limits.retention_days) * 86400
    }

    pub fn enforce_limits(&self, now: i64) -> Result<(), SqliteError> {
        self.enforce(&mut self.state(), now)
    }

    fn enforce(&self, state: &mut State, now: i64) -> Result<(), SqliteError> {
        state.inserted_since_cleanup = 0;
        let cutoff = now - self.retention();
        let transaction = state
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM events WHERE created_at < ?", [cutoff])?;
        let count = |transaction: &Transaction<'_>| -> rusqlite::Result<i64> {
            transaction.query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        };
        let excess = count(&transaction)? - i64::from(self.limits.max_events);
        if excess > 0 {
            drop_oldest(&transaction, excess, EVENT_LIMIT)?;
        }
        let pragma = |name: &str| -> rusqlite::Result<i64> {
            transaction.pragma_query_value(None, name, |row| row.get(0))
        };
        let used = (pragma("page_count")? - pragma("freelist_count")?) * pragma("page_size")?;
        if used > self.limits.max_bytes {
            let total = count(&transaction)?;
            drop_oldest(&transaction, (total / 10).max(1), STORAGE_BUDGET)?;
        }
        // A delivery or a session is listed for as long as one of its events
        // is there, whether its events went for their age or for a size
        // limit. Only one that ended no later than the oldest event left can
        // be without any.
        let oldest: Option<i64> =
            transaction.query_row("SELECT min(created_at) FROM events", [], |row| row.get(0))?;
        let oldest = oldest.unwrap_or(i64::MAX);
        for (table, key) in [("queues", "queue_id"), ("spans", "span_id")] {
            transaction.execute(
                &format!(
                    "DELETE FROM {table} WHERE last_seen <= ? AND NOT EXISTS \
                     (SELECT 1 FROM events WHERE events.{key} = {table}.{key})"
                ),
                [oldest],
            )?;
        }
        transaction.execute("DELETE FROM gaps WHERE end_at < ?", [cutoff])?;
        transaction.commit()?;
        Ok(())
    }
}

fn meta(db: &Connection, key: &str) -> Result<Option<Value>, SqliteError> {
    let text: Option<String> = db
        .query_row("SELECT value FROM metadata WHERE key=?", [key], |row| {
            row.get(0)
        })
        .optional()?;
    Ok(text.and_then(|text| serde_json::from_str(&text).ok()))
}

fn set_meta(db: &Connection, key: &str, value: i64) -> Result<(), SqliteError> {
    recording::set(db, key, value)?;
    Ok(())
}

/// Remove the `count` oldest events to keep the size limit `limit`.
fn drop_oldest(db: &Connection, count: i64, limit: &str) -> Result<(), SqliteError> {
    let (first, last): (Option<i64>, Option<i64>) = db.query_row(
        "SELECT min(created_at), max(created_at) FROM \
         (SELECT created_at FROM events ORDER BY created_at LIMIT ?)",
        [count],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (Some(first), Some(last)) = (first, last) else {
        return Ok(());
    };
    db.execute(
        "DELETE FROM events WHERE seq IN (SELECT seq FROM events ORDER BY created_at LIMIT ?)",
        [count],
    )?;
    // The history now begins after `last`; say so explicitly.
    widen(db, limit, first, last)
}

/// Keep one window for what the size limit `limit` removed: everything it
/// removed so far and the events from `first` to `last` it removed now. A
/// limit always takes the oldest events, so these are one stretch.
fn widen(db: &Connection, limit: &str, first: i64, last: i64) -> Result<(), SqliteError> {
    let known: (Option<i64>, Option<i64>) = db.query_row(
        "SELECT min(start_at), max(end_at) FROM gaps WHERE reason=?",
        [limit],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (start, end) = match known {
        (Some(start), Some(end)) => (start.min(first), end.max(last)),
        _ => (first, last),
    };
    db.execute("DELETE FROM gaps WHERE reason=?", [limit])?;
    db.execute(
        "INSERT INTO gaps(start_at,end_at,reason) VALUES(?,?,?)",
        params![start, end, limit],
    )?;
    Ok(())
}

#[cfg(test)]
mod failing_tests;
#[cfg(test)]
mod limit_tests;
#[cfg(test)]
mod sequence_tests;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod time_tests;
