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

use std::path::Path;
use std::sync::Mutex;

use garrison_core::config::Database;
use garrison_core::{sqlite, time};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;

use crate::policy::{EventType, identifier, select_fields};

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
    "CREATE TABLE gaps(
        id INTEGER PRIMARY KEY,
        start_at INTEGER NOT NULL,
        end_at INTEGER NOT NULL,
        reason TEXT NOT NULL
    )",
    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
]];

/// The reasons a window in `gaps` may lack events. The receiver was away for
/// longer than Stalwart keeps undelivered events.
pub const OFFLINE: &str = "receiver-offline";
/// The oldest events were removed to keep the event limit.
pub const EVENT_LIMIT: &str = "capacity-events";
/// The oldest events were removed to keep the storage budget.
pub const STORAGE_BUDGET: &str = "capacity-bytes";

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
}

/// What one batch did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub stored: u64,
    pub skipped: u64,
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
        let mut state = self.state();
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
        transaction.commit()?;
        Ok(())
    }

    pub fn heartbeat(&self, now: i64) -> Result<(), SqliteError> {
        let state = self.state();
        set_meta(&state.db, "heartbeatAt", now)?;
        Ok(())
    }

    /// Store one webhook batch atomically.
    pub fn ingest(&self, events: &[Value], received: i64) -> Result<Outcome, SqliteError> {
        let mut state = self.state();
        let mut outcome = Outcome::default();
        let transaction = state
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for event in events {
            if insert(&transaction, event, received)? {
                outcome.stored += 1;
            } else {
                outcome.skipped += 1;
            }
        }
        set_meta(&transaction, "lastBatchAt", received)?;
        set_meta(&transaction, "heartbeatAt", received)?;
        transaction.commit()?;
        state.inserted_since_cleanup += outcome.stored;
        if state.inserted_since_cleanup >= CLEANUP_AFTER {
            // The batch is committed either way; a failed cleanup runs again later.
            if let Err(error) = self.enforce(&mut state, received) {
                log::error!("Event retention failed: {error}");
            }
        }
        Ok(outcome)
    }

    pub fn enforce_limits(&self, now: i64) -> Result<(), SqliteError> {
        self.enforce(&mut self.state(), now)
    }

    fn enforce(&self, state: &mut State, now: i64) -> Result<(), SqliteError> {
        state.inserted_since_cleanup = 0;
        let cutoff = now - i64::from(self.limits.retention_days) * 86400;
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
    db.execute(
        "INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value.to_string()],
    )?;
    Ok(())
}

/// Insert one event; `false` if it is not recordable or already recorded.
fn insert(db: &Connection, event: &Value, received: i64) -> Result<bool, SqliteError> {
    let Value::Object(event) = event else {
        return Ok(false);
    };
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        .and_then(EventType::parse);
    let created = event.get("createdAt").and_then(parse_time);
    let event_id = match event.get("id") {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Number(number)) if !number.is_f64() => Some(number.to_string()),
        _ => None,
    }
    .filter(|id| id.chars().count() <= MAX_EVENT_ID);
    let (Some(event_type), Some(created), Some(event_id)) = (event_type, created, event_id) else {
        return Ok(false);
    };
    let data = event.get("data").unwrap_or(&Value::Null);
    let fields = select_fields(event_type, data);
    let span = data.get("spanId").and_then(identifier);
    let queue = data.get("queueId").and_then(identifier);
    let kind = event_type.category();
    let inserted = db.execute(
        "INSERT OR IGNORE INTO events(event_id,created_at,received_at,type,category,\
         span_id,queue_id,fields) VALUES(?,?,?,?,?,?,?,?)",
        params![
            event_id,
            created,
            received,
            event_type.as_str(),
            kind,
            span,
            queue,
            Value::Object(fields).to_string(),
        ],
    )?;
    if inserted != 1 {
        return Ok(false); // A retried batch: the event is already recorded.
    }
    if let Some(queue) = &queue {
        db.execute(
            "INSERT INTO queues VALUES(?,?,?,1) ON CONFLICT(queue_id) DO UPDATE SET \
             first_seen=min(first_seen,excluded.first_seen),\
             last_seen=max(last_seen,excluded.last_seen),event_count=event_count+1",
            params![queue, created, created],
        )?;
    }
    if let Some(span) = &span {
        // A span that contains any SMTP event is an SMTP session, even if a
        // queue event of the same span happened to arrive first.
        db.execute(
            "INSERT INTO spans VALUES(?,?,?,1,?) ON CONFLICT(span_id) DO UPDATE SET \
             first_seen=min(first_seen,excluded.first_seen),\
             last_seen=max(last_seen,excluded.last_seen),event_count=event_count+1,\
             protocol=CASE WHEN excluded.protocol='smtp' THEN 'smtp' ELSE protocol END",
            params![span, created, created, kind],
        )?;
    }
    Ok(true)
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
mod limit_tests;
#[cfg(test)]
mod sequence_tests;
#[cfg(test)]
pub(crate) mod tests;
