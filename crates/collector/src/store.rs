//! Status snapshots and metric history. Only the collector writes this database.
//!
//! Gauges are stored as sampled. Counters are stored as per-interval
//! increases, computed against the previous reading; a counter that went down
//! (process restart) contributes its new value and is recorded as a reset.
//! Intervals longer than three minutes produce no increase, so a collection
//! gap never becomes a spike. Samples older than eight days are thinned to
//! one per ten minutes (thinning.rs); the history reads both (history.rs).

use std::collections::BTreeMap;
use std::path::Path;

use garrison_core::config::Database;
use garrison_core::sqlite::{self, Migration, SqliteError};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::context::Memory;
use crate::snapshot::Snapshot;

mod history;
mod thinning;

pub use history::{History, HistoryError, PERIODS, history};

const MAX_COUNTER_INTERVAL: i64 = 180;
const KEEP_SNAPSHOTS: i64 = 10;

/// The schema version this release writes; `self-check` accepts up to it.
pub const SCHEMA_VERSION: usize = MIGRATIONS.len();

const MIGRATIONS: [Migration; 2] = [
    &[
        "CREATE TABLE snapshots(
        id INTEGER PRIMARY KEY,
        collected_at INTEGER NOT NULL,
        document TEXT NOT NULL
    )",
        "CREATE TABLE samples(
        name TEXT NOT NULL,
        ts INTEGER NOT NULL,
        value REAL NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('gauge','increase')),
        PRIMARY KEY(name, ts)
    ) WITHOUT ROWID",
        "CREATE INDEX samples_ts ON samples(ts)",
        "CREATE TABLE counters(
        name TEXT PRIMARY KEY,
        ts INTEGER NOT NULL,
        value REAL NOT NULL
    )",
        "CREATE TABLE resets(ts INTEGER NOT NULL, name TEXT NOT NULL)",
        "CREATE INDEX resets_ts ON resets(ts)",
        // What the collector keeps between two runs (context::Memory).
        "CREATE TABLE memory(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    ],
    &[
        // How many minutes a sample stands for: one, or up to ten where it was
        // thinned. A release before this one cannot write the table any more, so
        // a rollback to it needs the state from before the upgrade.
        "ALTER TABLE samples ADD COLUMN minutes INTEGER NOT NULL DEFAULT 1 CHECK(minutes >= 1)",
        // The history's coverage then reads the minutes from the index alone.
        // On 90 days of minute samples the rebuild takes about a second.
        "DROP INDEX samples_ts",
        "CREATE INDEX samples_ts ON samples(ts, minutes)",
    ],
];

#[derive(Debug)]
pub struct StatusStore {
    db: Connection,
    history_days: u32,
}

impl StatusStore {
    pub fn open(path: &Path, history_days: u32) -> Result<Self, SqliteError> {
        let db = sqlite::open_database(path, &MIGRATIONS, Database::Status)?;
        Ok(StatusStore { db, history_days })
    }

    pub fn write(
        &mut self,
        collected_at: i64,
        snapshot: &Snapshot,
        gauges: &BTreeMap<String, f64>,
        counters: &BTreeMap<String, f64>,
    ) -> Result<(), SqliteError> {
        let document = serde_json::to_string(snapshot).map_err(std::io::Error::from)?;
        let minute = collected_at - collected_at.rem_euclid(60);
        let mut transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO snapshots(collected_at, document) VALUES(?,?)",
            params![collected_at, document],
        )?;
        transaction.execute(
            "DELETE FROM snapshots WHERE id NOT IN \
             (SELECT id FROM snapshots ORDER BY id DESC LIMIT ?)",
            [KEEP_SNAPSHOTS],
        )?;
        for (name, value) in gauges {
            if value.is_finite() {
                sample(&transaction, name, minute, *value, "gauge")?;
            }
        }
        for (name, value) in counters {
            counter(&transaction, name, collected_at, minute, *value)?;
        }
        let cutoff = collected_at - i64::from(self.history_days) * 86400;
        transaction.execute("DELETE FROM samples WHERE ts < ?", [cutoff])?;
        transaction.execute("DELETE FROM resets WHERE ts < ?", [cutoff])?;
        // Thinning is upkeep: where it fails, the run's samples are kept all the same.
        if let Err(error) = thinning::thin(&mut transaction, minute) {
            log::warn!("The metric history was not thinned in this run: {error}");
        }
        transaction.commit()?;
        Ok(())
    }
}

impl Memory for StatusStore {
    fn recall(&self, key: &str) -> Option<String> {
        self.db
            .query_row("SELECT value FROM memory WHERE key=?", [key], |row| {
                row.get(0)
            })
            .optional()
            .unwrap_or_else(|error| {
                log::warn!("The status database did not give {key}: {error}");
                None
            })
    }

    fn keep(&self, key: &str, value: &str) {
        let kept = self.db.execute(
            "INSERT INTO memory VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        );
        if let Err(error) = kept {
            log::warn!("The status database did not keep {key}: {error}");
        }
    }
}

/// A repeated collection within the same minute replaces that minute's value.
fn sample(
    db: &Connection,
    name: &str,
    minute: i64,
    value: f64,
    kind: &str,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO samples(name, ts, value, kind) VALUES(?,?,?,?) \
         ON CONFLICT(name, ts) DO UPDATE SET value=excluded.value",
        params![name, minute, value, kind],
    )?;
    Ok(())
}

fn counter(db: &Connection, name: &str, now: i64, minute: i64, value: f64) -> rusqlite::Result<()> {
    if !value.is_finite() || value < 0.0 {
        return Ok(());
    }
    let previous: Option<(i64, f64)> = db
        .query_row(
            "SELECT ts, value FROM counters WHERE name=?",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    db.execute(
        "INSERT INTO counters VALUES(?,?,?) \
         ON CONFLICT(name) DO UPDATE SET ts=excluded.ts, value=excluded.value",
        params![name, now, value],
    )?;
    let Some((at, last)) = previous else {
        return Ok(());
    };
    if !(1..=MAX_COUNTER_INTERVAL).contains(&(now - at)) {
        return Ok(());
    }
    let increase = if value < last {
        db.execute("INSERT INTO resets VALUES(?,?)", params![now, name])?;
        value
    } else {
        value - last
    };
    sample(db, name, minute, increase, "increase")
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("the stored snapshot is not one this release reads: {0}")]
    Unreadable(#[from] serde_json::Error),
    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// The newest snapshot, or `None` before the first collection run. A stored
/// document that is no snapshot is an error, not an absent snapshot.
pub fn latest_snapshot(db: &Connection) -> Result<Option<Snapshot>, SnapshotError> {
    let text: Option<String> = db
        .query_row(
            "SELECT document FROM snapshots ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(text.as_deref().map(serde_json::from_str).transpose()?)
}

#[cfg(test)]
mod tests;
