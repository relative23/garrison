//! Status snapshots and metric history. Only the collector writes this database.
//!
//! Gauges are stored as sampled. Counters are stored as per-interval
//! increases, computed against the previous reading; a counter that went down
//! (process restart) contributes its new value and is recorded as a reset.
//! Intervals longer than three minutes produce no increase, so a collection
//! gap never becomes a spike.

use std::collections::BTreeMap;
use std::path::Path;

use garrison_core::config::Database;
use garrison_core::sqlite::{self, Migration, SqliteError};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::context::Memory;
use crate::snapshot::Snapshot;
use crate::values::float;

const MAX_COUNTER_INTERVAL: i64 = 180;
const KEEP_SNAPSHOTS: i64 = 10;

/// The schema version this release writes; `self-check` accepts up to it.
pub const SCHEMA_VERSION: usize = MIGRATIONS.len();

const MIGRATIONS: [Migration; 1] = [&[
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
]];

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
        let transaction = self
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
        "INSERT INTO samples VALUES(?,?,?,?) \
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

/// The history periods the interface offers: seconds and buckets.
pub const PERIODS: [(&str, i64, usize); 4] = [
    ("24h", 86400, 48),
    ("7d", 7 * 86400, 56),
    ("30d", 30 * 86400, 60),
    ("90d", 90 * 86400, 90),
];

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("Invalid time range or resolution")]
    Invalid,
    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// The recorded samples of a time range in buckets. The series are whatever
/// the providers stored, so each point is a map from a series' name to its
/// value in that bucket, or `null` where nothing was recorded.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct History {
    pub from: i64,
    pub to: i64,
    /// One per bucket, each with the `timestamp` of the bucket's middle.
    pub points: Vec<Map<String, Value>>,
    /// The sum of each counter's increases in the range.
    pub totals: Map<String, Value>,
    /// The first and the last minute that have a sample, and how many have.
    pub coverage_from: Option<i64>,
    pub coverage_to: Option<i64>,
    pub sampled_minutes: i64,
    pub counter_resets: i64,
    /// The newest value of each gauge in the range.
    pub latest: Map<String, Value>,
}

/// Where each bucket of a range of `seconds` begins: bucket `index` holds the
/// seconds from `[index]` up to, not including, `[index + 1]`, counted from
/// the start of the range; the last entry is `seconds`.
///
/// A second's bucket is `second / span`, cut off to a whole number. Each limit
/// is the first second that expression puts into its bucket or a later one,
/// found by halving the range, so a second at a limit lies in the bucket the
/// expression gives it, also when the span is no whole number.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn bucket_limits(seconds: i64, buckets: usize) -> Vec<i64> {
    let span = seconds as f64 / buckets as f64;
    let bucket_of = |second: i64| (second as f64 / span) as usize;
    (0..=buckets)
        .map(|index| {
            let (mut first, mut beyond) = (0, seconds);
            while first < beyond {
                let middle = first + (beyond - first) / 2;
                if bucket_of(middle) < index {
                    first = middle + 1;
                } else {
                    beyond = middle;
                }
            }
            first
        })
        .collect()
}

/// The names of all series, in order. Each step asks the primary key for the
/// next name, so the samples themselves are not read.
fn series(db: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut statement = db.prepare(
        "WITH RECURSIVE series(name) AS (\
           SELECT min(name) FROM samples \
           UNION ALL \
           SELECT (SELECT min(name) FROM samples WHERE name > series.name) \
           FROM series WHERE series.name IS NOT NULL) \
         SELECT name FROM series WHERE name IS NOT NULL",
    )?;
    statement.query_map([], |row| row.get(0))?.collect()
}

/// Samples in buckets: gauges are averaged, increases are summed. Missing
/// data stays missing (`null`), never zero.
///
/// Each series is read bucket by bucket along the primary key (name, time),
/// and SQLite aggregates the rows as it passes them. One query that groups
/// all samples of the range had to sort them first, which took longer than a
/// reader's time budget once a host held 90 days of them.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
pub fn history(
    db: &Connection,
    start: i64,
    end: i64,
    buckets: usize,
) -> Result<History, HistoryError> {
    let seconds = end.checked_sub(start).unwrap_or(0);
    if !(1..=730 * 86400).contains(&seconds) || !(1..=1440).contains(&buckets) {
        return Err(HistoryError::Invalid);
    }
    let span = seconds as f64 / buckets as f64;
    let mut points: Vec<Map<String, Value>> = (0..buckets)
        .map(|index| {
            let mut point = Map::new();
            let middle = start as f64 + (index as f64 + 0.5) * span;
            point.insert("timestamp".into(), json!(middle as i64));
            point
        })
        .collect();
    let limits = bucket_limits(seconds, buckets);
    let mut bucket = db.prepare(
        "SELECT avg(value) FILTER (WHERE kind = 'gauge'), \
                sum(value) FILTER (WHERE kind = 'increase') \
         FROM samples WHERE name = ? AND ts >= ? AND ts < ?",
    )?;
    let mut newest = db.prepare(
        "SELECT value FROM samples WHERE name = ? AND kind = 'gauge' AND ts >= ? AND ts < ? \
         ORDER BY ts DESC LIMIT 1",
    )?;
    let mut totals: Map<String, Value> = Map::new();
    let mut latest = Map::new();
    let mut names: Vec<String> = Vec::new();
    for name in series(db)? {
        let (mut total, mut sampled, mut gauge) = (0.0, false, false);
        for (index, point) in points.iter_mut().enumerate() {
            let (from, to) = (start + limits[index], start + limits[index + 1]);
            if from == to {
                continue;
            }
            let (average, sum): (Option<f64>, Option<f64>) = bucket
                .query_row(params![name, from, to], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?;
            if let Some(value) = average {
                point.insert(name.clone(), float(value));
                gauge = true;
            }
            // A name used as a gauge and as a counter shows its increases.
            if let Some(value) = sum {
                point.insert(name.clone(), float(value));
                total += value;
                totals.insert(name.clone(), float(total));
            }
            sampled |= average.is_some() || sum.is_some();
        }
        if gauge {
            let value: f64 = newest.query_row(params![name, start, end], |row| row.get(0))?;
            latest.insert(name.clone(), float(value));
        }
        if sampled {
            names.push(name);
        }
    }
    for point in &mut points {
        for name in &names {
            point.entry(name.clone()).or_insert(Value::Null);
        }
    }
    let (first, last, minutes): (Option<i64>, Option<i64>, i64) = db.query_row(
        "SELECT min(ts), max(ts), count(DISTINCT ts) FROM samples WHERE ts >= ? AND ts < ?",
        [start, end],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let resets: i64 = db.query_row(
        "SELECT count(*) FROM resets WHERE ts >= ? AND ts < ?",
        [start, end],
        |row| row.get(0),
    )?;
    Ok(History {
        from: start,
        to: end,
        points,
        totals,
        coverage_from: first,
        coverage_to: last,
        sampled_minutes: minutes,
        counter_resets: resets,
        latest,
    })
}

#[cfg(test)]
mod history_tests;
#[cfg(test)]
mod tests;
