//! Status snapshots and metric history. Only the collector writes this database.
//!
//! Gauges are stored as sampled. Counters are stored as per-interval
//! increases, computed against the previous reading; a counter that went down
//! (process restart) contributes its new value and is recorded as a reset.
//! Intervals longer than three minutes produce no increase, so a collection
//! gap never becomes a spike. Samples older than eight days are thinned to
//! one per ten minutes (thinning.rs); the history reads both (history.rs).
//! What is old is counted from the collector's own run time (clock.rs), so a
//! clock that jumps ahead takes nothing with it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use garrison_core::config::Database;
use garrison_core::sqlite::{self, Migration, SqliteError};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::context::Memory;
use crate::snapshot::Snapshot;

mod clock;
mod history;
mod replace;
mod residue;
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

/// A rebuild of the status database (residue.rs) begins only where the run
/// leaves it this long: what a disk that writes 2 MB a second takes for 90
/// days of history, some 20 seconds, and room besides. A later run that
/// leaves more does it.
const REBUILD_FOR: Duration = Duration::from_secs(60);
/// While a rebuild runs, systemd is asked for this much more time again and
/// again, as long as the rebuild may run, so that its unit's 120 seconds do
/// not end it (`NotifyAccess=main`).
const ASK_FOR: Duration = Duration::from_secs(60);
const ASK_EVERY: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub struct StatusStore {
    db: Connection,
    path: PathBuf,
    history_days: u32,
}

impl StatusStore {
    pub fn open(path: &Path, history_days: u32) -> Result<Self, SqliteError> {
        // A copy that a rebuild ended midway left may hold a key; collection
        // runs are one at a time (run.rs), so no rebuild is under way.
        replace::remove(&replace::copy_of(path));
        let db = sqlite::open_database(path, &MIGRATIONS, Database::Status)?;
        Ok(StatusStore {
            db,
            path: path.to_owned(),
            history_days,
        })
    }

    /// Rebuild the database without what earlier releases kept of a key of
    /// Spamhaus' Data Query Service, where it may hold some (residue.rs), by
    /// `until`; `now` is the run's time. A run's last step, so that it costs
    /// no run: a rebuild that did not finish is said in the journal.
    pub fn clear_residue(&mut self, now: i64, until: Instant) {
        let unread = |error: &dyn std::fmt::Display| {
            log::warn!(
                "The status database could not be cleared of a key of Spamhaus' Data Query \
                 Service that an earlier release kept: {error}; the next run tries again"
            );
        };
        match residue::due(&self.db, &self.path, now) {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => return unread(&error),
        }
        if until.saturating_duration_since(Instant::now()) < REBUILD_FOR {
            log::info!(
                "The status database may hold a key of Spamhaus' Data Query Service that an \
                 earlier release kept; this run left too little time to rebuild it, a later \
                 one does"
            );
            return;
        }
        let began = Instant::now();
        let (db, path) = (&mut self.db, self.path.as_path());
        match with_more_time(until, || residue::clear(db, path, now, until)) {
            Ok(rows) => {
                log::info!(
                    "The status database held a key of Spamhaus' Data Query Service that an \
                     earlier release kept: {rows} rows named it, now without it, and the file was \
                     rebuilt beside it in {} ms and put in its place",
                    began.elapsed().as_millis()
                );
                // The connection holds the file that the copy replaced.
                match sqlite::open_database(&self.path, &MIGRATIONS, Database::Status) {
                    Ok(db) => self.db = db,
                    Err(error) => log::warn!("The rebuilt status database did not open: {error}"),
                }
            }
            Err(residue::Unfinished::Late) => log::warn!(
                "The status database could not be cleared of a key of Spamhaus' Data Query \
                 Service that an earlier release kept within the time this run left: the copy \
                 was removed, and a run tries again in a day"
            ),
            Err(residue::Unfinished::Failed(error)) => unread(&error),
        }
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
        let previous: Option<i64> = transaction
            .query_row(
                "SELECT collected_at FROM snapshots ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
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
        // The snapshot and the samples keep the run's own time; what is old
        // goes by the collector's run time.
        let cleaned = clock::cleaned_by(&transaction, collected_at, previous)?;
        if let Some((level, line)) = &cleaned.said {
            log::log!(*level, "{line}");
        }
        let by = cleaned.by;
        let cutoff = by.saturating_sub(i64::from(self.history_days) * 86400);
        transaction.execute("DELETE FROM samples WHERE ts < ?", [cutoff])?;
        transaction.execute("DELETE FROM resets WHERE ts < ?", [cutoff])?;
        // Thinning is upkeep: where it fails, the run's samples are kept all the same.
        if let Err(error) = thinning::thin(&mut transaction, by - by.rem_euclid(60)) {
            log::warn!("The metric history was not thinned in this run: {error}");
        }
        transaction.commit()?;
        Ok(())
    }
}

/// `work`, with systemd asked for more time while it runs, until `until`.
fn with_more_time<T>(until: Instant, work: impl FnOnce() -> T) -> T {
    let (done, waiting) = mpsc::channel::<()>();
    thread::scope(|scope| {
        scope.spawn(move || {
            while Instant::now() < until {
                garrison_core::systemd::extend_timeout(ASK_FOR);
                if waiting.recv_timeout(ASK_EVERY) != Err(RecvTimeoutError::Timeout) {
                    return;
                }
            }
        });
        let result = work();
        drop(done);
        result
    })
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

/// One value for one minute. A repeated collection within the same minute
/// replaces a gauge, which is a reading, and adds to an increase, which is
/// what happened since the reading before: replaced, the events of the
/// minute's first interval would be lost.
fn sample(
    db: &Connection,
    name: &str,
    minute: i64,
    value: f64,
    kind: &str,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO samples(name, ts, value, kind) VALUES(?,?,?,?) \
         ON CONFLICT(name, ts) DO UPDATE SET value = CASE \
             WHEN excluded.kind = 'increase' AND samples.kind = 'increase' \
             THEN samples.value + excluded.value ELSE excluded.value END",
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
    // Also a second run within the same second: what the counter rose by
    // since the reading before still happened. A reading at a time that is
    // none, in a damaged database, is no interval either.
    if !now
        .checked_sub(at)
        .is_some_and(|step| (0..=MAX_COUNTER_INTERVAL).contains(&step))
    {
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
mod residue_tests;
#[cfg(test)]
mod tests;
