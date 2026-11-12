//! How fast the metric history answers the periods the dashboard offers.
//!
//! ```sh
//! cargo bench -p garrison-collector
//! ```
//!
//! The numbers belong to the machine and to the directory for temporary
//! files (a tmpfs leaves the disk out): compare a change with the commit
//! before it on the same machine. Nothing here is a limit a test checks.

// A benchmark fails by panicking, like a test.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use garrison_collector::store::{History, PERIODS, StatusStore, history};
use garrison_core::sqlite::reading;
use rusqlite::{Connection, params};

/// 2026-10-28T10:00:00Z, the end of the stored history.
const END: i64 = 1_793_181_600;
const DAYS: i64 = 90;
/// As a host with every provider stores them each minute.
const GAUGES: i64 = 8;
const COUNTERS: i64 = 12;
/// The web service gives a query two seconds and fails the request after
/// that. Here a query may take longer, so that the time it needs shows: a
/// period above two seconds is one the dashboard cannot draw.
const BUDGET: Duration = Duration::from_secs(60);

/// 90 days of samples, one per series and minute, written once.
static STATUS: OnceLock<PathBuf> = OnceLock::new();

fn main() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    // The store makes the schema; one run a minute for 90 days would take too
    // long to write through it, so the samples go in as its rows.
    drop(StatusStore::open(&path, 90).unwrap());
    fill(&path);
    STATUS.set(path).unwrap();
    divan::main();
}

fn fill(path: &Path) {
    let mut db = Connection::open(path).unwrap();
    let transaction = db.transaction().unwrap();
    {
        let mut insert = transaction
            .prepare("INSERT INTO samples(name, ts, value, kind) VALUES(?,?,?,?)")
            .unwrap();
        for minute in 0..DAYS * 1440 {
            let at = END - (minute + 1) * 60;
            for series in 0..GAUGES + COUNTERS {
                let (name, kind) = if series < GAUGES {
                    (format!("gauge_{series}"), "gauge")
                } else {
                    (format!("counter_{series}"), "increase")
                };
                insert
                    .execute(params![name, at, (minute + series) % 97, kind])
                    .unwrap();
            }
        }
    }
    transaction.commit().unwrap();
}

/// One request's query for a period: a reader of its own, as the web service
/// opens it, and the period's buckets over all 20 series.
#[divan::bench(args = ["24h", "7d", "30d", "90d"])]
fn history_of(period: &str) -> History {
    let (_, seconds, buckets) = PERIODS.iter().find(|(name, ..)| *name == period).unwrap();
    let db = reading(STATUS.get().unwrap(), BUDGET).unwrap().unwrap();
    let found = history(&db, END - seconds, END, *buckets).unwrap();
    assert_eq!(found.points.len(), *buckets);
    found
}
