use std::time::Duration;

use garrison_core::sqlite::reading;
use serde_json::{Value, json};

use super::*;
use crate::snapshot::SCHEMA;

/// An empty snapshot; `collected_at` tells one from another.
fn snapshot(collected_at: &str) -> Snapshot {
    Snapshot {
        schema_version: SCHEMA,
        collected_at: collected_at.into(),
        observations: Vec::new(),
        provider_errors: Vec::new(),
    }
}

fn counters(value: f64) -> BTreeMap<String, f64> {
    BTreeMap::from([("delivery_completed".to_owned(), value)])
}

#[test]
fn counters_become_increases_with_reset_and_gap_handling() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    let mut store = StatusStore::open(&path, 90).unwrap();
    let snapshot = snapshot("2026-10-29T12:00:00+00:00");
    let load = |value: f64| BTreeMap::from([("load_1m".to_owned(), value)]);
    store
        .write(60_000, &snapshot, &load(1.0), &counters(10.0))
        .unwrap();
    store
        .write(60_060, &snapshot, &load(3.0), &counters(15.0))
        .unwrap(); // +5
    store
        .write(60_120, &snapshot, &BTreeMap::new(), &counters(2.0))
        .unwrap(); // restart: +2, one reset
    store
        .write(61_000, &snapshot, &BTreeMap::new(), &counters(50.0))
        .unwrap(); // gap > 180 s: nothing
    let db = reading(&path, Duration::from_secs(2)).unwrap().unwrap();
    let result = json!(history(&db, 60_000, 61_060, 4).unwrap());
    assert_eq!(result["totals"]["delivery_completed"], json!(7.0));
    assert_eq!(result["counterResets"], json!(1));
    assert_eq!(result["points"][0]["load_1m"], json!(2.0));
    assert_eq!(result["points"][2]["load_1m"], Value::Null); // Missing data is not zero.
    assert_eq!(result["latest"]["load_1m"], json!(3.0));
    assert_eq!(latest_snapshot(&db).unwrap(), Some(snapshot));
}

#[test]
fn a_counter_that_starts_over_at_zero_counts_its_first_events() {
    // A restart as the exporter reports it: 5, zero until two events, 2.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    let mut store = StatusStore::open(&path, 90).unwrap();
    for (at, value) in [(60_000, 5.0), (60_060, 0.0), (60_120, 0.0), (60_180, 2.0)] {
        store
            .write(at, &snapshot(""), &BTreeMap::new(), &counters(value))
            .unwrap();
    }
    let db = reading(&path, Duration::from_secs(2)).unwrap().unwrap();
    let result = json!(history(&db, 60_000, 60_240, 4).unwrap());
    let minutes: Vec<&Value> = (0..4)
        .map(|index| &result["points"][index]["delivery_completed"])
        .collect();
    assert_eq!(
        minutes,
        [&Value::Null, &json!(0.0), &json!(0.0), &json!(2.0)]
    );
    assert_eq!(result["totals"]["delivery_completed"], json!(2.0));
    assert_eq!(result["counterResets"], json!(1));
}

#[test]
fn only_ten_snapshots_are_kept_and_bad_values_are_skipped() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    let mut store = StatusStore::open(&path, 1).unwrap();
    let gauges = BTreeMap::from([("nan".to_owned(), f64::NAN), ("ok".to_owned(), 1.0)]);
    for index in 0..12 {
        store
            .write(
                100_000 + index * 60,
                &snapshot(&index.to_string()),
                &gauges,
                &counters(-1.0),
            )
            .unwrap();
    }
    let db = reading(&path, Duration::from_secs(2)).unwrap().unwrap();
    let count: i64 = db
        .query_row("SELECT count(*) FROM snapshots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 10);
    let names: i64 = db
        .query_row("SELECT count(DISTINCT name) FROM samples", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(names, 1, "NaN gauges and negative counters are not stored");
    assert_eq!(latest_snapshot(&db).unwrap(), Some(snapshot("11")));
    assert!(matches!(
        history(&db, 10, 10, 4),
        Err(HistoryError::Invalid)
    ));
    assert!(matches!(history(&db, 0, 10, 0), Err(HistoryError::Invalid)));
    // Without overflow checks, this span would wrap around to one second.
    assert!(matches!(
        history(&db, i64::MAX, i64::MIN, 4),
        Err(HistoryError::Invalid)
    ));
    let longest = 730 * 86400;
    assert!(history(&db, 0, longest, 1440).is_ok());
    assert!(matches!(
        history(&db, 0, longest + 1, 1440),
        Err(HistoryError::Invalid)
    ));
    assert!(matches!(
        history(&db, 0, longest, 1441),
        Err(HistoryError::Invalid)
    ));
}

#[test]
fn a_second_run_within_a_minute_adds_to_that_minutes_increase() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    let mut store = StatusStore::open(&path, 90).unwrap();
    let snapshot = snapshot("");
    let load = |value: f64| BTreeMap::from([("load_1m".to_owned(), value)]);
    let total = || {
        let db = reading(&path, Duration::from_secs(2)).unwrap().unwrap();
        let result = json!(history(&db, 60_000, 60_120, 2).unwrap());
        (
            result["totals"]["delivery_completed"].clone(),
            result["latest"]["load_1m"].clone(),
        )
    };
    store
        .write(60_000, &snapshot, &load(1.0), &counters(10.0))
        .unwrap();
    store
        .write(60_060, &snapshot, &load(2.0), &counters(15.0))
        .unwrap();
    assert_eq!(total(), (json!(5.0), json!(2.0)));
    // A run by hand half a minute later, in which nothing was delivered:
    // the five of this minute stay, and the newer load replaces the older.
    store
        .write(60_090, &snapshot, &load(4.0), &counters(15.0))
        .unwrap();
    assert_eq!(total(), (json!(5.0), json!(4.0)));
    // And one in the same second, after two more deliveries.
    store
        .write(60_090, &snapshot, &load(4.0), &counters(17.0))
        .unwrap();
    assert_eq!(total(), (json!(7.0), json!(4.0)));
    // A counter that started over within the minute adds what it counts.
    store
        .write(60_100, &snapshot, &load(4.0), &counters(3.0))
        .unwrap();
    assert_eq!(total().0, json!(10.0));
}

#[test]
fn samples_belong_to_their_minute_and_counters_start_at_zero() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    let mut store = StatusStore::open(&path, 90).unwrap();
    let snapshot = snapshot("");
    let load = BTreeMap::from([("load_1m".to_owned(), 1.0)]);
    // 60 059 lies in the minute from 60 000; a counter may start at zero.
    store
        .write(60_059, &snapshot, &load, &counters(0.0))
        .unwrap();
    store
        .write(60_119, &snapshot, &BTreeMap::new(), &counters(4.0))
        .unwrap();
    // An unchanged counter is no reset: it adds nothing.
    store
        .write(60_179, &snapshot, &BTreeMap::new(), &counters(4.0))
        .unwrap();
    let db = reading(&path, Duration::from_secs(2)).unwrap().unwrap();
    let minutes: Vec<(String, i64, f64)> = db
        .prepare("SELECT name, ts, value FROM samples ORDER BY ts, name")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        minutes,
        [
            ("load_1m".to_owned(), 60_000, 1.0),
            ("delivery_completed".to_owned(), 60_060, 4.0),
            ("delivery_completed".to_owned(), 60_120, 0.0),
        ]
    );
    let resets: i64 = db
        .query_row("SELECT count(*) FROM resets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(resets, 0);
}

/// 2026-10-28T10:00:00Z, the end of the tests' history.
const T0: i64 = 1_793_181_600;
const DAY: i64 = 86400;

/// A store that keeps 90 days, with one sample every `every` seconds over
/// the `days` before [`T0`], and a run at `T0`.
fn history_of(days: i64, every: usize) -> (tempfile::TempDir, StatusStore) {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StatusStore::open(&directory.path().join("status.sqlite"), 90).unwrap();
    {
        let mut insert = store
            .db
            .prepare("INSERT INTO samples(name, ts, value, kind) VALUES('load', ?, 1.0, 'gauge')")
            .unwrap();
        for ts in (T0 - days * DAY..T0).step_by(every) {
            insert.execute([ts]).unwrap();
        }
    }
    run_at(&mut store, T0);
    (directory, store)
}

/// A collection run at `at` that adds no sample of its own.
fn run_at(store: &mut StatusStore, at: i64) {
    store
        .write(at, &snapshot(""), &BTreeMap::new(), &BTreeMap::new())
        .unwrap();
}

fn samples_from(store: &StatusStore, from: i64) -> i64 {
    store
        .db
        .query_row(
            "SELECT count(*) FROM samples WHERE ts >= ?",
            [from],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn a_clock_a_year_ahead_takes_nothing_from_the_history() {
    let (_directory, mut store) = history_of(89, 3600);
    assert_eq!(samples_from(&store, 0), 89 * 24);
    for minute in 0..3 {
        run_at(&mut store, T0 + 365 * DAY + minute * 60);
        assert_eq!(samples_from(&store, 0), 89 * 24, "run {minute}");
    }
}

#[test]
fn a_clock_days_ahead_thins_no_minute_the_views_still_draw() {
    let (_directory, mut store) = history_of(8, 60);
    run_at(&mut store, T0 + 3 * DAY);
    assert_eq!(
        samples_from(&store, 0),
        8 * 1440,
        "each minute of the last eight days keeps its own sample"
    );
}

#[test]
fn after_a_long_downtime_the_clock_is_believed_within_a_day() {
    let (_directory, mut store) = history_of(90, 3600);
    // Back a month later, with a run every ten minutes: for a day nothing goes.
    let back = T0 + 30 * DAY;
    for run in 0..144 {
        run_at(&mut store, back + run * 600);
        assert_eq!(samples_from(&store, 0), 90 * 24, "run {run}");
    }
    // Then the clock has kept its time for a day, and the history keeps 90
    // days by it.
    run_at(&mut store, back + DAY);
    let kept = samples_from(&store, back + DAY - 90 * DAY);
    assert_eq!((samples_from(&store, 0), kept), (59 * 24, 59 * 24));
}

#[test]
fn a_stored_document_that_is_no_snapshot_is_an_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    drop(StatusStore::open(&path, 90).unwrap());
    let db = Connection::open(&path).unwrap();
    assert_eq!(latest_snapshot(&db).unwrap(), None, "before the first run");
    let more = r#"{"schemaVersion": 1, "collectedAt": "", "observations": [],
                   "providerErrors": [], "more": 1}"#;
    for document in ["not json", "{}", more] {
        db.execute(
            "INSERT INTO snapshots(collected_at, document) VALUES(1, ?)",
            [document],
        )
        .unwrap();
        assert!(
            matches!(latest_snapshot(&db), Err(SnapshotError::Unreadable(_))),
            "{document}"
        );
    }
}
