use std::collections::BTreeMap;
use std::time::Duration;

use garrison_core::sqlite::{self, reading};
use rusqlite::Connection;
use serde_json::Value;

use super::*;
use crate::snapshot::{SCHEMA, Snapshot};
use crate::store::{History, MIGRATIONS, StatusStore, history};

/// 2026-10-28T10:00:00Z, the tests' last minute and a step's start.
const END: i64 = 1_793_181_600;
const DAY: i64 = 86400;

/// Minute samples of a gauge and a counter over `days` before [`END`]: the
/// gauge misses every 23rd minute, both miss one hour on the second day, as
/// a collector that stopped.
fn minutes(db: &Connection, days: i64) {
    let mut insert = db
        .prepare("INSERT INTO samples(name, ts, value, kind) VALUES(?,?,?,?)")
        .unwrap();
    let away = (END - days * DAY + DAY + 3600)..(END - days * DAY + DAY + 7200);
    for ts in (END - days * DAY..END).step_by(60) {
        if away.contains(&ts) {
            continue;
        }
        let minute = ts / 60;
        if minute % 23 != 0 {
            let load = f64::from(u8::try_from(minute % 17).unwrap()) / 4.0;
            insert.execute(params!["load", ts, load, "gauge"]).unwrap();
        }
        let sent = f64::from(u8::try_from(minute % 5).unwrap());
        insert
            .execute(params!["sent", ts, sent, "increase"])
            .unwrap();
    }
}

/// One run's thinning at `minute`.
fn run(store: &mut StatusStore, minute: i64) {
    let mut transaction = store.db.transaction().unwrap();
    thin(&mut transaction, minute).unwrap();
    transaction.commit().unwrap();
}

/// Runs at `minute` until nothing is left to thin; how many thinned.
fn thin_all(store: &mut StatusStore, minute: i64) -> usize {
    let mut runs = 0;
    loop {
        let before = kept(store);
        run(store, minute);
        if kept(store) == before {
            return runs;
        }
        runs += 1;
    }
}

fn kept(store: &StatusStore) -> Option<String> {
    store
        .db
        .query_row("SELECT value FROM memory WHERE key = ?", [KEPT], |row| {
            row.get(0)
        })
        .optional()
        .unwrap()
}

fn rows(db: &Connection, from: i64, to: i64) -> Vec<(String, i64, f64, String, i64)> {
    db.prepare(
        "SELECT name, ts, value, kind, minutes FROM samples WHERE ts >= ? AND ts < ? \
         ORDER BY name, ts",
    )
    .unwrap()
    .query_map([from, to], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })
    .unwrap()
    .collect::<rusqlite::Result<_>>()
    .unwrap()
}

/// Two numbers that differ by no more than rounding does.
fn near(left: &Value, right: &Value) -> bool {
    match (left.as_f64(), right.as_f64()) {
        (Some(left), Some(right)) => (left - right).abs() <= 1e-9 * left.abs().max(1.0),
        _ => left == right,
    }
}

/// The same buckets, totals and coverage, each value up to rounding.
fn same(left: &History, right: &History, context: &str) {
    assert_eq!(left.points.len(), right.points.len(), "{context}");
    for (left, right) in left.points.iter().zip(&right.points) {
        assert_eq!(
            left.keys().collect::<Vec<_>>(),
            right.keys().collect::<Vec<_>>(),
            "{context}"
        );
        for (name, value) in left {
            assert!(
                near(value, &right[name]),
                "{context}: {name} {value} {}",
                right[name]
            );
        }
    }
    for (name, value) in &left.totals {
        assert!(
            near(value, &right.totals[name]),
            "{context}: total of {name}"
        );
    }
    assert_eq!(
        (
            left.sampled_minutes,
            left.coverage_from,
            left.counter_resets
        ),
        (
            right.sampled_minutes,
            right.coverage_from,
            right.counter_resets
        ),
        "{context}"
    );
}

#[test]
fn a_thinned_history_reads_as_its_minutes_did() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StatusStore::open(&directory.path().join("status.sqlite"), 90).unwrap();
    minutes(&store.db, 12);
    // Buckets of whole steps: a day, six hours, an hour.
    let ranges = [
        (END - 12 * DAY, END - 8 * DAY, 4),
        (END - 12 * DAY, END, 48),
        (END - 11 * DAY, END - 10 * DAY, 24),
    ];
    let before: Vec<History> = ranges
        .iter()
        .map(|(from, to, buckets)| history(&store.db, *from, *to, *buckets).unwrap())
        .collect();
    assert_eq!(thin_all(&mut store, END), 4, "one day in each run");
    for ((from, to, buckets), before) in ranges.iter().zip(&before) {
        let after = history(&store.db, *from, *to, *buckets).unwrap();
        same(before, &after, &format!("{from}..{to} in {buckets}"));
        if *to == END {
            assert_eq!(before.latest, after.latest, "the newest minutes are kept");
        }
    }
    // Before the horizon one sample per series and step, after it every minute.
    let thinned = rows(&store.db, END - 12 * DAY, END - 8 * DAY);
    assert!(thinned.iter().all(|(_, ts, ..)| ts % STEP == 0));
    assert_eq!(
        thinned.iter().filter(|row| row.0 == "sent").count(),
        4 * 144 - 6,
        "the hour the collector was away stays empty"
    );
    assert!(thinned.iter().any(|row| row.4 == 10) && thinned.iter().any(|row| row.4 == 9));
    let fine = rows(&store.db, END - 8 * DAY, END);
    assert!(fine.iter().all(|row| row.4 == 1));
    assert_eq!(fine.iter().filter(|row| row.0 == "sent").count(), 8 * 1440);
}

#[test]
fn each_run_thins_one_day_from_where_the_last_stopped() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StatusStore::open(&directory.path().join("status.sqlite"), 90).unwrap();
    minutes(&store.db, 11);
    for (day, stopped) in [(1, END - 10 * DAY), (2, END - 9 * DAY), (3, END - 8 * DAY)] {
        run(&mut store, END);
        assert_eq!(kept(&store), Some(stopped.to_string()), "run {day}");
    }
    let untouched = rows(&store.db, END - 8 * DAY, END);
    run(&mut store, END);
    assert_eq!(
        kept(&store),
        Some((END - 8 * DAY).to_string()),
        "nothing closer"
    );
    assert_eq!(rows(&store.db, END - 8 * DAY, END), untouched);
    // A minute later nothing is due either: a step goes once it is whole.
    run(&mut store, END + 60);
    assert_eq!(kept(&store), Some((END - 8 * DAY).to_string()));
    run(&mut store, END + STEP);
    assert_eq!(kept(&store), Some((END - 8 * DAY + STEP).to_string()));
    // Without samples there is nothing to start from.
    let empty = tempfile::tempdir().unwrap();
    let mut store = StatusStore::open(&empty.path().join("status.sqlite"), 90).unwrap();
    run(&mut store, END);
    assert_eq!(kept(&store), None);
}

#[test]
fn thinning_again_changes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StatusStore::open(&directory.path().join("status.sqlite"), 90).unwrap();
    minutes(&store.db, 10);
    thin_all(&mut store, END);
    let once = rows(&store.db, 0, END);
    store
        .db
        .execute("DELETE FROM memory WHERE key = ?", [KEPT])
        .unwrap();
    thin_all(&mut store, END);
    let twice = rows(&store.db, 0, END);
    assert_eq!(once.len(), twice.len());
    for (once, twice) in once.iter().zip(&twice) {
        assert_eq!(
            (&once.0, once.1, &once.3, once.4),
            (&twice.0, twice.1, &twice.3, twice.4)
        );
        assert!((once.2 - twice.2).abs() <= 1e-9, "{once:?} {twice:?}");
    }
}

#[test]
fn a_step_without_its_first_minute_and_a_name_of_both_kinds() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StatusStore::open(&directory.path().join("status.sqlite"), 90).unwrap();
    let step = END - 10 * DAY;
    let mut insert = store
        .db
        .prepare("INSERT INTO samples(name, ts, value, kind) VALUES(?,?,?,?)")
        .unwrap();
    for minute in 1..10 {
        insert
            .execute(params![
                "load",
                step + minute * 60,
                f64::from(u8::try_from(minute).unwrap()),
                "gauge"
            ])
            .unwrap();
    }
    for minute in 0..10 {
        insert
            .execute(params!["sent", step + minute * 60, 1.0, "increase"])
            .unwrap();
    }
    insert
        .execute(params!["mixed", step, 100.0, "gauge"])
        .unwrap();
    insert
        .execute(params!["mixed", step + 60, 3.0, "increase"])
        .unwrap();
    insert
        .execute(params!["mixed", step + 120, 4.0, "increase"])
        .unwrap();
    drop(insert);
    run(&mut store, END);
    assert_eq!(
        rows(&store.db, step, step + STEP),
        [
            ("load".to_owned(), step, 5.0, "gauge".to_owned(), 9),
            ("mixed".to_owned(), step, 7.0, "increase".to_owned(), 2),
            ("sent".to_owned(), step, 10.0, "increase".to_owned(), 10),
        ]
    );
}

#[test]
fn a_database_of_the_release_before_is_read_and_then_migrated() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    {
        // As 0.1.1 left it: the first schema, rows of four columns.
        let db = Connection::open(&path).unwrap();
        sqlite::migrate(&db, &MIGRATIONS[..1]).unwrap();
        for minute in 0..30 {
            db.execute(
                "INSERT INTO samples VALUES('load', ?, ?, 'gauge')",
                params![
                    END - 3600 + minute * 60,
                    f64::from(u8::try_from(minute % 4).unwrap())
                ],
            )
            .unwrap();
        }
    }
    // The web service may read it before the collector's next run migrates it.
    let unmigrated = {
        let reader = reading(&path, Duration::from_secs(2)).unwrap().unwrap();
        history(&reader, END - 3600, END, 6).unwrap()
    };
    assert_eq!(unmigrated.sampled_minutes, 30);
    let store = StatusStore::open(&path, 90).unwrap();
    let version: i64 = store
        .db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 2);
    assert!(rows(&store.db, 0, END).iter().all(|row| row.4 == 1));
    assert_eq!(history(&store.db, END - 3600, END, 6).unwrap(), unmigrated);
}

#[test]
fn the_store_thins_as_it_writes() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StatusStore::open(&directory.path().join("status.sqlite"), 90).unwrap();
    minutes(&store.db, 9);
    let snapshot = Snapshot {
        schema_version: SCHEMA,
        collected_at: String::new(),
        observations: Vec::new(),
        provider_errors: Vec::new(),
    };
    let load = BTreeMap::from([("load".to_owned(), 1.0)]);
    store
        .write(END, &snapshot, &load, &BTreeMap::new())
        .unwrap();
    assert_eq!(kept(&store), Some((END - 8 * DAY).to_string()));
    assert!(
        rows(&store.db, END - 9 * DAY, END - 8 * DAY)
            .iter()
            .all(|row| row.1 % STEP == 0)
    );
    // The run's own sample is there as well.
    assert_eq!(rows(&store.db, END, END + 60).len(), 1);
}
