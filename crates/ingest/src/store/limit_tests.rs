//! The store's limits at their exact boundaries.

use serde_json::json;

use super::tests::{event, read, store};
use super::*;

/// Events one second apart, starting at `start` (seconds since the epoch).
fn batch(count: u64, start: i64) -> Vec<Value> {
    (0..count)
        .map(|index| {
            let second = start + i64::try_from(index).unwrap();
            let at = time::isoformat(time::Timestamp::from_second(second).unwrap());
            event(index, "auth.failed", &at, &json!({}))
        })
        .collect()
}

fn gaps(directory: &Path) -> Vec<(i64, i64, String)> {
    let db = read(directory);
    let mut statement = db
        .prepare("SELECT start_at, end_at, reason FROM gaps ORDER BY id")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn count(directory: &Path) -> i64 {
    read(directory)
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap()
}

const START: i64 = 1_793_000_000;

#[test]
fn the_file_may_grow_to_twice_the_byte_budget() {
    let directory = tempfile::tempdir().unwrap();
    let events = EventStore::open(
        &directory.path().join("events.sqlite"),
        Limits::new(30, 1000, 64 * 1024 * 1024),
    )
    .unwrap();
    let state = events.state();
    let pages: i64 = state
        .db
        .pragma_query_value(None, "max_page_count", |row| row.get(0))
        .unwrap();
    let page: i64 = state
        .db
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .unwrap();
    assert_eq!(pages * page, 128 * 1024 * 1024);
}

#[test]
fn downtime_within_the_buffer_loses_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events.start(START).unwrap();
    events.start(START + 3600).unwrap();
    assert_eq!(gaps(directory.path()), []);
    events.start(START + 3600 + 3601).unwrap();
    assert_eq!(
        gaps(directory.path()),
        [(START + 3600, START + 3601, "receiver-offline".to_owned())]
    );
}

#[test]
fn cleanup_runs_by_itself_after_a_thousand_events() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let now = START + 40 * 86400;
    events.ingest(&batch(999, START), now).unwrap();
    assert_eq!(count(directory.path()), 999, "not yet");
    events.ingest(&batch(1, now), now).unwrap();
    assert_eq!(
        count(directory.path()),
        1,
        "expired events go after 1000 new ones"
    );
}

#[test]
fn retention_keeps_exactly_the_configured_days() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let now = START + 30 * 86400;
    events.ingest(&batch(3, START - 1), now).unwrap();
    events.enforce_limits(now).unwrap();
    assert_eq!(count(directory.path()), 2, "older than 30 days is gone");
}

#[test]
fn a_full_store_records_no_gap_until_it_overflows() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events.ingest(&batch(1000, START), START).unwrap();
    events.enforce_limits(START).unwrap();
    assert_eq!(gaps(directory.path()), []);
}

#[test]
fn a_limit_keeps_one_window_however_often_it_removes() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events.ingest(&batch(1100, START), START).unwrap();
    events.enforce_limits(START).unwrap();
    assert_eq!(
        gaps(directory.path()),
        [(START, START + 99, EVENT_LIMIT.to_owned())]
    );
    // Later events push out more of the oldest: the same window reaches further.
    for round in 1..=3 {
        let more: Vec<Value> = (0..50)
            .map(|index| {
                let second = START + 2000 + round * 100 + index;
                let at = time::isoformat(time::Timestamp::from_second(second).unwrap());
                let id = 5000 + (round * 100 + index).unsigned_abs();
                event(id, "auth.failed", &at, &json!({}))
            })
            .collect();
        events.ingest(&more, START).unwrap();
        events.enforce_limits(START).unwrap();
        assert_eq!(
            gaps(directory.path()),
            [(START, START + 99 + round * 50, EVENT_LIMIT.to_owned())]
        );
    }
    assert_eq!(count(directory.path()), 1000);
}

fn recording_since(directory: &Path) -> Option<String> {
    read(directory)
        .query_row(
            "SELECT value FROM metadata WHERE key='recordingSince'",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
}

#[test]
fn a_new_history_is_recorded_since_its_first_start() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events.start(START).unwrap();
    events.ingest(&batch(3, START - 500), START + 10).unwrap();
    events.start(START + 60).unwrap();
    assert_eq!(
        recording_since(directory.path()),
        Some(START.to_string()),
        "a later start keeps it, whatever arrived since"
    );
}

#[test]
fn the_byte_budget_drops_a_tenth_of_the_events() {
    let used = |directory: &Path| -> i64 {
        let db = read(directory);
        let pragma =
            |name: &str| -> i64 { db.pragma_query_value(None, name, |row| row.get(0)).unwrap() };
        (pragma("page_count") - pragma("freelist_count")) * pragma("page_size")
    };
    let measured = tempfile::tempdir().unwrap();
    store(measured.path(), 100_000)
        .ingest(&batch(200, START), START)
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let budget = used(measured.path()) - 1;
    let events = EventStore::open(
        &directory.path().join("events.sqlite"),
        Limits::new(30, 100_000, budget),
    )
    .unwrap();
    events.ingest(&batch(200, START), START).unwrap();
    events.enforce_limits(START).unwrap();
    assert_eq!(count(directory.path()), 180);
    assert_eq!(
        gaps(directory.path()),
        [(START, START + 19, "capacity-bytes".to_owned())]
    );
}

#[test]
fn free_pages_do_not_count_against_the_byte_budget() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.sqlite");
    let old = START - 40 * 86400;
    let expired: Vec<Value> = (0..400)
        .map(|index| {
            let at = time::isoformat(time::Timestamp::from_second(old + index).unwrap());
            event(
                10_000 + index.unsigned_abs(),
                "auth.failed",
                &at,
                &json!({}),
            )
        })
        .collect();
    let events = store(directory.path(), 100_000);
    events.ingest(&expired, START).unwrap();
    events.ingest(&batch(400, START), START).unwrap();
    // Retention deletes the expired half; its pages stay in the file, free.
    events.enforce_limits(START).unwrap();
    drop(events);
    let db = read(directory.path());
    let pragma =
        |name: &str| -> i64 { db.pragma_query_value(None, name, |row| row.get(0)).unwrap() };
    assert!(pragma("freelist_count") > 0);
    let used = (pragma("page_count") - pragma("freelist_count")) * pragma("page_size");
    drop(db);
    // A budget of exactly the used bytes is kept without dropping anything.
    let events = EventStore::open(&path, Limits::new(30, 100_000, used)).unwrap();
    events.enforce_limits(START).unwrap();
    assert_eq!(count(directory.path()), 400);
    assert_eq!(gaps(directory.path()), []);
}
