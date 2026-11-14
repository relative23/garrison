//! A receiver that runs but stores nothing: its heartbeat stays fresh, so
//! the time in which events were lost must be recorded another way.

use std::path::Path;

use rusqlite::Connection;
use serde_json::json;

use super::tests::{AT, event, store};
use super::*;

const START: i64 = 1_793_000_000;
const HOUR: i64 = 3600;

fn gaps(directory: &Path) -> Vec<(i64, i64, String)> {
    Connection::open(directory.join("events.sqlite"))
        .unwrap()
        .prepare("SELECT start_at,end_at,reason FROM gaps ORDER BY id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

/// A batch of one event that reads, written at `second`.
fn clean(seq: u64, second: i64) -> Vec<Value> {
    let at = time::isoformat(time::Timestamp::from_second(second).unwrap());
    vec![event(seq, "auth.failed", &at, &json!({}))]
}

#[test]
fn batches_refused_for_longer_than_stalwart_keeps_them_leave_a_gap() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events.start(START).unwrap();
    // The signature key no longer matches, or the database is full: every
    // batch is refused, while the receiver runs and its heartbeat is fresh.
    events.refused(START + 100);
    events.refused(START + 160);
    events.heartbeat(START + 3 * HOUR).unwrap();
    assert_eq!(events.health().failing_since, Some(START + 100));
    assert_eq!(events.health().refused, 2);
    assert_eq!(gaps(directory.path()), []);
    // Three hours later a batch is taken again. Stalwart kept the last hour
    // and brings it; what was refused before that is lost.
    let back = START + 100 + 3 * HOUR;
    events.ingest(&clean(1, back), back).unwrap();
    assert_eq!(
        gaps(directory.path()),
        [(
            START + 100,
            START + 100 + 2 * HOUR,
            "batches-refused".to_owned()
        )]
    );
    assert_eq!(events.health().failing_since, None);
    // A refusal that ends within the hour lost nothing: Stalwart brought
    // everything again.
    events.refused(START + 4 * HOUR);
    let back = START + 4 * HOUR + 600;
    events.ingest(&clean(2, back), back).unwrap();
    assert_eq!(gaps(directory.path()).len(), 1);
    assert_eq!(events.health().failing_since, None);
}

#[test]
fn events_of_a_recorded_type_that_cannot_be_read_leave_a_gap_at_once() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events.start(START).unwrap();
    // Stalwart changed how it writes an event: a type that is recorded, and
    // a time that no longer reads. The batch is answered as stored, so
    // Stalwart does not bring it again.
    let changed = json!({"id": "1", "createdAt": 1_793_000_100, "type": "auth.failed", "data": {}});
    let outcome = events
        .ingest(
            &[changed.clone(), clean(1, START + 100)[0].clone()],
            START + 100,
        )
        .unwrap();
    assert_eq!(
        (outcome.stored, outcome.skipped, outcome.unreadable),
        (1, 1, 1)
    );
    assert_eq!(events.health().failing_since, Some(START + 100));
    events.ingest(&[changed], START + 200).unwrap();
    assert_eq!(events.health().unreadable, 2);
    assert_eq!(gaps(directory.path()), []);
    // Once every event reads again, the time in between is a gap.
    events.ingest(&clean(2, START + 900), START + 900).unwrap();
    assert_eq!(
        gaps(directory.path()),
        [(START + 100, START + 900, "events-unreadable".to_owned())]
    );
    // What is not recorded at all, and what was stored before, is neither.
    let outcome = events
        .ingest(
            &[
                event(9, "smtp.raw-input", AT, &json!({})),
                clean(2, START + 900)[0].clone(),
                json!("no event"),
            ],
            START + 1000,
        )
        .unwrap();
    assert_eq!(
        (
            outcome.stored,
            outcome.skipped,
            outcome.duplicate,
            outcome.unreadable
        ),
        (0, 3, 1, 0)
    );
    assert_eq!(events.health().failing_since, None);
    assert_eq!(gaps(directory.path()).len(), 1);
}

#[test]
fn a_restart_does_not_forget_since_when_nothing_was_stored() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events.start(START).unwrap();
    events.refused(START + 100);
    drop(events);
    // The receiver is started anew within the minute: its heartbeat was
    // fresh, so the start records no gap of its own.
    let events = store(directory.path(), 1000);
    events.start(START + 130).unwrap();
    assert_eq!(events.health().failing_since, Some(START + 100));
    assert_eq!(gaps(directory.path()), []);
    let back = START + 100 + 5 * HOUR;
    events.ingest(&clean(1, back), back).unwrap();
    assert_eq!(
        gaps(directory.path()),
        [(
            START + 100,
            START + 100 + 4 * HOUR,
            "batches-refused".to_owned()
        )]
    );
}
