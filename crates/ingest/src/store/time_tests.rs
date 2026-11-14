//! The time an event says it happened, against the time it arrived.

use serde_json::json;

use super::tests::{event, read, store};
use super::*;

const DAY: i64 = 86_400;
/// When the batches of these tests arrive.
const NOW: i64 = 1_793_000_000;

fn dated(seq: u64, second: i64) -> Value {
    let at = time::isoformat(time::Timestamp::from_second(second).unwrap());
    event(seq, "auth.failed", &at, &json!({}))
}

/// The times of the stored events, oldest first.
fn stored(directory: &Path) -> Vec<i64> {
    let db = read(directory);
    let mut statement = db
        .prepare("SELECT created_at FROM events ORDER BY created_at")
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn an_event_is_dated_between_what_the_history_keeps_and_its_arrival() {
    let directory = tempfile::tempdir().unwrap();
    // The history keeps 30 days.
    let events = store(directory.path(), 1000);
    let batch = [
        dated(1, NOW - 30 * DAY - 1),
        dated(2, NOW - 30 * DAY),
        dated(3, NOW),
        // Two clocks may differ by five minutes.
        dated(4, NOW + 300),
        dated(5, NOW + 301),
        event(6, "auth.failed", "9999-12-31T23:59:59Z", &json!({})),
        event(7, "auth.failed", "1970-01-01T00:00:00Z", &json!({})),
    ];
    assert_eq!(
        events.ingest(&batch, NOW).unwrap(),
        Outcome {
            stored: 3,
            skipped: 4,
            duplicate: 0,
            unreadable: 4
        }
    );
    assert_eq!(stored(directory.path()), [NOW - 30 * DAY, NOW, NOW + 300]);
    // The four went missing, and that is said as of any event that does
    // not read.
    assert_eq!(events.health().failing_since, Some(NOW));
    assert_eq!(events.health().unreadable, 4);
}

#[test]
fn events_dated_years_ahead_do_not_take_the_place_of_real_ones() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    // Retention goes by an event's own time and a size limit takes the
    // oldest first: events dated years ahead would outlive both.
    let ahead: Vec<Value> = (0..1000)
        .map(|index| dated(index, NOW + 3650 * DAY + i64::try_from(index).unwrap()))
        .collect();
    events.ingest(&ahead, NOW).unwrap();
    let real: Vec<Value> = (0..100)
        .map(|index| dated(5000 + index, NOW + i64::try_from(index).unwrap()))
        .collect();
    events.ingest(&real, NOW + 100).unwrap();
    events.enforce_limits(NOW + 100).unwrap();
    let expected: Vec<i64> = (NOW..NOW + 100).collect();
    assert_eq!(stored(directory.path()), expected);
    // No size limit moved the history's beginning to a time yet to come.
    let trimmed: i64 = read(directory.path())
        .query_row(
            "SELECT count(*) FROM gaps WHERE reason IN (?, ?)",
            [EVENT_LIMIT, STORAGE_BUDGET],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(trimmed, 0);
}

#[test]
fn a_batch_that_comes_again_later_is_known_by_its_events_own_times() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let batch = [dated(1, NOW - 20), dated(2, NOW + 200)];
    assert_eq!(events.ingest(&batch, NOW).unwrap().stored, 2);
    // Stalwart got no answer and brings the batch again: an event keeps the
    // time it carries, so it is the same event whenever it arrives.
    let again = events.ingest(&batch, NOW + 3000).unwrap();
    assert_eq!((again.stored, again.duplicate), (0, 2));
    assert_eq!(stored(directory.path()), [NOW - 20, NOW + 200]);
}
