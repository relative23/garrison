use rusqlite::params;
use serde_json::json;

use super::*;
use crate::store::OFFLINE;
use crate::store::tests::{read as reader, store};

/// Put a window into the history's `gaps`, as the store would.
fn window(directory: &std::path::Path, start: i64, end: i64, reason: &str) {
    Connection::open(directory.join("events.sqlite"))
        .unwrap()
        .execute(
            "INSERT INTO gaps(start_at,end_at,reason) VALUES(?,?,?)",
            params![start, end, reason],
        )
        .unwrap();
}

#[test]
fn coverage_without_a_database_says_so() {
    let coverage = read(None, 0).unwrap();
    assert_eq!(
        (coverage.available, coverage.receiver),
        (false, Receiver::Unavailable)
    );
    assert_eq!(coverage.limitations, LIMITATIONS);
    // Every name the API states is there, with nothing known behind it.
    assert_eq!(
        json!(coverage),
        json!({
            "available": false, "receiver": "unavailable", "heartbeatAt": null,
            "recordingSince": null, "lastBatchAt": null, "retentionDays": null,
            "eventCount": 0, "trimmed": null, "gapCount": 0, "gaps": [],
            "limitations": LIMITATIONS,
        })
    );
}

#[test]
fn the_receiver_is_running_while_its_heartbeat_is_fresh() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events.heartbeat(1000).unwrap();
    let db = reader(directory.path());
    let at = |now| read(Some(&db), now).unwrap();
    assert_eq!(
        (at(1090).receiver, at(1090).heartbeat_at),
        (Receiver::Running, Some(1000))
    );
    assert_eq!(at(1091).receiver, Receiver::Stale);
    assert!(at(1090).available);
    for (receiver, name) in [
        (Receiver::Running, "running"),
        (Receiver::Stale, "stale"),
        (Receiver::Unavailable, "unavailable"),
    ] {
        assert_eq!(json!(receiver), name);
        assert_eq!(receiver.as_str(), name);
    }
}

#[test]
fn a_size_limit_moves_the_beginning_and_is_no_gap() {
    let directory = tempfile::tempdir().unwrap();
    store(directory.path(), 1000);
    window(directory.path(), 100, 200, EVENT_LIMIT);
    let db = reader(directory.path());
    let coverage = read(Some(&db), 0).unwrap();
    assert_eq!(
        coverage.trimmed,
        Some(Trimmed {
            until: 200,
            limit: Limit::Events
        })
    );
    assert_eq!(
        json!(coverage)["trimmed"],
        json!({"until": 200, "limit": "events"})
    );
    assert_eq!((coverage.gap_count, coverage.gaps), (0, Vec::new()));
}

#[test]
fn the_limit_that_reached_furthest_decides_where_the_history_begins() {
    let directory = tempfile::tempdir().unwrap();
    store(directory.path(), 1000);
    window(directory.path(), 100, 200, EVENT_LIMIT);
    window(directory.path(), 150, 260, STORAGE_BUDGET);
    window(directory.path(), 300, 400, OFFLINE);
    // A reason this release does not know is a gap, never silently nothing.
    window(directory.path(), 500, 600, "something-new");
    let db = reader(directory.path());
    let coverage = read(Some(&db), 0).unwrap();
    assert_eq!(
        coverage.trimmed,
        Some(Trimmed {
            until: 260,
            limit: Limit::Bytes
        })
    );
    assert_eq!(coverage.gap_count, 2);
    assert_eq!(
        json!(coverage.gaps),
        json!([
            {"start": 500, "end": 600, "reason": "something-new"},
            {"start": 300, "end": 400, "reason": OFFLINE},
        ])
    );
    for (limit, name) in [(Limit::Events, "events"), (Limit::Bytes, "bytes")] {
        assert_eq!(json!(limit), name);
        assert_eq!(limit.as_str(), name);
    }
}

#[test]
fn only_the_twenty_newest_gaps_are_listed_and_all_are_counted() {
    let directory = tempfile::tempdir().unwrap();
    store(directory.path(), 1000);
    for index in 0..25 {
        window(directory.path(), index * 10, index * 10 + 5, OFFLINE);
    }
    window(directory.path(), 0, 1000, EVENT_LIMIT);
    let db = reader(directory.path());
    let coverage = read(Some(&db), 0).unwrap();
    assert_eq!((coverage.gap_count, coverage.gaps.len()), (25, 20));
    assert_eq!((coverage.gaps[0].start, coverage.gaps[19].start), (240, 50));
}
