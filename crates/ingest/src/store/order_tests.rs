//! The order of the history: the order in which the receiver stored the
//! events, as SQLite numbers each one past the greatest number. The event
//! history's pages, the summaries of attacks and destinations, which read
//! the newest events of a stretch first, and doctor's last arrival go by it.

use serde_json::json;

use super::tests::{event, read, store};
use super::*;
use crate::queries::{self, Filter};

const NOW: i64 = 1_793_000_000;

/// An event whose number is the greatest integer, as a damaged or
/// hand-edited history may hold, has SQLite number every later event at
/// random. It costs that event's number alone: the events stored after it
/// are listed newest first, in the order they arrived, and the newest by
/// number is the one stored last.
#[test]
fn an_event_of_the_greatest_number_keeps_the_later_ones_in_order() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let dated = |index: u64, second: i64| {
        let at = time::isoformat(time::Timestamp::from_second(second).unwrap());
        event(index, "auth.failed", &at, &json!({}))
    };
    events.ingest(&[dated(0, NOW - 3600)], NOW - 3600).unwrap();
    events
        .state()
        .db
        .execute("UPDATE events SET seq = ?1", [i64::MAX])
        .unwrap();
    let at = |index: u64| NOW - 600 + i64::try_from(index).unwrap();
    for index in 1..=30 {
        events
            .ingest(&[dated(index, at(index))], at(index))
            .unwrap();
    }
    let db = read(directory.path());
    let filter = Filter {
        limit: 10,
        ..Filter::default()
    };
    let page = queries::list_events(&db, &filter).unwrap();
    let listed: Vec<i64> = page.items.iter().map(|item| item.created_at).collect();
    let newest: Vec<i64> = (21..=30).rev().map(at).collect();
    assert_eq!(listed, newest);
    let last: i64 = db
        .query_row(
            "SELECT received_at FROM events ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last, at(30));
}
