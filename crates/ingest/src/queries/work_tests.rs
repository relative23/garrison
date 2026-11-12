//! How much work the queries are, counted in steps of SQLite's virtual machine
//! and not in time, so the answer is the same on every machine. A page of a
//! list must cost the same in a history ten times as large: it is read along
//! an index. What looks at every event by design (a search) may grow with the
//! history, but only in proportion. A query that starts to scan or sort the
//! history fails here long before a reader meets its time budget on a full
//! history.
//!
//! Known to grow, and held to what it costs today: the events of one type in
//! a time range that lies back. The index holds a type's events newest
//! first, so the newer ones are passed on the way; they are passed in the
//! index, and no event is read for it.
//!
//! Steps do not see everything: `count(*)` is one step whatever it reads.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use garrison_core::time;
use rusqlite::{Connection, OpenFlags};
use serde_json::json;

use super::*;
use crate::coverage;
use crate::store::tests::event;
use crate::store::{EventStore, Limits};

/// 2026-10-28T10:00:00Z; one event a second from here.
const BEGINNING: i64 = 1_793_181_600;
const SMALL: i64 = 2_000;
const LARGE: i64 = 20_000;

/// A history of `count` events as a mail server produces them: sessions of
/// four events, every third of which queues a message that is delivered.
fn history(directory: &Path, count: i64) -> Connection {
    let path = directory.join("events.sqlite");
    let store = EventStore::open(&path, Limits::new(30, 10_000_000, 4 << 30)).unwrap();
    let mut batch = Vec::new();
    for index in 0..count {
        let at = time::isoformat(time::Timestamp::from_second(BEGINNING + index).unwrap());
        let session = index / 4;
        let (kind, data) = match index % 4 {
            0 => (
                "smtp.connection-start",
                json!({"spanId": session, "remoteIp": "192.0.2.1"}),
            ),
            1 => (
                "smtp.ehlo",
                json!({"spanId": session, "domain": "client.example.net"}),
            ),
            2 if session % 3 == 0 => (
                "queue.message-queued",
                json!({"spanId": session, "queueId": session, "to": [format!("user{}@example.test", session % 500)]}),
            ),
            2 => (
                "smtp.rcpt-to",
                json!({"spanId": session, "to": ["nobody@example.test"]}),
            ),
            _ if session % 3 == 0 => (
                "delivery.delivered",
                json!({"queueId": session, "to": ["a@example.test"]}),
            ),
            _ => ("smtp.connection-end", json!({"spanId": session})),
        };
        batch.push(event(u64::try_from(index).unwrap(), kind, &at, &data));
        if batch.len() == 1000 {
            store.ingest(&batch, BEGINNING + index).unwrap();
            batch.clear();
        }
    }
    store.ingest(&batch, BEGINNING + count).unwrap();
    drop(store);
    Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

/// The steps SQLite takes for `query`.
fn steps<T>(db: &mut Connection, query: impl FnOnce(&Connection) -> T) -> u64 {
    let taken = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&taken);
    db.progress_handler(
        1,
        Some(move || {
            counter.fetch_add(1, Ordering::Relaxed);
            false
        }),
    )
    .unwrap();
    query(db);
    db.progress_handler(0, None::<fn() -> bool>).unwrap();
    taken.load(Ordering::Relaxed)
}

/// Each query's work in the small and in the large history.
fn compared(query: impl Fn(&Connection)) -> (u64, u64) {
    let small = tempfile::tempdir().unwrap();
    let large = tempfile::tempdir().unwrap();
    (
        steps(&mut history(small.path(), SMALL), &query),
        steps(&mut history(large.path(), LARGE), &query),
    )
}

/// A page costs the same whatever the history's size: a deeper index is a
/// few steps, a scan would be ten times the work.
fn flat(name: &str, (small, large): (u64, u64)) {
    assert!(small > 0, "{name} was not counted");
    assert!(
        large <= small + small / 4 + 200,
        "{name}: {small} steps in {SMALL} events, {large} in {LARGE}"
    );
}

/// Work that looks at every event grows with the history and no faster.
fn proportional(name: &str, (small, large): (u64, u64)) {
    assert!(large > small, "{name} was expected to look at every event");
    assert!(
        large <= small * 12,
        "{name}: {small} steps in {SMALL} events, {large} in {LARGE}"
    );
}

#[test]
fn a_page_of_events_costs_the_same_in_a_larger_history() {
    flat(
        "the newest events",
        compared(|db| {
            let page = list_events(db, &Filter::default()).unwrap();
            assert_eq!(page.items.len(), 50);
        }),
    );
    flat(
        "a later page of events",
        compared(|db| {
            let filter = Filter {
                before: Some("900".into()),
                ..Filter::default()
            };
            assert_eq!(list_events(db, &filter).unwrap().items.len(), 50);
        }),
    );
    flat(
        "the events of one category",
        compared(|db| {
            let filter = Filter {
                category: "smtp".into(),
                ..Filter::default()
            };
            assert_eq!(list_events(db, &filter).unwrap().items.len(), 50);
        }),
    );
}

/// A quarter of the history is of this type; the delivered messages are a
/// twelfth of it.
#[test]
fn a_page_of_one_type_costs_the_same_in_a_larger_history() {
    let of_type = |filter: Filter| Filter {
        event_type: "smtp.ehlo".into(),
        ..filter
    };
    for (name, filter) in [
        ("the events of one type", of_type(Filter::default())),
        (
            "a later page of one type",
            of_type(Filter {
                before: Some("900".into()),
                ..Filter::default()
            }),
        ),
        (
            "the events of one type since a time",
            of_type(Filter {
                since: Some(BEGINNING + 500),
                ..Filter::default()
            }),
        ),
        (
            "the events of one type and its category",
            of_type(Filter {
                category: "smtp".into(),
                ..Filter::default()
            }),
        ),
        (
            "the events of a rare type",
            Filter {
                event_type: "delivery.delivered".into(),
                ..Filter::default()
            },
        ),
    ] {
        flat(
            name,
            compared(|db| assert_eq!(list_events(db, &filter).unwrap().items.len(), 50)),
        );
    }
    flat(
        "the events of a type there are none of",
        compared(|db| {
            let filter = Filter {
                event_type: "auth.failed".into(),
                ..Filter::default()
            };
            assert_eq!(list_events(db, &filter).unwrap().items, []);
        }),
    );
}

/// The first minutes of the history: every newer event of the type is passed
/// first. About one step for each event of the history, all in the index;
/// reading the events passed would be several times that.
#[test]
fn a_type_in_a_time_range_that_lies_back_passes_the_newer_ones_in_the_index() {
    let work = compared(|db| {
        let filter = Filter {
            event_type: "smtp.ehlo".into(),
            since: Some(BEGINNING + 100),
            until: Some(BEGINNING + 140),
            ..Filter::default()
        };
        assert_eq!(list_events(db, &filter).unwrap().items.len(), 10);
    });
    proportional("the events of one type in an early time range", work);
    assert!(
        work.1 <= u64::try_from(LARGE).unwrap() * 2,
        "the events of one type in an early time range: {} steps in {LARGE} events",
        work.1
    );
}

#[test]
fn a_page_of_deliveries_or_sessions_costs_the_same_in_a_larger_history() {
    let limit = Filter {
        limit: 25,
        ..Filter::default()
    };
    flat(
        "the newest deliveries",
        compared(|db| assert_eq!(list_deliveries(db, &limit).unwrap().items.len(), 25)),
    );
    flat(
        "the newest sessions",
        compared(|db| assert_eq!(list_sessions(db, &limit).unwrap().items.len(), 25)),
    );
    flat(
        "one delivery",
        compared(|db| assert!(delivery_detail(db, "30").unwrap().is_some())),
    );
    flat(
        "one session",
        compared(|db| assert!(session_detail(db, "31").unwrap().is_some())),
    );
}

#[test]
fn what_looks_at_every_event_grows_in_proportion() {
    proportional(
        "a search that finds nothing",
        compared(|db| {
            let filter = Filter {
                search: "nobody@example.invalid".into(),
                ..Filter::default()
            };
            assert_eq!(list_events(db, &filter).unwrap().items, []);
        }),
    );
}

#[test]
fn what_the_history_covers_costs_the_same_in_a_larger_history() {
    flat(
        "what the history covers",
        compared(|db| {
            coverage::read(Some(db), BEGINNING).unwrap();
        }),
    );
}
