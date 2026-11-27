use std::path::Path;
use std::time::Duration;

use garrison_core::sqlite::{Reader, reading};
use serde_json::json;

use super::*;
use crate::coverage;
use crate::queries::{self, Filter};

pub(crate) const SPAN: u64 = 337_538_776_114_949_120;
pub(crate) const QUEUE: u64 = 337_538_776_689_541_120;

/// An event in Stalwart's webhook shape; `data` holds the event's fields.
pub(crate) fn event(seq: u64, kind: &str, at: &str, data: &Value) -> Value {
    json!({"id": (17_932_310_300_000 + seq).to_string(), "createdAt": at, "type": kind, "data": data})
}

pub(crate) const AT: &str = "2026-10-28T23:43:50Z";

pub(crate) fn store(directory: &Path, max_events: u32) -> EventStore {
    EventStore::open(
        &directory.join("events.sqlite"),
        Limits::new(30, max_events, 64 * 1024 * 1024),
    )
    .unwrap()
}

impl EventStore {
    /// Store a batch that arrives as its newest event is written: the time
    /// of an arrival these tests do not ask about.
    pub(crate) fn arriving(&self, events: &[Value]) -> Result<Outcome, SqliteError> {
        let newest = events
            .iter()
            .filter_map(|event| event.get("createdAt").and_then(parse_time))
            .max();
        let received = newest.unwrap_or(0);
        self.passed(received);
        self.ingest(events, received)
    }

    /// The time passed to `now` under the receiver's looks, which come
    /// every thirty seconds: for tests that ask about something else than
    /// its clock, so that it is believed there.
    pub(crate) fn passed(&self, now: i64) {
        clock::passed(&self.state().db, now).unwrap();
    }
}

pub(crate) fn read(directory: &Path) -> Reader {
    reading(&directory.join("events.sqlite"), Duration::from_secs(2))
        .unwrap()
        .unwrap()
}

#[test]
fn the_privacy_filter_keeps_identifiers_exact() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let outcome = events
        .arriving(&[
            event(
                1,
                "queue.message-queued",
                AT,
                &json!({"queueId": QUEUE, "spanId": SPAN, "to": ["a@example.test"],
                            "blobId": "secret-blob", "details": "x".repeat(1000)}),
            ),
            event(2, "smtp.raw-input", AT, &json!({"contents": "DATA ..."})), // Never selected.
            event(
                3,
                "smtp.mail-from",
                AT,
                &json!({"spanId": SPAN, "from": "s@example.net", "details": "client text"}),
            ),
        ])
        .unwrap();
    assert_eq!(
        outcome,
        Outcome {
            stored: 2,
            skipped: 1,
            ..Outcome::default()
        }
    );
    let db = read(directory.path());
    let rows = json!(queries::list_events(&db, &Filter::default()).unwrap().items);
    let types: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["smtp.mail-from", "queue.message-queued"]);
    let queued = &rows[1];
    assert_eq!(queued["queueId"], json!(QUEUE.to_string())); // Exact 64-bit value as text.
    assert!(queued["fields"].get("blobId").is_none());
    assert_eq!(queued["fields"]["details"].as_str().unwrap().len(), 300);
    // Free-form text from SMTP clients is not kept.
    assert!(rows[0]["fields"].get("details").is_none());
    assert_eq!(rows[0]["label"], "SMTP MAIL FROM command");
}

#[test]
fn a_retried_batch_is_stored_once() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let batch = [event(
        1,
        "smtp.ehlo",
        AT,
        &json!({"spanId": SPAN, "domain": "client.example.net"}),
    )];
    let at = time::parse(AT).unwrap().as_second();
    assert_eq!(
        events.ingest(&batch, at + 10).unwrap(),
        Outcome {
            stored: 1,
            ..Outcome::default()
        }
    );
    assert_eq!(
        events.ingest(&batch, at + 20).unwrap(),
        Outcome {
            stored: 0,
            skipped: 1,
            duplicate: 1,
            unreadable: 0
        }
    );
    let db = read(directory.path());
    let (count, spans): (i64, i64) = db
        .query_row(
            "SELECT (SELECT count(*) FROM events), (SELECT event_count FROM spans)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((count, spans), (1, 1));
}

#[test]
fn unrecordable_events_are_skipped() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let data = json!({});
    let batch = [
        json!("not an object"),
        event(1, "unknown.event", AT, &data),
        event(2, "smtp.ehlo", "2026-10-28T23:43:50", &data), // No offset.
        event(3, "smtp.ehlo", &"2".repeat(41), &data),
        json!({"id": true, "createdAt": AT, "type": "smtp.ehlo"}),
        json!({"id": 1.5, "createdAt": AT, "type": "smtp.ehlo"}),
        json!({"id": "x".repeat(41), "createdAt": AT, "type": "smtp.ehlo"}),
        json!({"id": 42, "createdAt": "2026-10-28T23:43:50.999+01:00", "type": "smtp.ehlo"}),
    ];
    assert_eq!(
        events.arriving(&batch).unwrap(),
        // Two are no event of a recorded type; five are, and do not read.
        Outcome {
            stored: 1,
            skipped: 7,
            duplicate: 0,
            unreadable: 5
        }
    );
    let db = read(directory.path());
    let (id, created, fields): (String, i64, String) = db
        .query_row(
            "SELECT event_id, created_at, fields FROM events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((id.as_str(), fields.as_str()), ("42", "{}"));
    assert_eq!(
        created,
        time::parse("2026-10-28T22:43:50Z").unwrap().as_second()
    );
}

#[test]
fn receiver_downtime_longer_than_the_buffer_is_a_gap() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events.start(1000).unwrap();
    events.heartbeat(1030).unwrap();
    events.start(1030 + 3600 + 600).unwrap(); // Down for longer than discardAfter.
    events.start(1030 + 3600 + 600 + 60).unwrap(); // A short restart loses nothing.
    let db = read(directory.path());
    let coverage = json!(coverage::read(Some(&db), 5300).unwrap());
    assert_eq!(
        coverage["gaps"],
        json!([{"start": 1030, "end": 1630, "reason": "receiver-offline"}])
    );
    assert_eq!(coverage["recordingSince"], 1000);
    assert_eq!(coverage["receiver"], "running");
    assert_eq!(
        coverage::read(Some(&db), 5381).unwrap().receiver,
        crate::answers::Receiver::Stale
    );
}

#[test]
fn capacity_eviction_is_visible() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let batch: Vec<Value> = (0..1100)
        .map(|index| {
            let at = format!("2026-10-28T10:{:02}:{:02}Z", index / 60, index % 60);
            event(index, "auth.failed", &at, &json!({}))
        })
        .collect();
    events.arriving(&batch).unwrap();
    events.enforce_limits(1_793_000_000).unwrap();
    let db = read(directory.path());
    let coverage = json!(coverage::read(Some(&db), 0).unwrap());
    assert_eq!(coverage["eventCount"], 1000);
    // The hundred oldest are gone: the history begins after the last of them.
    let until = time::parse("2026-10-28T10:01:39Z").unwrap().as_second();
    assert_eq!(
        coverage["trimmed"],
        json!({"until": until, "limit": "events"})
    );
    assert_eq!(
        (&coverage["gapCount"], &coverage["gaps"]),
        (&json!(0), &json!([]))
    );
}

#[test]
fn retention_removes_old_events_and_groups() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let old = event(
        1,
        "queue.message-queued",
        "2026-09-01T00:00:00Z",
        &json!({"queueId": QUEUE}),
    );
    let new = event(2, "smtp.ehlo", AT, &json!({"spanId": SPAN}));
    // Each arrives as it is written; the old one is older than the 30 days
    // by the time retention runs.
    events.arriving(&[old]).unwrap();
    events.arriving(&[new]).unwrap();
    events
        .enforce_limits(time::parse(AT).unwrap().as_second())
        .unwrap();
    let db = read(directory.path());
    let left: (i64, i64, i64) = db
        .query_row(
            "SELECT (SELECT count(*) FROM events), (SELECT count(*) FROM queues), \
             (SELECT count(*) FROM spans)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(left, (1, 0, 1));
}

#[test]
fn the_file_is_shared_with_readers_only() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    store(directory.path(), 10);
    let mode = std::fs::metadata(directory.path().join("events.sqlite"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o640);
}

/// The numbers of the events of one type that `filter` lists, page by page.
fn listed(db: &Connection, filter: &Filter) -> Vec<i64> {
    let mut numbers = Vec::new();
    let mut before = None;
    loop {
        let filter = Filter {
            event_type: "auth.failed".into(),
            limit: 7,
            before,
            ..filter.clone()
        };
        let page = queries::list_events(db, &filter).unwrap();
        numbers.extend(page.items.iter().map(|item| item.seq));
        before = page.next;
        if before.is_none() {
            return numbers;
        }
    }
}

#[test]
fn a_types_events_are_listed_by_arrival_and_found_by_their_own_time() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    // Sixty events of two types; every fifth arrived forty seconds late, so
    // the order of arrival is not the order of time.
    let batch: Vec<Value> = (0..60_u64)
        .map(|index| {
            let kind = if index % 2 == 0 {
                "auth.failed"
            } else {
                "smtp.ehlo"
            };
            let second = 100 + index - if index % 5 == 0 { 40 } else { 0 };
            let at = format!("2026-10-28T23:{:02}:{:02}Z", second / 60, second % 60);
            event(index, kind, &at, &json!({}))
        })
        .collect();
    assert_eq!(events.ingest(&batch, 1_793_231_000).unwrap().stored, 60);
    let db = read(directory.path());
    assert_eq!(
        listed(&db, &Filter::default()),
        (1..=60)
            .rev()
            .filter(|number| number % 2 == 1)
            .collect::<Vec<i64>>()
    );
    // Before 23:01:40 lie only the late ones.
    let early = Filter {
        until: Some(time::parse("2026-10-28T23:01:39Z").unwrap().as_second()),
        ..Filter::default()
    };
    assert_eq!(listed(&db, &early), [31, 21, 11, 1]);
    // SQLite reads a page's choice from the index and sorts nothing.
    let plan: Vec<String> = db
        .prepare(
            "EXPLAIN QUERY PLAN SELECT seq FROM events \
             WHERE type='a' AND created_at>=1 ORDER BY seq DESC LIMIT 5",
        )
        .unwrap()
        .query_map([], |row| row.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        plan,
        ["SEARCH events USING COVERING INDEX events_type (type=?)"]
    );
}
