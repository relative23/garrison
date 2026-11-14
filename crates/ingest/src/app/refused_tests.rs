//! Batches that are refused while the receiver runs: the time is kept, the
//! health answer says it, and what was lost becomes a gap.

use std::sync::atomic::{AtomicI64, Ordering};

use axum::body::Body;
use axum::http::Request;

use super::tests::{batch, call, signed};
use super::*;
use crate::answers::Receiver as State;
use crate::coverage;
use crate::store::tests::{AT, event, read, store};

const KEY: &[u8] = b"test-signature-key-0123456789";
const START: i64 = 1_793_000_000;

fn health() -> Request<Body> {
    Request::get("/health").body(Body::empty()).unwrap()
}

/// A request signed with a key that is not the receiver's.
fn foreign(body: &[u8]) -> Request<Body> {
    Request::post("/webhook")
        .header("Content-Length", body.len())
        .header("Content-Type", "application/json")
        .header("X-Signature", signature(b"another-key-0123456789", body))
        .body(Body::from(body.to_vec()))
        .unwrap()
}

static KEY_CLOCK: AtomicI64 = AtomicI64::new(START);

#[tokio::test]
async fn a_signature_key_that_no_longer_matches_is_counted_and_leaves_a_gap() {
    let directory = tempfile::tempdir().unwrap();
    let events = Arc::new(store(directory.path(), 1000));
    events.start(START).unwrap();
    let app = router_with_clock(Arc::clone(&events), KEY, || {
        KEY_CLOCK.load(Ordering::SeqCst)
    });
    let body = batch(&[event(1, "auth.failed", AT, &json!({}))]);
    assert_eq!(
        call(&app, health()).await,
        (
            StatusCode::OK,
            json!({"status": "ok", "failingSince": null, "refused": 0, "unreadable": 0, "duplicate": 0})
        )
    );
    // Stalwart signs with a key the receiver does not have: every batch is
    // refused, and the receiver runs on.
    KEY_CLOCK.store(START + 60, Ordering::SeqCst);
    for _ in 0..3 {
        assert_eq!(call(&app, foreign(&body)).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        call(&app, health()).await.1,
        json!({"status": "failing", "failingSince": START + 60, "refused": 3, "unreadable": 0, "duplicate": 0})
    );
    events.heartbeat(START + 7000).unwrap();
    let during = coverage::read(Some(&read(directory.path())), START + 7000).unwrap();
    assert_eq!(during.receiver, State::Refusing);
    assert_eq!(during.failing_since, Some(START + 60));
    // Two hours later the key is right again. Of what Stalwart tried to
    // send, it kept the last hour.
    KEY_CLOCK.store(START + 60 + 7200, Ordering::SeqCst);
    assert_eq!(call(&app, signed(&body)).await.0, StatusCode::OK);
    let after = coverage::read(Some(&read(directory.path())), START + 60 + 7200).unwrap();
    assert_eq!(
        (after.receiver, after.failing_since),
        (State::Running, None)
    );
    assert_eq!(after.gap_count, 1);
    assert_eq!(
        (
            after.gaps[0].start,
            after.gaps[0].end,
            after.gaps[0].reason.as_str()
        ),
        (START + 60, START + 60 + 3600, "batches-refused")
    );
    assert_eq!(call(&app, health()).await.1["status"], "ok");
}

static FULL_CLOCK: AtomicI64 = AtomicI64::new(START);

#[tokio::test]
async fn a_database_that_takes_nothing_is_counted_and_leaves_a_gap() {
    let directory = tempfile::tempdir().unwrap();
    let events = Arc::new(store(directory.path(), 1000));
    events.start(START).unwrap();
    let app = router_with_clock(Arc::clone(&events), KEY, || {
        FULL_CLOCK.load(Ordering::SeqCst)
    });
    let body = batch(&[event(1, "auth.failed", AT, &json!({}))]);
    // Another connection holds the database, as a full or read-only one
    // would refuse every write: the batch is not stored, and nothing of it.
    let holder = rusqlite::Connection::open(directory.path().join("events.sqlite")).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    FULL_CLOCK.store(START + 30, Ordering::SeqCst);
    assert_eq!(
        call(&app, signed(&body)).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "Storage unavailable"})
        )
    );
    holder.execute_batch("ROLLBACK").unwrap();
    let stored: i64 = read(directory.path())
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored, 0, "a failed batch stores none of its events");
    // The database could not be told; the receiver remembers all the same.
    assert_eq!(
        call(&app, health()).await.1,
        json!({"status": "failing", "failingSince": START + 30, "refused": 1, "unreadable": 0, "duplicate": 0})
    );
    // Stalwart brings the batch again, three hours later.
    FULL_CLOCK.store(START + 30 + 3 * 3600, Ordering::SeqCst);
    assert_eq!(
        call(&app, signed(&body)).await.1,
        json!({"status": "stored", "stored": 1, "skipped": 0})
    );
    let after = coverage::read(Some(&read(directory.path())), START + 30 + 3 * 3600).unwrap();
    assert_eq!(
        (
            after.gaps[0].start,
            after.gaps[0].end,
            after.gaps[0].reason.as_str()
        ),
        (START + 30, START + 30 + 2 * 3600, "batches-refused")
    );
}
