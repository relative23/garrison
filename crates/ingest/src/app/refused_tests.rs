//! Batches that are refused while the receiver runs: nothing of such a
//! batch is stored, the time is kept, the health answer says it, and what
//! was lost becomes a gap.

use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::body::Body;
use axum::http::Request;

use super::tests::{batch, call, signed};
use super::*;
use crate::answers::Receiver as State;
use crate::coverage;
use crate::store::Limits;
use crate::store::tests::{event, read, store};

const KEY: &[u8] = b"test-signature-key-0123456789";
const START: i64 = 1_793_000_000;
/// The time of the events' own, which is `START`.
const WRITTEN: &str = "2026-10-26T07:33:20Z";

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
    let body = batch(&[event(1, "auth.failed", WRITTEN, &json!({}))]);
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
    let body = batch(&[event(1, "auth.failed", WRITTEN, &json!({}))]);
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

fn stored(directory: &Path) -> i64 {
    read(directory)
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap()
}

fn one(seq: u64) -> Vec<u8> {
    batch(&[event(seq, "auth.failed", WRITTEN, &json!({}))])
}

#[tokio::test]
async fn a_batch_that_fills_the_database_is_refused_whole() {
    let directory = tempfile::tempdir().unwrap();
    // The file may grow to 256 KiB, twice the budget: room for some
    // thirteen hundred of these events.
    let limits = Limits::new(30, 1_000_000, 128 * 1024);
    let events =
        Arc::new(EventStore::open(&directory.path().join("events.sqlite"), limits).unwrap());
    events.start(START).unwrap();
    let app = router_with_clock(Arc::clone(&events), KEY, || START);
    assert_eq!(call(&app, signed(&one(0))).await.1["stored"], 1);
    // Five thousand at once: the database is full a quarter of the way
    // through the batch.
    let many: Vec<Value> = (1..=5000)
        .map(|seq| event(seq, "auth.failed", WRITTEN, &json!({})))
        .collect();
    assert_eq!(
        call(&app, signed(&batch(&many))).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "Storage unavailable"})
        )
    );
    // None of it was stored, not even the events that fitted, and the
    // refusal is counted.
    assert_eq!(stored(directory.path()), 1);
    assert_eq!(call(&app, health()).await.1["refused"], 1);
    // A batch that fits is stored as before.
    assert_eq!(call(&app, signed(&one(9000))).await.1["stored"], 1);
    assert_eq!(stored(directory.path()), 2);
}

#[tokio::test]
async fn a_batch_the_file_system_does_not_take_is_refused_whole() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let folder = directory.path();
    let events = Arc::new(store(folder, 1000));
    events.start(START).unwrap();
    let app = router_with_clock(Arc::clone(&events), KEY, || START);
    let body = batch(&[
        event(1, "auth.failed", WRITTEN, &json!({})),
        event(2, "auth.failed", WRITTEN, &json!({})),
    ]);
    // A write's journal cannot be made in a directory that takes no new
    // file, as on a file system that went read-only.
    let mode = |bits| std::fs::set_permissions(folder, std::fs::Permissions::from_mode(bits));
    mode(0o500).unwrap();
    // Root makes files all the same, and learns nothing here.
    let privileged = std::fs::write(folder.join("probe"), "").is_ok();
    let answer = if privileged {
        None
    } else {
        Some(call(&app, signed(&body)).await)
    };
    mode(0o700).unwrap();
    let Some(answer) = answer else {
        return;
    };
    assert_eq!(
        answer,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "Storage unavailable"})
        )
    );
    assert_eq!(stored(folder), 0);
    // Writable again, the same batch is stored whole.
    assert_eq!(
        call(&app, signed(&body)).await.1,
        json!({"status": "stored", "stored": 2, "skipped": 0})
    );
}
