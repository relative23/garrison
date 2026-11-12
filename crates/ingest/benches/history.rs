//! How fast the event history takes a batch and answers a list or a search.
//!
//! ```sh
//! cargo bench -p garrison-ingest
//! ```
//!
//! The numbers belong to the machine and to the directory for temporary
//! files (a tmpfs leaves the disk out): compare a change with the commit
//! before it on the same machine. Nothing here is a limit a test checks.

// A benchmark fails by panicking, like a test.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use divan::Bencher;
use garrison_core::sqlite::reading;
use garrison_core::time::{self, Timestamp};
use garrison_ingest::answers::{DeliverySummary, EventItem, Page};
use garrison_ingest::queries::{Filter, list_deliveries, list_events};
use garrison_ingest::store::{EventStore, Limits};
use serde_json::{Value, json};

/// 2026-10-28T10:00:00Z; one event per second from here.
const START: u64 = 1_793_181_600;
/// The events of the history the queries read.
const STORED: u64 = 20_000;
/// A reader's time budget, as the web service sets it.
const BUDGET: Duration = Duration::from_secs(2);

/// The history the queries read, filled once.
static HISTORY: OnceLock<PathBuf> = OnceLock::new();
/// The history the batches go into; it grows while the benchmark runs.
static RECEIVER: OnceLock<EventStore> = OnceLock::new();
static NEXT: AtomicU64 = AtomicU64::new(0);

fn main() {
    let directory = tempfile::tempdir().unwrap();
    let history = directory.path().join("events.sqlite");
    let store = open(&history);
    for from in (0..STORED).step_by(1000) {
        store.ingest(&events(from, 1000), received(STORED)).unwrap();
    }
    drop(store);
    HISTORY.set(history).unwrap();
    RECEIVER
        .set(open(&directory.path().join("receiver.sqlite")))
        .unwrap();
    divan::main();
}

fn open(path: &Path) -> EventStore {
    EventStore::open(path, Limits::new(30, 10_000_000, 4 << 30)).unwrap()
}

fn received(index: u64) -> i64 {
    i64::try_from(START + index).unwrap()
}

/// `count` events from number `from` on, as Stalwart sends them: by turns a
/// message queued for one of 500 recipients and its delivery.
fn events(from: u64, count: u64) -> Vec<Value> {
    (from..from + count)
        .map(|index| {
            let at = time::isoformat(Timestamp::from_second(received(index)).unwrap());
            let queue = index / 2 + 1;
            let to = [format!("user{}@example.test", queue % 500)];
            let (kind, data) = if index % 2 == 0 {
                (
                    "queue.message-queued",
                    json!({"queueId": queue, "from": "sender@example.org", "to": to, "size": 4096}),
                )
            } else {
                (
                    "delivery.delivered",
                    json!({"queueId": queue, "to": to, "hostname": "mx.example.test",
                           "code": 250, "elapsed": 120}),
                )
            };
            json!({"id": (10_000_000 + index).to_string(), "createdAt": at, "type": kind, "data": data})
        })
        .collect()
}

/// One webhook batch of new events, stored in one transaction.
#[divan::bench(args = [100, 1000])]
fn store_a_batch(bencher: Bencher, size: u64) {
    let store = RECEIVER.get().unwrap();
    bencher
        .with_inputs(|| {
            let from = NEXT.fetch_add(size, Ordering::Relaxed);
            (events(from, size), received(from + size))
        })
        .bench_local_values(|(batch, at)| {
            let outcome = store.ingest(&batch, at).unwrap();
            assert_eq!(outcome.stored, size);
        });
}

/// One request's query: a reader of its own, as the web service opens it.
fn events_matching(filter: &Filter) -> Page<EventItem> {
    let db = reading(HISTORY.get().unwrap(), BUDGET).unwrap().unwrap();
    list_events(&db, filter).unwrap()
}

/// The newest 50 of 20,000 events.
#[divan::bench]
fn list_the_newest_events() -> Page<EventItem> {
    events_matching(&Filter::default())
}

/// A text that 40 of 20,000 events hold; every event is looked at.
#[divan::bench]
fn search_for_a_recipient() -> Page<EventItem> {
    let page = events_matching(&Filter {
        search: "USER7@example.test".into(),
        ..Filter::default()
    });
    assert_eq!(page.items.len(), 40);
    page
}

/// A text no event holds: the longest search, since nothing ends it early.
#[divan::bench]
fn search_for_nothing() -> Page<EventItem> {
    let page = events_matching(&Filter {
        search: "nobody@example.invalid".into(),
        ..Filter::default()
    });
    assert_eq!(page.items, []);
    page
}

/// The newest 25 of 10,000 deliveries, each summarized from its events.
#[divan::bench]
fn list_a_page_of_deliveries() -> Page<DeliverySummary> {
    let db = reading(HISTORY.get().unwrap(), BUDGET).unwrap().unwrap();
    let filter = Filter {
        limit: 25,
        ..Filter::default()
    };
    let page = list_deliveries(&db, &filter).unwrap();
    assert_eq!(page.items.len(), 25);
    page
}
