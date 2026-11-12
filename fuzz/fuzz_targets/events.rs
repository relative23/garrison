//! A batch of events as the webhook delivers it, after its signature was
//! checked: storing it never fails, and whatever was stored can be read
//! through every view of the history. An event that could be stored but not
//! read would hide the history until it expires.
#![no_main]

use std::sync::OnceLock;
use std::time::Duration;

use garrison_core::json;
use garrison_core::sqlite::reading;
use garrison_ingest::coverage;
use garrison_ingest::queries::{self, Filter};
use garrison_ingest::store::{EventStore, Limits};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

/// Seconds since the epoch at which every batch arrives.
const NOW: i64 = 1_794_000_000;

struct Setup {
    store: EventStore,
    path: std::path::PathBuf,
    _directory: tempfile::TempDir,
}

fn setup() -> &'static Setup {
    static SETUP: OnceLock<Setup> = OnceLock::new();
    SETUP.get_or_init(|| {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("events.sqlite");
        // Few events are kept, so the database stays small over a long run.
        let store = EventStore::open(&path, Limits::new(30, 2000, 16 << 20)).expect("a store");
        store.start(NOW).expect("a started store");
        Setup {
            store,
            path,
            _directory: directory,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(Value::Object(mut batch)) = json::parse(data, 1 << 20) else {
        return;
    };
    let Some(Value::Array(events)) = batch.remove("events") else {
        return;
    };
    let setup = setup();
    setup.store.ingest(&events, NOW).expect("a batch is stored");
    setup.store.enforce_limits(NOW).expect("limits are kept");
    let db = reading(&setup.path, Duration::from_secs(30))
        .expect("the history opens")
        .expect("the history exists");
    let filter = Filter {
        limit: 50,
        ..Filter::default()
    };
    queries::list_events(&db, &filter).expect("events are listed");
    let deliveries = queries::list_deliveries(&db, &filter).expect("deliveries are listed");
    let sessions = queries::list_sessions(&db, &filter).expect("sessions are listed");
    for delivery in deliveries.items.iter().take(3) {
        queries::delivery_detail(&db, &delivery.queue_id).expect("a delivery is shown");
    }
    for session in sessions.items.iter().take(3) {
        queries::session_detail(&db, &session.span_id).expect("a session is shown");
    }
    coverage::read(Some(&db), NOW).expect("coverage is read");
});
