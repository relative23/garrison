//! A known batch yields known rows and known query answers.
//!
//! `fixtures/batch.json` is a signed webhook batch with ordinary events and
//! edge cases. `fixtures/golden.json` holds the expected answers, every stored
//! row and the history queries' answers for it. Stored `fields` are compared as
//! JSON values, not as text. A deliberate change of the stored format or of an
//! answer updates `golden.json` in the same commit.

// Helpers fail the test by panicking, like the test itself.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::Request;
use garrison_core::sqlite::reading;
use garrison_ingest::app::{router_with_clock, signature};
use garrison_ingest::coverage;
use garrison_ingest::queries::{self, Filter};
use garrison_ingest::store::{EventStore, Limits};
use rusqlite::types::ValueRef;
use serde_json::{Map, Value, json};
use tower::ServiceExt;

const KEY: &[u8] = b"golden-signature-key-0123456789";
const START: i64 = 1_793_000_000;
const RECEIVED: i64 = 1_793_000_100;
const TABLES: [(&str, &str); 5] = [
    ("events", "seq"),
    ("queues", "queue_id"),
    ("spans", "span_id"),
    ("gaps", "id"),
    ("metadata", "key"),
];

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

/// Every row of every table, as JSON objects; `fields` parsed.
fn rows(path: &Path) -> Value {
    let db = rusqlite::Connection::open(path).unwrap();
    let mut tables = Map::new();
    for (table, key) in TABLES {
        let mut statement = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY {key}"))
            .unwrap();
        let names: Vec<String> = statement.column_names().map(ToString::to_string).collect();
        let mut result = Vec::new();
        let mut cursor = statement.query([]).unwrap();
        while let Some(row) = cursor.next().unwrap() {
            let mut object = Map::new();
            for (index, name) in names.iter().enumerate() {
                let value = match row.get_ref(index).unwrap() {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(number) => json!(number),
                    ValueRef::Text(text) => {
                        let text = std::str::from_utf8(text).unwrap();
                        if name == "fields" {
                            serde_json::from_str(text).unwrap()
                        } else {
                            json!(text)
                        }
                    }
                    other => panic!("unexpected {other:?}"),
                };
                object.insert(name.clone(), value);
            }
            result.push(Value::Object(object));
        }
        tables.insert(table.to_owned(), Value::Array(result));
    }
    Value::Object(tables)
}

fn parsed_fields(mut golden: Value) -> Value {
    for row in golden["events"].as_array_mut().unwrap() {
        let text = row["fields"].as_str().unwrap().to_owned();
        row["fields"] = serde_json::from_str(&text).unwrap();
    }
    golden
}

/// Post the signed batch twice, as Stalwart does when it retries; the answers.
async fn post_twice(app: &axum::Router, body: &[u8]) -> Value {
    let mut answers = Vec::new();
    for _ in 0..2 {
        let request = Request::post("/webhook")
            .header("Content-Type", "application/json")
            .header("Content-Length", body.len())
            .header("X-Signature", signature(KEY, body))
            .body(Body::from(body.to_vec()))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let answer: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        answers.push(json!([status, answer]));
    }
    Value::Array(answers)
}

fn limit(limit: usize) -> Filter {
    Filter {
        limit,
        ..Filter::default()
    }
}

/// The history queries whose answers `golden.json` holds, by name, as the
/// JSON they go out as.
fn query_answers(db: &rusqlite::Connection) -> Vec<(&'static str, Value)> {
    let first = queries::list_deliveries(db, &limit(1)).unwrap();
    let after = Filter {
        before: first.next,
        ..limit(25)
    };
    let search = Filter {
        search: "EXAMPLE.org".into(),
        ..Filter::default()
    };
    let delivery = queries::delivery_detail(db, "337538776689541120").unwrap();
    let session = queries::session_detail(db, "337538776114949120").unwrap();
    vec![
        (
            "events",
            json!(queries::list_events(db, &limit(100)).unwrap()),
        ),
        (
            "eventsPage",
            json!(queries::list_events(db, &limit(5)).unwrap()),
        ),
        (
            "eventsSearch",
            json!(queries::list_events(db, &search).unwrap()),
        ),
        (
            "deliveries",
            json!(queries::list_deliveries(db, &limit(25)).unwrap()),
        ),
        (
            "deliveriesAfter",
            json!(queries::list_deliveries(db, &after).unwrap()),
        ),
        ("delivery", json!(delivery.unwrap())),
        (
            "sessions",
            json!(queries::list_sessions(db, &limit(25)).unwrap()),
        ),
        ("session", json!(session.unwrap())),
        (
            "coverage",
            json!(coverage::read(Some(db), RECEIVED + 10).unwrap()),
        ),
    ]
}

#[tokio::test]
async fn the_same_signed_batch_yields_the_same_rows_and_answers() {
    let golden: Value = serde_json::from_slice(&fixture("golden.json")).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.sqlite");
    let store = Arc::new(EventStore::open(&path, Limits::new(30, 1000, 64 << 20)).unwrap());
    store.start(START).unwrap();
    let app = router_with_clock(store, KEY, || RECEIVED);
    assert_eq!(
        post_twice(&app, &fixture("batch.json")).await,
        golden["answers"]
    );

    let stored = rows(&path);
    let expected = parsed_fields(golden["rows"].clone());
    for (table, _) in TABLES {
        let (ours, theirs) = (&stored[table], &expected[table]);
        let length = ours.as_array().unwrap().len();
        assert_eq!(length, theirs.as_array().unwrap().len(), "{table}");
        for index in 0..length {
            assert_eq!(ours[index], theirs[index], "{table} row {index}");
        }
    }

    let db = reading(&path, Duration::from_secs(2)).unwrap().unwrap();
    for (name, ours) in query_answers(&db) {
        assert_eq!(ours, golden["queries"][name], "{name}");
    }
}
