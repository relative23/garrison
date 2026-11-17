//! Readers of another service's database while that service writes it.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use garrison_core::config::Database;
use garrison_core::time;
use garrison_ingest::store::{EventStore, Limits};
use serde_json::json;
use support::{setup, write_status};

/// What a reader answers that waited out the writer's commit.
const WAITED: &str = "The query waited too long for another service's write; try again in a moment";

/// A route of the API with a value for each of its parameters.
fn filled(template: &str) -> String {
    template
        .replace("{queue_id}", "7")
        .replace("{span_id}", "9")
        .replace("{job_id}", &"a".repeat(32))
}

/// The receiver or the collector holds its database for longer than a
/// reader waits for it, as while the receiver removes a tenth of a full
/// history at its size limit, or on a slow disk. Every route that reads
/// such a database says that this passes, and none answers it as an
/// internal error, which would put an error line in the journal for each
/// request. The table holds every GET operation of the API, so that a new
/// route that reads a database has to say what it answers here.
#[tokio::test]
async fn every_reader_that_waits_out_a_writer_says_that_it_passes() {
    let mut setup = setup();
    let events = setup.config.database(Database::Events);
    let status = setup.config.database(Database::Status);
    // Both exist, as after the receiver's and the collector's first runs.
    EventStore::open(&events, Limits::new(30, 1000, 64 << 20))
        .unwrap()
        .start(time::now().as_second())
        .unwrap();
    write_status(&status, &json!([]), &json!([]));
    setup.client.sign_in("code-admin").await;
    // Each writer in the middle of a commit: no reader may begin.
    let holders: Vec<rusqlite::Connection> = [&events, &status]
        .into_iter()
        .map(|path| {
            let holder = rusqlite::Connection::open(path).unwrap();
            holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
            holder
        })
        .collect();
    let document = garrison_web::openapi::document();
    let mut answers = Vec::new();
    for (template, operations) in document["paths"].as_object().unwrap() {
        if operations.get("get").is_some() {
            let answer = setup.client.get(&filled(template)).await;
            let detail = answer.json()["detail"].as_str().unwrap_or("").to_owned();
            answers.push((template.clone(), answer.status.as_u16(), detail));
        }
    }
    drop(holders);
    answers.sort();
    let waited = |path: &str| (path.to_owned(), 503, WAITED.to_owned());
    let answered = |path: &str| (path.to_owned(), 200, String::new());
    assert_eq!(
        answers,
        [
            answered("/api/actions"),
            answered("/api/actions/jobs/{job_id}"),
            waited("/api/attacks"),
            waited("/api/coverage"),
            waited("/api/deliveries"),
            waited("/api/deliveries/{queue_id}"),
            waited("/api/destinations"),
            waited("/api/events"),
            waited("/api/metrics"),
            answered("/api/session"),
            waited("/api/sessions"),
            waited("/api/sessions/{span_id}"),
            waited("/api/status"),
            answered("/api/switch"),
        ]
    );
}
