//! What every route answers where the broker gives no answer.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;
use std::time::Duration;

use axum::http::Method;
use garrison_broker::client::CallError;
use garrison_core::config::Database;
use garrison_core::time;
use garrison_ingest::store::{EventStore, Limits};
use serde_json::{Value, json};
use support::{ORIGIN, refused, setup_with_cache, write_status};

/// A route of the API with a value for each of its parameters.
fn filled(template: &str) -> String {
    template
        .replace("{queue_id}", "7")
        .replace("{span_id}", "9")
        .replace("{job_id}", &"a".repeat(32))
}

/// A body the write at `template` takes.
fn body(template: &str) -> Option<Value> {
    match template {
        "/api/actions" => Some(json!({
            "action": "run_monitor",
            "requestId": "0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b",
            "confirmation": "RUN HEALTH CHECKS",
        })),
        "/api/preferences" => Some(json!({
            "theme": "system", "hiddenModules": [], "showSwitch": false,
        })),
        _ => None,
    }
}

/// A request the broker cannot read (400) is the web service's own fault
/// where the web service made the request alone: an internal error with a
/// line under its reference. Only a submission carries what the user typed,
/// such as a confirmation phrase that does not match, and the broker's 400
/// reaches the user with its words.
#[tokio::test]
async fn a_broker_400_is_the_users_only_for_a_submission() {
    let mut setup = setup_with_cache(Duration::from_secs(60));
    let csrf = setup.client.sign_in("code-admin").await;
    let phrase = "The confirmation phrase does not match";
    setup.broker.set("admin-token", refused(400, phrase));
    let headers = [("origin", ORIGIN), ("x-csrf-token", csrf.as_str())];
    let submitted = setup
        .client
        .send(Method::POST, "/api/actions", &headers, body("/api/actions"))
        .await;
    assert_eq!(
        (
            submitted.status.as_u16(),
            submitted.json()["detail"].clone()
        ),
        (400, json!(phrase))
    );
    let listed = setup.client.get("/api/actions").await;
    assert_eq!(
        (listed.status.as_u16(), listed.json()["detail"].clone()),
        (500, json!("Internal error"))
    );
}

/// A broker that gives no answer is one condition, worded alike whichever
/// route meets it, in the words the operations guide has a row for: with
/// the user's rights confirmed a moment ago, where only the Maintenance
/// page's routes ask the broker again, and without, where every route's
/// check meets it. Every operation of the API is asked, so a new one that
/// words it otherwise fails here.
#[tokio::test]
async fn a_broker_that_gives_no_answer_is_worded_alike_on_every_route() {
    for cache in [Duration::from_secs(60), Duration::ZERO] {
        let mut setup = setup_with_cache(cache);
        // The databases exist, so that no route answers that its own is
        // not there yet.
        EventStore::open(
            &setup.config.database(Database::Events),
            Limits::new(30, 1000, 64 << 20),
        )
        .unwrap()
        .start(time::now().as_second())
        .unwrap();
        write_status(
            &setup.config.database(Database::Status),
            &json!([]),
            &json!([]),
        );
        let csrf = setup.client.sign_in("code-admin").await;
        let silent = Err(CallError::Unavailable(
            "The maintenance broker is unavailable",
        ));
        setup.broker.set("admin-token", silent);
        let document = garrison_web::openapi::document();
        let mut worded = BTreeSet::new();
        let mut asked = 0;
        for (template, operations) in document["paths"].as_object().unwrap() {
            // Sign-out looks only at the session, and would end it.
            if template == "/api/logout" {
                continue;
            }
            for method in operations.as_object().unwrap().keys() {
                let method = Method::from_bytes(method.to_ascii_uppercase().as_bytes()).unwrap();
                let headers = [("origin", ORIGIN), ("x-csrf-token", csrf.as_str())];
                let answer = setup
                    .client
                    .send(method, &filled(template), &headers, body(template))
                    .await;
                if answer.status.as_u16() == 503 {
                    asked += 1;
                    worded.insert(answer.json()["detail"].as_str().unwrap().to_owned());
                }
            }
        }
        assert_eq!(
            worded,
            BTreeSet::from(["Authorization is temporarily unavailable".to_owned()]),
            "{cache:?}"
        );
        // The Maintenance page's three, and with no rights kept every
        // operation but the switch row's question, which needs none: 15 of
        // the 16 asked.
        assert_eq!(asked, if cache.is_zero() { 15 } else { 3 }, "{cache:?}");
    }
}
