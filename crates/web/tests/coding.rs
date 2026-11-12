//! Content codings of the API's answers (src/coding.rs): gzip for JSON, never
//! for the session, which carries the CSRF token.
#![allow(clippy::unwrap_used)]

mod support;

use std::io::Read;

use axum::http::Method;
use flate2::read::GzDecoder;
use garrison_core::config::Database;
use serde_json::{Value, json};
use support::{setup, write_status};

fn observation(index: usize) -> Value {
    json!({
        "id": format!("o{index}"), "provider": "p", "title": "t", "modules": ["dashboard"],
        "evidence": "process", "state": "ok", "checkedAt": "2000-01-01T00:00:00+00:00",
        "source": "s", "kind": "details", "scope": "", "fields": [], "table": null,
        "findings": [], "value": {}, "maxAge": 60,
    })
}

#[tokio::test]
async fn json_answers_go_out_gzipped_but_never_the_session() {
    let mut setup = setup();
    write_status(
        &setup.config.database(Database::Status),
        &json!((0..30).map(observation).collect::<Vec<_>>()),
        &json!([]),
    );
    setup.client.sign_in("code-admin").await;
    let plain = setup.client.get("/api/status").await;
    assert_eq!(plain.header("content-encoding"), "");
    let zipped = setup
        .client
        .send(
            Method::GET,
            "/api/status",
            &[("accept-encoding", "gzip, br")],
            None,
        )
        .await;
    assert_eq!(zipped.header("content-encoding"), "gzip");
    assert_eq!(zipped.header("vary"), "accept-encoding");
    let mut body = Vec::new();
    GzDecoder::new(zipped.body.as_slice())
        .read_to_end(&mut body)
        .unwrap();
    assert_eq!(body, plain.body);
    assert!(zipped.body.len() < plain.body.len() / 4);
    // The session stays as it is though large enough; so do small answers.
    let session = setup
        .client
        .send(
            Method::GET,
            "/api/session",
            &[("accept-encoding", "gzip")],
            None,
        )
        .await;
    assert!(session.body.len() > 1024, "{}", session.body.len());
    assert_eq!(session.header("content-encoding"), "");
    assert!(session.json()["session"]["csrf"].is_string());
    let small = setup
        .client
        .send(
            Method::GET,
            "/api/switch",
            &[("accept-encoding", "gzip")],
            None,
        )
        .await;
    assert!(small.body.len() < 1024);
    assert_eq!(small.header("content-encoding"), "");
}
