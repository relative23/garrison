use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

use super::*;
use crate::store::tests::{AT, SPAN, event, read, store};

const KEY: &[u8] = b"test-signature-key-0123456789";

/// Request headers, and the status and message they lead to.
type Case<'a> = (Vec<(&'a str, &'a str)>, StatusCode, &'a str);

fn batch(events: &[Value]) -> Vec<u8> {
    json!({"events": events}).to_string().into_bytes()
}

fn request(body: &[u8], headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::post("/webhook").header("Content-Length", body.len());
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::from(body.to_vec())).unwrap()
}

fn signed(body: &[u8]) -> Request<Body> {
    let signature = signature(KEY, body);
    request(
        body,
        &[
            ("Content-Type", "application/json; charset=utf-8"),
            ("X-Signature", &signature),
        ],
    )
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn signed_batches_are_stored_once_and_others_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let app = router(Arc::new(store(directory.path(), 1000)), KEY);
    let body = batch(&[event(
        1,
        "smtp.ehlo",
        AT,
        &json!({"spanId": SPAN, "domain": "client.example.net"}),
    )]);
    let wrong = signature(b"wrong-key-wrong-key-wrong", &body);
    let invalid = json!({"status": "Invalid signature"});
    let headers = [
        ("Content-Type", "application/json"),
        ("X-Signature", wrong.as_str()),
    ];
    assert_eq!(
        call(&app, request(&body, &headers)).await,
        (StatusCode::UNAUTHORIZED, invalid.clone())
    );
    let unsigned = request(&body, &[("Content-Type", "application/json")]);
    assert_eq!(
        call(&app, unsigned).await,
        (StatusCode::UNAUTHORIZED, invalid)
    );
    let stored = json!({"status": "stored", "stored": 1, "skipped": 0});
    assert_eq!(call(&app, signed(&body)).await, (StatusCode::OK, stored));
    // Stalwart retries the same batch.
    let retried = json!({"status": "stored", "stored": 0, "skipped": 1});
    assert_eq!(call(&app, signed(&body)).await, (StatusCode::OK, retried));
    let count: i64 = read(directory.path())
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn requests_are_checked_before_the_signature() {
    let directory = tempfile::tempdir().unwrap();
    let app = router(Arc::new(store(directory.path(), 1000)), KEY);
    let body = batch(&[]);
    let signature = signature(KEY, &body);
    let cases: [Case<'_>; 3] = [
        (
            vec![("Content-Type", "text/plain")],
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "JSON required",
        ),
        (
            vec![
                ("Content-Type", "application/json"),
                ("Content-Encoding", "gzip"),
            ],
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Compressed bodies are not accepted",
        ),
        (
            vec![
                ("Content-Type", "application/json"),
                ("Content-Encoding", "identity"),
                ("X-Signature", &signature),
            ],
            StatusCode::OK,
            "stored",
        ),
    ];
    for (headers, status, message) in cases {
        let (answer, body) = call(&app, request(&body, &headers)).await;
        assert_eq!(
            (answer, body["status"].as_str().unwrap()),
            (status, message)
        );
    }
    let undeclared = Request::post("/webhook")
        .header("Content-Type", "application/json")
        .body(Body::from(body.clone()))
        .unwrap();
    assert_eq!(
        call(&app, undeclared).await,
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"status": "Body missing or too large"})
        )
    );
    let huge = Request::post("/webhook")
        .header("Content-Type", "application/json")
        .header("Content-Length", MAX_BODY + 1)
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&app, huge).await.0, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn only_well_formed_batches_reach_the_store() {
    let directory = tempfile::tempdir().unwrap();
    let app = router(Arc::new(store(directory.path(), 1000)), KEY);
    let cases: [(&[u8], &str); 4] = [
        (b"{not json", "Invalid JSON"),
        (br#"{"events": 1, "events": 2}"#, "Invalid JSON"),
        (br#"{"events": {}}"#, "Invalid batch"),
        (b"[]", "Invalid batch"),
    ];
    for (body, message) in cases {
        assert_eq!(
            call(&app, signed(body)).await,
            (StatusCode::BAD_REQUEST, json!({"status": message}))
        );
    }
}

#[tokio::test]
async fn health_and_unknown_paths_answer_like_before() {
    let directory = tempfile::tempdir().unwrap();
    let app = router(Arc::new(store(directory.path(), 1000)), KEY);
    let health = Request::get("/health").body(Body::empty()).unwrap();
    assert_eq!(
        call(&app, health).await,
        (StatusCode::OK, json!({"status": "ok"}))
    );
    let missing = Request::get("/other").body(Body::empty()).unwrap();
    assert_eq!(
        call(&app, missing).await,
        (StatusCode::NOT_FOUND, json!({"detail": "Not Found"}))
    );
    let wrong = Request::get("/webhook").body(Body::empty()).unwrap();
    assert_eq!(
        call(&app, wrong).await,
        (
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"detail": "Method Not Allowed"})
        )
    );
}

#[test]
fn signatures_are_base64_hmac_sha256() {
    // RFC 4231 test case 2 (5bdcc146...64ec3843), base64-encoded.
    assert_eq!(
        signature(b"Jefe", b"what do ya want for nothing?"),
        "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM="
    );
    let body = b"{}";
    let good = signature(KEY, body);
    assert!(signature_matches(KEY, body, &good));
    assert!(!signature_matches(KEY, body, good.trim_end_matches('=')));
    assert!(!signature_matches(KEY, body, ""));
    assert!(!signature_matches(KEY, b"{} ", &good));
}

#[tokio::test]
async fn a_body_may_use_exactly_its_size_limit() {
    let directory = tempfile::tempdir().unwrap();
    let app = router(Arc::new(store(directory.path(), 1000)), KEY);
    let mut body = batch(&[]);
    // Stalwart batches up to 8 MiB.
    body.resize(8 * 1024 * 1024, b' ');
    let (status, answer) = call(&app, signed(&body)).await;
    assert_eq!(
        (status, answer["stored"].clone()),
        (StatusCode::OK, json!(0))
    );
    body.push(b' ');
    let (status, _) = call(&app, signed(&body)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn the_declared_length_must_be_plain_digits() {
    let directory = tempfile::tempdir().unwrap();
    let app = router(Arc::new(store(directory.path(), 1000)), KEY);
    let body = batch(&[]);
    for declared in ["", "+2", "0x10", "-1"] {
        let request = Request::post("/webhook")
            .header("Content-Type", "application/json")
            .header("Content-Length", declared)
            .header("X-Signature", signature(KEY, &body))
            .body(Body::from(body.clone()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{declared:?}"
        );
    }
}

#[tokio::test]
async fn a_batch_holds_at_most_fifty_thousand_events() {
    let directory = tempfile::tempdir().unwrap();
    let app = router(Arc::new(store(directory.path(), 1000)), KEY);
    let most: Vec<Value> = vec![json!(null); MAX_EVENTS_PER_BATCH];
    let (status, answer) = call(&app, signed(&batch(&most))).await;
    assert_eq!(
        (status, answer["skipped"].clone()),
        (StatusCode::OK, json!(MAX_EVENTS_PER_BATCH))
    );
    let too_many: Vec<Value> = vec![json!(null); MAX_EVENTS_PER_BATCH + 1];
    let (status, answer) = call(&app, signed(&batch(&too_many))).await;
    assert_eq!(
        (status, answer),
        (StatusCode::BAD_REQUEST, json!({"status": "Invalid batch"}))
    );
}

#[tokio::test]
async fn events_are_received_at_the_current_time() {
    let directory = tempfile::tempdir().unwrap();
    let app = router(Arc::new(store(directory.path(), 1000)), KEY);
    let before = time::now().as_second();
    let body = batch(&[event(1, "auth.failed", AT, &json!({}))]);
    assert_eq!(call(&app, signed(&body)).await.0, StatusCode::OK);
    let received: i64 = read(directory.path())
        .query_row("SELECT received_at FROM events", [], |row| row.get(0))
        .unwrap();
    assert!((before..=time::now().as_second()).contains(&received));
}

fn metadata(directory: &std::path::Path, key: &str) -> Option<String> {
    read(directory)
        .query_row("SELECT value FROM metadata WHERE key=?", [key], |row| {
            row.get(0)
        })
        .ok()
}

#[test]
fn every_twentieth_beat_applies_retention() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let now = 1_800_000_000;
    events
        .ingest(&[event(1, "auth.failed", AT, &json!({}))], now)
        .unwrap();
    let remaining = || -> i64 {
        read(directory.path())
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .unwrap()
    };
    for count in 1..CLEANUP_EVERY {
        beat(&events, count, now).unwrap();
    }
    assert_eq!(remaining(), 1);
    assert_eq!(
        metadata(directory.path(), "heartbeatAt"),
        Some(now.to_string())
    );
    beat(&events, CLEANUP_EVERY, now).unwrap();
    assert_eq!(remaining(), 0);
}

#[tokio::test(start_paused = true)]
async fn the_receiver_beats_every_thirty_seconds() {
    let directory = tempfile::tempdir().unwrap();
    let events = Arc::new(store(directory.path(), 1000));
    // Expired, but retention runs only every twentieth beat.
    let expired = event(1, "auth.failed", "2026-01-01T00:00:00Z", &json!({}));
    events.ingest(&[expired], 1).unwrap();
    let ingested = Some("1".to_owned());
    let task = tokio::spawn(maintain(Arc::clone(&events)));
    tokio::time::sleep(HEARTBEAT / 2).await;
    assert_eq!(metadata(directory.path(), "heartbeatAt"), ingested);
    for _ in 0..50 {
        tokio::time::sleep(HEARTBEAT).await;
        if metadata(directory.path(), "heartbeatAt") != ingested {
            break;
        }
    }
    assert_ne!(metadata(directory.path(), "heartbeatAt"), ingested);
    let kept: i64 = read(directory.path())
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(kept, 1);
    task.abort();
}
