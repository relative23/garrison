//! Loopback webhook receiver for Stalwart telemetry events.
//!
//! Stalwart signs each batch with HMAC-SHA256 over the raw body (base64 in the
//! `X-Signature` header). Unsigned or altered batches are rejected. A batch is
//! acknowledged only after it is durably committed; on any storage error the
//! receiver answers 503 and Stalwart retries the same batch later.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_core::{json, time};
use hmac::{KeyInit, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::store::EventStore;

pub const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_EVENTS_PER_BATCH: usize = 50_000;
const HEARTBEAT: Duration = Duration::from_secs(30);
/// Retention runs every this many heartbeats (ten minutes).
const CLEANUP_EVERY: u32 = 20;

type Hmac = hmac::Hmac<Sha256>;

/// The base64 HMAC-SHA256 of `body`, as Stalwart sends it.
pub fn signature(key: &[u8], body: &[u8]) -> String {
    STANDARD.encode(mac(key, body).finalize().into_bytes())
}

/// Compares in constant time, on the decoded bytes of a canonical base64 value.
fn signature_matches(key: &[u8], body: &[u8], provided: &str) -> bool {
    let Ok(provided) = STANDARD.decode(provided) else {
        return false;
    };
    mac(key, body).verify_slice(&provided).is_ok()
}

fn mac(key: &[u8], body: &[u8]) -> Hmac {
    let mut mac = Hmac::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(body);
    mac
}

#[derive(Clone)]
struct Receiver {
    store: Arc<EventStore>,
    key: Arc<[u8]>,
    /// Seconds since the epoch; fixed in comparison tests.
    clock: fn() -> i64,
}

fn now() -> i64 {
    time::now().as_second()
}

fn answer(status: StatusCode, message: &str, extra: Map<String, Value>) -> Response {
    let mut body = Map::new();
    body.insert("status".into(), json!(message));
    body.extend(extra);
    (status, axum::Json(Value::Object(body))).into_response()
}

fn refuse(status: StatusCode, message: &str) -> Response {
    answer(status, message, Map::new())
}

fn header_text<'a>(headers: &'a HeaderMap, name: &header::HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// The routes, without the maintenance task; [`crate::run`] adds it.
pub fn router(store: Arc<EventStore>, key: &[u8]) -> Router {
    router_with_clock(store, key, now)
}

/// [`router`] with another clock for `received_at`.
pub fn router_with_clock(store: Arc<EventStore>, key: &[u8], clock: fn() -> i64) -> Router {
    let receiver = Receiver {
        store,
        key: Arc::from(key),
        clock,
    };
    Router::new()
        .route("/webhook", post(webhook))
        .route("/health", get(|| async { refuse(StatusCode::OK, "ok") }))
        .fallback(|| async { detail(StatusCode::NOT_FOUND, "Not Found") })
        .method_not_allowed_fallback(|| async {
            detail(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
        })
        .with_state(receiver)
}

/// The answer for unknown paths and methods.
fn detail(status: StatusCode, message: &str) -> Response {
    (status, axum::Json(json!({"detail": message}))).into_response()
}

async fn webhook(State(receiver): State<Receiver>, request: Request) -> Response {
    let headers = request.headers();
    let media = header_text(headers, &header::CONTENT_TYPE).unwrap_or_default();
    if media.split(';').next().unwrap_or_default().trim() != "application/json" {
        return refuse(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON required");
    }
    if headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|encoding| encoding != "identity")
    {
        return refuse(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Compressed bodies are not accepted",
        );
    }
    let declared = header_text(headers, &header::CONTENT_LENGTH)
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse::<usize>().ok());
    if declared.is_none_or(|length| length > MAX_BODY) {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, "Body missing or too large");
    }
    let provided = header_text(headers, &header::HeaderName::from_static("x-signature"))
        .unwrap_or_default()
        .to_owned();
    let Ok(body) = to_bytes(request.into_body(), MAX_BODY).await else {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, "Body missing or too large");
    };
    if !signature_matches(&receiver.key, &body, &provided) {
        log::warn!("Rejected a webhook batch with an invalid signature");
        return refuse(StatusCode::UNAUTHORIZED, "Invalid signature");
    }
    let Ok(payload) = json::parse(&body, MAX_BODY) else {
        return refuse(StatusCode::BAD_REQUEST, "Invalid JSON");
    };
    let events = match payload {
        Value::Object(mut payload) => match payload.remove("events") {
            Some(Value::Array(events)) if events.len() <= MAX_EVENTS_PER_BATCH => events,
            _ => return refuse(StatusCode::BAD_REQUEST, "Invalid batch"),
        },
        _ => return refuse(StatusCode::BAD_REQUEST, "Invalid batch"),
    };
    let (store, arrival) = (receiver.store.clone(), (receiver.clock)());
    match off_thread(move || store.ingest(&events, arrival)).await {
        Ok(outcome) => {
            let mut extra = Map::new();
            extra.insert("stored".into(), json!(outcome.stored));
            extra.insert("skipped".into(), json!(outcome.skipped));
            answer(StatusCode::OK, "stored", extra)
        }
        Err(error) => {
            log::error!("Could not store a webhook batch; Stalwart will retry: {error}");
            refuse(StatusCode::SERVICE_UNAVAILABLE, "Storage unavailable")
        }
    }
}

/// Run blocking SQLite work off the async threads; a panic there is an error.
async fn off_thread<T: Send + 'static, E: std::fmt::Display + Send + 'static>(
    work: impl FnOnce() -> Result<T, E> + Send + 'static,
) -> Result<T, String> {
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result.map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    }
}

/// Heartbeat every 30 seconds and retention every ten minutes, until dropped.
pub(crate) async fn maintain(store: Arc<EventStore>) {
    let mut ticks = tokio::time::interval(HEARTBEAT);
    ticks.tick().await; // The first tick completes at once.
    let mut beats = 0;
    loop {
        ticks.tick().await;
        beats += 1;
        let store = store.clone();
        if let Err(error) = off_thread(move || beat(&store, beats, now())).await {
            log::error!("Event store maintenance failed: {error}");
        }
    }
}

/// The `count`-th heartbeat; every [`CLEANUP_EVERY`]-th also applies retention.
fn beat(store: &EventStore, count: u32, at: i64) -> Result<(), crate::store::SqliteError> {
    store.heartbeat(at)?;
    if count.is_multiple_of(CLEANUP_EVERY) {
        store.enforce_limits(at)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
