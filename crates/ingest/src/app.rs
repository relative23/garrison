//! Loopback webhook receiver for Stalwart telemetry events.
//!
//! Stalwart signs each batch with HMAC-SHA256 over the raw body (base64 in the
//! `X-Signature` header). Unsigned or altered batches are rejected. A batch is
//! acknowledged only after it is durably committed; on any storage error the
//! receiver answers 503 and Stalwart retries the same batch later.
//!
//! Few batches are read at a time and none for long (`turns`). What the
//! store removes to keep its limits, it removes in the maintenance task and
//! not before a batch is answered.

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
use tokio::sync::Notify;

use crate::store::EventStore;

mod turns;

use turns::{Late, Turns};

pub const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_EVENTS_PER_BATCH: usize = 50_000;
/// The batches that are read and stored at a time. Stalwart sends one and
/// waits for its answer; the second turn is for whoever else reaches the
/// port. A batch may hold 8 MiB and takes a few times that once it is
/// parsed, and the unit allows the service 256 MiB.
const AT_A_TIME: usize = 2;
/// How long a batch has to get its turn and to arrive whole. Stalwart waits
/// five seconds for the answer, as `garrison stalwart setup` sets it, and
/// brings the batch again.
const ARRIVAL: Duration = Duration::from_secs(10);
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
    // RFC 2104 defines HMAC for a key of any length, a longer one hashed
    // first, and hmac's `new_from_slice` refuses only a key of the wrong
    // length for a MAC that has a fixed one, never for HMAC:
    // `a_key_of_any_length_makes_a_mac` holds that for the locked release.
    let mut mac = Hmac::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC takes a key of any length"));
    mac.update(body);
    mac
}

#[derive(Clone)]
struct Receiver {
    store: Arc<EventStore>,
    key: Arc<[u8]>,
    /// Seconds since the epoch; fixed in comparison tests.
    clock: fn() -> i64,
    turns: Turns,
    /// Tells the maintenance task that the store's clean-up is due.
    due: Arc<Notify>,
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
    routes(Receiver::new(store, key, clock, ARRIVAL))
}

/// The routes and the maintenance task that belongs to them: the routes tell
/// it when the store's clean-up should not wait for its turn.
pub(crate) fn service(
    store: Arc<EventStore>,
    key: &[u8],
) -> (Router, impl Future<Output = ()> + Send + 'static) {
    let receiver = Receiver::new(Arc::clone(&store), key, now, ARRIVAL);
    let maintenance = maintain(store, Arc::clone(&receiver.due));
    (routes(receiver), maintenance)
}

impl Receiver {
    fn new(store: Arc<EventStore>, key: &[u8], clock: fn() -> i64, arrival: Duration) -> Self {
        Receiver {
            store,
            key: Arc::from(key),
            clock,
            turns: Turns::new(AT_A_TIME, arrival),
            due: Arc::new(Notify::new()),
        }
    }
}

fn routes(receiver: Receiver) -> Router {
    Router::new()
        .route("/webhook", post(webhook))
        .route("/health", get(health))
        .fallback(|| async { detail(StatusCode::NOT_FOUND, "Not Found") })
        .method_not_allowed_fallback(|| async {
            detail(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
        })
        .with_state(receiver)
}

/// Whether the receiver stores what it is sent, and what it counted since
/// it started. Always 200 while the process answers: that it runs is one
/// thing, that it takes Stalwart's batches another, which the body says.
async fn health(State(receiver): State<Receiver>) -> Response {
    let health = receiver.store.health();
    let mut extra = Map::new();
    extra.insert("failingSince".into(), json!(health.failing_since));
    extra.insert("refused".into(), json!(health.refused));
    extra.insert("unreadable".into(), json!(health.unreadable));
    extra.insert("duplicate".into(), json!(health.duplicate));
    let status = if health.failing_since.is_some() {
        "failing"
    } else {
        "ok"
    };
    answer(StatusCode::OK, status, extra)
}

/// A batch was refused: the store keeps since when, and the journal gets
/// the first refusal and every hundredth, not one line for each.
async fn refused(receiver: &Receiver, why: &str) {
    let (store, at) = (receiver.store.clone(), (receiver.clock)());
    let count = off_thread(move || Ok::<u64, String>(store.refused(at))).await;
    if let Ok(count) = count
        && (count == 1 || count.is_multiple_of(100))
    {
        log::warn!(
            "Refused a webhook batch: {why} ({count} refused since the receiver started; \
             /health says since when nothing was stored)"
        );
    }
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
    // Nothing of the body is read before it is this batch's turn, and the
    // turn is kept until the batch is stored and answered.
    let arriving = to_bytes(request.into_body(), MAX_BODY);
    let (_turn, body) = match receiver.turns.take(arriving).await {
        Ok(taken) => taken,
        // Either way Stalwart brings the batch again, for an hour: the
        // time in which none is taken is kept as for any refusal.
        Err(Late::Busy) => {
            refused(&receiver, "the batches before it took too long").await;
            return refuse(StatusCode::SERVICE_UNAVAILABLE, "Busy");
        }
        Err(Late::Slow) => {
            refused(&receiver, "it did not arrive whole in time").await;
            return refuse(StatusCode::REQUEST_TIMEOUT, "Body did not arrive in time");
        }
    };
    let Ok(body) = body else {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, "Body missing or too large");
    };
    if !signature_matches(&receiver.key, &body, &provided) {
        // Stalwart brings the batch again for an hour, then drops it: with
        // a key that no longer matches, events go missing while the
        // receiver runs.
        refused(&receiver, "its signature is not of the configured key").await;
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
    let stored = off_thread(move || {
        let outcome = store.ingest(&events, arrival)?;
        Ok::<_, crate::store::SqliteError>((outcome, store.cleanup_due()))
    });
    match stored.await {
        Ok((outcome, cleanup_due)) => {
            if cleanup_due {
                receiver.due.notify_one();
            }
            let mut extra = Map::new();
            extra.insert("stored".into(), json!(outcome.stored));
            extra.insert("skipped".into(), json!(outcome.skipped));
            answer(StatusCode::OK, "stored", extra)
        }
        Err(error) => {
            log::error!("Could not store a webhook batch; Stalwart will retry: {error}");
            // A database that is full is what the clean-up mends.
            receiver.due.notify_one();
            refused(&receiver, "it could not be stored").await;
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

/// Heartbeat every 30 seconds and the store's clean-up every ten minutes,
/// or as soon as the routes say that it is `due`; until dropped.
pub(crate) async fn maintain(store: Arc<EventStore>, due: Arc<Notify>) {
    let mut ticks = tokio::time::interval(HEARTBEAT);
    ticks.tick().await; // The first tick completes at once.
    let mut beats = 0;
    loop {
        let store = store.clone();
        let done = tokio::select! {
            _ = ticks.tick() => {
                beats += 1;
                off_thread(move || beat(&store, beats, now())).await
            }
            () = due.notified() => off_thread(move || store.enforce_limits(now())).await,
        };
        if let Err(error) = done {
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
mod load_tests;
#[cfg(test)]
mod refused_tests;
#[cfg(test)]
mod tests;
