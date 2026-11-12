//! Which Stalwart events are recorded, and which of their fields are kept.
//!
//! This is the privacy boundary of the event history. Raw protocol input and
//! output, message bodies, Milter frames, request URLs and credentials are never
//! selected. Fields not listed here are dropped before anything is written to
//! disk.

use serde_json::{Map, Number, Value};

pub use crate::event_type::EventType;

/// Never requested, even if an operator edits the native webhook by hand.
pub const FORBIDDEN_EVENTS: [&str; 14] = [
    "auth.error",
    "delivery.raw-input",
    "delivery.raw-output",
    "http.request-body",
    "http.request-url",
    "http.response-body",
    "imap.raw-input",
    "imap.raw-output",
    "milter.frame-invalid",
    "milter.read",
    "milter.unexpected-response",
    "milter.write",
    "smtp.raw-input",
    "smtp.raw-output",
];

const SCALAR_FIELDS: [&str; 25] = [
    "messageId",
    "hostname",
    "domain",
    "remoteIp",
    "localIp",
    "remotePort",
    "localPort",
    "code",
    "elapsed",
    "size",
    "total",
    "totalSuccesses",
    "totalFailures",
    "totalRecipients",
    "retryNum",
    "listenerId",
    "protocol",
    "accountId",
    "expires",
    "nextRetry",
    "nextDsn",
    "queueName",
    "version",
    "causedBy",
    "policy",
];
const ADDRESS_FIELDS: [&str; 2] = ["from", "to"];
/// Large unsigned identifiers are stored as strings: JavaScript cannot represent
/// 64-bit queue and span IDs exactly as numbers.
const IDENTIFIER_FIELDS: [&str; 2] = ["queueId", "spanId"];
/// Free-form text is kept only where it carries a remote or local verdict that
/// an operator needs (for example "DNS lookup failed: null MX"), and is truncated.
const DETAIL_FIELDS: [&str; 2] = ["details", "reason"];
const DETAIL_CATEGORIES: [&str; 5] = ["delivery", "queue", "milter", "mta-hook", "server"];
/// Where only the verdict itself is kept: why a sign-in was refused, an
/// address banned or a TLS handshake ended.
const REASON_CATEGORIES: [&str; 3] = ["auth", "security", "tls"];
/// The name someone tried to sign in with is kept only where Stalwart found
/// an account of that name, which it says with `accountId`. Any other name
/// may be a password typed into the wrong field, and is not stored.
const ACCOUNT_NAME: &str = "accountName";
const ACCOUNT_ID: &str = "accountId";
const ACCOUNT_CATEGORIES: [&str; 2] = ["auth", "security"];
/// What a check of the sender came to. Stalwart sends it with everything
/// the check looked at; only the outcome's name is kept, such as `spf.fail`.
const RESULT: &str = "result";
const MAX_RESULTS: usize = 3;
const MAX_TEXT: usize = 300;
const MAX_ADDRESS: usize = 254;
const MAX_ADDRESSES: usize = 100;
/// Integers beyond ±2^53 lose precision in JavaScript and are kept as text.
const EXACT_INTEGER: i128 = 1 << 53;

/// Whether a name spells a recorded event type.
pub fn is_recorded(event_type: &str) -> bool {
    EventType::parse(event_type).is_some()
}

/// Every recorded event type, sorted.
pub fn event_types() -> Vec<&'static str> {
    let mut all: Vec<&str> = EventType::ALL.iter().map(|kind| kind.as_str()).collect();
    all.sort_unstable();
    all
}

/// The part before the first dot: `smtp`, `delivery`, `queue`, ...
pub fn category(event_type: &str) -> &str {
    event_type
        .split_once('.')
        .map_or(event_type, |(first, _)| first)
}

fn truncated(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

fn scalar(value: &Value) -> Option<Value> {
    match value {
        Value::Null | Value::Array(_) | Value::Object(_) => None,
        Value::Bool(_) => Some(value.clone()),
        Value::Number(number) => Some(match integer(number) {
            Some(whole) if whole <= -EXACT_INTEGER || whole >= EXACT_INTEGER => {
                Value::String(whole.to_string())
            }
            _ => value.clone(),
        }),
        Value::String(text) => Some(Value::String(truncated(text, MAX_TEXT))),
    }
}

fn integer(number: &Number) -> Option<i128> {
    number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
}

/// A positive integer identifier as text; 0 means "no span" natively.
pub fn identifier(value: &Value) -> Option<String> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .filter(|whole| *whole > 0)
            .map(|whole| whole.to_string()),
        Value::String(text)
            if (1..=20).contains(&text.len())
                && text.bytes().all(|byte| byte.is_ascii_digit())
                && text.bytes().any(|byte| byte != b'0') =>
        {
            Some(text.clone())
        }
        _ => None,
    }
}

/// The name of a check's outcome: of one result, or of each signature's
/// where a message carried several. No signature at all reads `none`.
fn outcome(value: &Value) -> Option<String> {
    let name = |item: &Value| item["type"].as_str().map(|name| truncated(name, 40));
    match value {
        Value::Object(_) => name(value),
        Value::Array(items) if items.is_empty() => Some("none".to_owned()),
        Value::Array(items) => {
            let names: Vec<String> = items.iter().take(MAX_RESULTS).filter_map(name).collect();
            (!names.is_empty()).then(|| names.join(", "))
        }
        _ => None,
    }
}

/// The fields of one event that may be stored, in the order Stalwart sent them.
pub fn select_fields(event_type: EventType, data: &Value) -> Map<String, Value> {
    let mut result = Map::new();
    let Value::Object(data) = data else {
        return result;
    };
    let details = DETAIL_CATEGORIES.contains(&event_type.category());
    let reason = REASON_CATEGORIES.contains(&event_type.category());
    for (key, value) in data {
        let key = key.as_str();
        if IDENTIFIER_FIELDS.contains(&key) {
            if let Some(text) = identifier(value) {
                result.insert(key.to_owned(), Value::String(text));
            }
        } else if ADDRESS_FIELDS.contains(&key) {
            let items = match value {
                Value::Array(items) => items.as_slice(),
                single => std::slice::from_ref(single),
            };
            let addresses: Vec<Value> = items
                .iter()
                .take(MAX_ADDRESSES)
                .filter_map(Value::as_str)
                .map(|address| Value::String(truncated(address, MAX_ADDRESS)))
                .collect();
            match (value, addresses.first()) {
                (_, None) => {}
                (Value::Array(_), Some(_)) => {
                    result.insert(key.to_owned(), Value::Array(addresses));
                }
                (_, Some(first)) => {
                    result.insert(key.to_owned(), first.clone());
                }
            }
        } else if (SCALAR_FIELDS.contains(&key)
            || (details && DETAIL_FIELDS.contains(&key))
            || (reason && key == "reason"))
            && let Some(kept) = scalar(value)
        {
            result.insert(key.to_owned(), kept);
        } else if key == RESULT && event_type.category() == "smtp" {
            if let Some(outcome) = outcome(value) {
                result.insert(key.to_owned(), Value::String(outcome));
            }
        } else if key == ACCOUNT_NAME
            && ACCOUNT_CATEGORIES.contains(&event_type.category())
            && data.get(ACCOUNT_ID).is_some_and(Value::is_number)
            && let Value::String(name) = value
        {
            result.insert(key.to_owned(), Value::String(truncated(name, MAX_ADDRESS)));
        }
    }
    result
}

#[cfg(test)]
mod tests;
