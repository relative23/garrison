//! Whether the event history can stand for the time a check counts over.
//!
//! A history that can be read is not yet a current one. While the receiver
//! is away nothing arrives, and what it lost while it was away longer than
//! Stalwart keeps events is gone: a quiet history then is no quiet server.
//! The checks that count events ask here before they call a count in order.

use garrison_core::recording::{self, QUIET_AFTER};
use rusqlite::Connection;
use rusqlite::types::ValueRef;
use serde_json::Value;

/// Why the history does not hold what happened from `since` until `until`,
/// in words for a finding; `None` when it does. What the receiver recorded
/// about itself and cannot be read is a reason too.
pub(super) fn uncovered(db: &Connection, since: i64, until: i64) -> Option<String> {
    match recording::uncovered(db, since, until, QUIET_AFTER) {
        Ok(reason) => reason.map(|reason| reason.to_string()),
        Err(error) => Some(format!(
            "what the event receiver recorded about itself cannot be read ({error})"
        )),
    }
}

/// The fields of an event as the event receiver writes them, a JSON object
/// in text; none for any other value, as the user who writes the history
/// can put there.
pub(super) fn fields(value: ValueRef<'_>) -> Option<Value> {
    let ValueRef::Text(text) = value else {
        return None;
    };
    serde_json::from_slice::<Value>(text)
        .ok()
        .filter(Value::is_object)
}

/// What a card says of the events of the history it left out, where a
/// value in them is of another type than the receiver writes.
pub(super) fn left_out(count: u64) -> Option<String> {
    match count {
        0 => None,
        1 => Some("1 event of the history could not be read and is left out.".to_owned()),
        _ => Some(format!(
            "{count} events of the history could not be read and are left out."
        )),
    }
}
