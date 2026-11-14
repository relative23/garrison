//! Whether the event history can stand for the time a check counts over.
//!
//! A history that can be read is not yet a current one. While the receiver
//! is away nothing arrives, and what it lost while it was away longer than
//! Stalwart keeps events is gone: a quiet history then is no quiet server.
//! The checks that count events ask here before they call a count in order.

use garrison_core::recording::{self, QUIET_AFTER};
use rusqlite::Connection;

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
