//! The time a run cleans up the metric history by.
//!
//! Samples go once they are older than `history_days` and are thinned once
//! they are older than eight days, both counted from a run's time. A clock
//! that jumps ahead would take with it what both still keep; a year ahead,
//! all of it. So a run's time is believed only where it is plausible against
//! the last run the store believed: at most ten minutes after it, the gap
//! the watch allows between two runs, or before it, since a clean-up by an
//! earlier time removes nothing more. A run that comes later is stored like
//! any other, but cleans up by the time believed last.
//!
//! A long downtime looks the same as such a jump, so the store believes a
//! new time once the clock has kept it for a day: each run no more than ten
//! minutes after the one before it, without a jump back. A clock that comes
//! back within ten minutes of the time believed is believed again at once.

use garrison_core::time;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::watch::LIMIT;

/// How long a clock keeps a time the store did not believe before it does.
const HOLD: i64 = 86400;
/// The time of the last run the store believed.
const BELIEVED: &str = "store.believed";
/// The first run of those since that came too late to be believed.
const AHEAD_SINCE: &str = "store.ahead-since";

/// `second` where it is a time at all; the database is read as data.
fn when(second: i64) -> Option<i64> {
    time::Timestamp::from_second(second).ok().map(|_| second)
}

fn recall(transaction: &Transaction<'_>, key: &str) -> rusqlite::Result<Option<i64>> {
    let text: Option<String> = transaction
        .query_row("SELECT value FROM memory WHERE key = ?", [key], |row| {
            row.get(0)
        })
        .optional()?;
    // A value that does not read is as good as none.
    Ok(text.and_then(|text| text.parse().ok()).and_then(when))
}

fn keep(transaction: &Transaction<'_>, key: &str, second: i64) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO memory VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, second.to_string()],
    )?;
    Ok(())
}

fn at(second: i64) -> String {
    time::Timestamp::from_second(second).map_or_else(|_| second.to_string(), time::isoformat)
}

/// The time the run at `now` cleans up by: its own where the store believes
/// it, else the last one it believed. `previous` is when the run before it
/// collected, the newest snapshot's time.
pub(super) fn cleaned_by(
    transaction: &Transaction<'_>,
    now: i64,
    previous: Option<i64>,
) -> rusqlite::Result<i64> {
    let previous = previous.and_then(when);
    // A database of a release before this one has its newest snapshot to go
    // by; the very first run has nothing to hold its clock against.
    let Some(believed) = recall(transaction, BELIEVED)?.or(previous) else {
        keep(transaction, BELIEVED, now)?;
        return Ok(now);
    };
    let since = recall(transaction, AHEAD_SINCE)?;
    if now <= believed.saturating_add(LIMIT) {
        if since.is_some() {
            transaction.execute("DELETE FROM memory WHERE key = ?", [AHEAD_SINCE])?;
            log::info!(
                "The clock is back within ten minutes of {}; the metric history is cleaned up \
                 by it again",
                at(believed)
            );
        }
        keep(transaction, BELIEVED, now)?;
        return Ok(now);
    }
    // The day is counted from run to run: another jump begins it again.
    let follows =
        previous.is_some_and(|previous| (0..=LIMIT).contains(&now.saturating_sub(previous)));
    let since = match since {
        Some(since) if follows => since,
        _ => {
            log::warn!(
                "This collection run is dated {}, more than ten minutes after {}, the last time \
                 the metric history was cleaned up by. The history keeps what it holds until \
                 the clock has kept this time for a day or comes back.",
                at(now),
                at(believed)
            );
            keep(transaction, AHEAD_SINCE, now)?;
            now
        }
    };
    if now.saturating_sub(since) < HOLD {
        return Ok(believed);
    }
    transaction.execute("DELETE FROM memory WHERE key = ?", [AHEAD_SINCE])?;
    keep(transaction, BELIEVED, now)?;
    log::info!(
        "The clock has kept its new time since {} for a day; the metric history is cleaned up \
         by it again",
        at(since)
    );
    Ok(now)
}

#[cfg(test)]
mod tests;
