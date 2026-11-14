//! The time a run cleans up the metric history by.
//!
//! Samples go once they are older than `history_days` and are thinned once
//! they are older than eight days. Counted from a run's own time, a clock
//! that jumps ahead would take with it what both still keep; a year ahead,
//! all of it. So the store keeps a clock of its own, the collector's run
//! time: each step from one run to the next of at most ten minutes, the gap
//! the watch allows between two runs, moves it on by that step; a longer
//! one, a pause or a jump, moves it not at all. It cannot jump, so clean-up
//! never stops: it lags at most by the pauses not counted yet.
//!
//! A run's own time is believed, and taken as that clock, when it is at most
//! ten minutes after it, or before it: a clean-up by an earlier time removes
//! nothing more, and a clock put right after hours ahead is back within ten
//! minutes of the run time. A run further ahead is stored like any other. A
//! pause looks the same as a jump, so the run's time is believed once the
//! collector has run at it for a day: each step of ten minutes or less adds
//! its length, a longer one adds a minute, one run of the timer, so that a
//! collector that only runs every quarter hour finds its way back too, and a
//! step back by more than ten minutes, to another time still ahead, begins
//! the day again.

use garrison_core::time;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::watch::LIMIT;

/// How long the collector runs at a time ahead of its run time before the
/// store believes that time.
const HOLD: i64 = 86400;
/// What a step longer than [`LIMIT`] counts towards [`HOLD`]: one run of the
/// timer, which starts the collector a minute after its last run.
const RUN: i64 = 60;
/// The collector's run time, which the history is cleaned up by.
const BELIEVED: &str = "store.believed";
/// How long the collector has run at a time ahead of its run time.
const AHEAD_FOR: &str = "store.ahead-for";

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
    Ok(text.and_then(|text| text.parse().ok()))
}

fn keep(transaction: &Transaction<'_>, key: &str, value: i64) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO memory VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value.to_string()],
    )?;
    Ok(())
}

fn forget(transaction: &Transaction<'_>, key: &str) -> rusqlite::Result<()> {
    transaction.execute("DELETE FROM memory WHERE key = ?", [key])?;
    Ok(())
}

fn at(second: i64) -> String {
    time::Timestamp::from_second(second).map_or_else(|_| second.to_string(), time::isoformat)
}

/// What the step from the run before, `previous`, to `now` adds to the run
/// time, and towards the day a time ahead must last; `None` begins that day
/// again.
fn step(previous: Option<i64>, now: i64) -> (i64, Option<i64>) {
    match previous.map(|previous| now.saturating_sub(previous)) {
        Some(step) if (0..=LIMIT).contains(&step) => (step, Some(step)),
        // A step back within what a step forward may take is no time.
        Some(step) if (-LIMIT..0).contains(&step) => (0, Some(0)),
        Some(step) if step < 0 => (0, None),
        // A pause, a jump ahead, or no run before to hold it against.
        _ => (0, Some(RUN)),
    }
}

/// The time the run at `now` cleans up by: its own where the store believes
/// it, else the collector's run time. `previous` is when the run before it
/// collected, the newest snapshot's time.
pub(super) fn cleaned_by(
    transaction: &Transaction<'_>,
    now: i64,
    previous: Option<i64>,
) -> rusqlite::Result<i64> {
    let previous = previous.and_then(when);
    // A database of a release before this one has its newest snapshot to go
    // by; the very first run has nothing to hold its clock against.
    let Some(believed) = recall(transaction, BELIEVED)?.and_then(when).or(previous) else {
        keep(transaction, BELIEVED, now)?;
        return Ok(now);
    };
    let ahead = recall(transaction, AHEAD_FOR)?.filter(|ahead| (0..HOLD).contains(ahead));
    if now <= believed.saturating_add(LIMIT) {
        if ahead.is_some() {
            forget(transaction, AHEAD_FOR)?;
            log::info!(
                "The clock is back within ten minutes of the collector's run time; the metric \
                 history is cleaned up by it again"
            );
        }
        keep(transaction, BELIEVED, now)?;
        return Ok(now);
    }
    let (counted, towards) = step(previous, now);
    let run_time = believed.saturating_add(counted);
    keep(transaction, BELIEVED, run_time)?;
    let Some(ahead) = ahead
        .zip(towards)
        .map(|(ahead, step)| ahead.saturating_add(step))
    else {
        log::warn!(
            "This collection run is dated {}, more than ten minutes after the collector's own \
             run time, {}: the clock went ahead, or the collector paused. The metric history \
             is cleaned up by the run time until the collector has run at this time for a \
             day, or the clock comes back.",
            at(now),
            at(believed)
        );
        keep(transaction, AHEAD_FOR, 0)?;
        return Ok(run_time);
    };
    if ahead < HOLD {
        keep(transaction, AHEAD_FOR, ahead)?;
        return Ok(run_time);
    }
    forget(transaction, AHEAD_FOR)?;
    keep(transaction, BELIEVED, now)?;
    log::info!(
        "The collector has run for a day at its clock's new time; the metric history is \
         cleaned up by the clock again"
    );
    Ok(now)
}

#[cfg(test)]
mod tests;
