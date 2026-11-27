//! The time a run cleans up the metric history by: the collector's run
//! time, which a jump of the host's clock cannot take along
//! (`garrison_core::run_time`). A step from one run to the next of at most
//! ten minutes, the gap the watch allows between two runs, moves it on; a
//! run further ahead is stored like any other and cleans up by the run
//! time, until the collector has run at its clock's new time for a day or
//! the clock comes back.

use garrison_core::run_time::{self, Kept, Pace, Turn};
use garrison_core::time;
use log::Level;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::watch::LIMIT;

/// The steps of the collector: ten minutes move its run time on, a day at
/// a time ahead makes that time believed, and a longer step counts as one
/// run of the timer, which starts the collector once in every minute.
const PACE: Pace = Pace {
    limit: LIMIT,
    hold: 86400,
    run: 60,
};
/// The collector's run time, which the history is cleaned up by.
const BELIEVED: &str = "store.believed";
/// How long the collector has run at a time ahead of its run time.
const AHEAD_FOR: &str = "store.ahead-for";

fn recall(transaction: &Transaction<'_>, key: &str) -> rusqlite::Result<Option<i64>> {
    let text: Option<String> = transaction
        .query_row("SELECT value FROM memory WHERE key = ?", [key], |row| {
            Ok(super::as_written(row.get_ref(0)?))
        })
        .optional()?
        .flatten();
    // A value that does not read, as no text or no number, is as good as
    // none.
    Ok(text.and_then(|text| text.parse().ok()))
}

/// Keeps `value` under `key`, or nothing there where it is none.
fn keep(transaction: &Transaction<'_>, key: &str, value: Option<i64>) -> rusqlite::Result<()> {
    match value {
        Some(value) => transaction.execute(
            "INSERT INTO memory VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value.to_string()],
        )?,
        None => transaction.execute("DELETE FROM memory WHERE key = ?", [key])?,
    };
    Ok(())
}

fn at(second: i64) -> String {
    time::Timestamp::from_second(second).map_or_else(|_| second.to_string(), time::isoformat)
}

/// The time a run cleans up the history by, and what the collector's
/// journal says of it where a stretch at a time ahead begins or ends.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Cleaned {
    pub(super) by: i64,
    pub(super) said: Option<(Level, String)>,
}

/// The time the run at `now` cleans up by: its own where the store believes
/// it, else the collector's run time. `previous` is when the run before it
/// collected, the newest snapshot's time.
pub(super) fn cleaned_by(
    transaction: &Transaction<'_>,
    now: i64,
    previous: Option<i64>,
) -> rusqlite::Result<Cleaned> {
    let kept = Kept {
        believed: recall(transaction, BELIEVED)?,
        ahead_for: recall(transaction, AHEAD_FOR)?,
    };
    let looked = run_time::look(kept, now, previous, PACE);
    keep(transaction, BELIEVED, looked.kept.believed)?;
    if looked.kept.ahead_for != kept.ahead_for {
        keep(transaction, AHEAD_FOR, looked.kept.ahead_for)?;
    }
    let said = looked.turn.map(|turn| match turn {
        Turn::Back => (
            Level::Info,
            "The clock is back within ten minutes of the collector's run time; the metric \
             history is cleaned up by it again"
                .to_owned(),
        ),
        Turn::Ahead { believed } => (
            Level::Warn,
            format!(
                "This collection run is dated {}, more than ten minutes after the collector's \
                 own run time, {}: the clock went ahead, or the collector paused. The metric \
                 history is cleaned up by the run time until the collector has run at this \
                 time for a day, or the clock comes back.",
                at(now),
                at(believed)
            ),
        ),
        Turn::Held => (
            Level::Info,
            "The collector has run for a day at its clock's new time; the metric history is \
             cleaned up by the clock again"
                .to_owned(),
        ),
    });
    Ok(Cleaned {
        by: looked.by,
        said,
    })
}

#[cfg(test)]
mod tests;
