//! Older samples in ten-minute steps. The metric history keeps every minute of
//! the last eight days, which the 24-hour and 7-day views draw; before that,
//! one sample per series and ten minutes stands for the minutes it holds
//! (`minutes`), as the 30-day and 90-day views need no finer steps. A gauge
//! keeps its average over those minutes and an increase their sum, so the
//! history reads the same (history.rs). With every check, 90 days take some
//! 48 MiB instead of 250.
//!
//! Each run thins at most one day, the oldest not yet thinned, and remembers
//! how far it got: after an upgrade the history is thinned within some 80
//! runs, and no single run takes long.

use rusqlite::{OptionalExtension, Transaction, params};

/// Every minute is kept for this long.
const FINE: i64 = 8 * 86400;
/// The step of a thinned sample.
const STEP: i64 = 600;
/// The most one run thins.
const MOST: i64 = 86400;
/// Where the store keeps the start of what it has not thinned yet.
const KEPT: &str = "store.thinned-to";

/// One sample per series and step for the samples of `?1..?2`. A name stored
/// as a gauge and as a counter within one step keeps its increases, as the
/// history shows them. The step's own first minute, if it has a sample, takes
/// the result; the other minutes go after.
const THIN: &str = "INSERT INTO samples(name, ts, value, kind, minutes) \
     SELECT name, ts - ts % ?3 AS step, \
            CASE WHEN max(kind = 'increase') THEN sum(value) FILTER (WHERE kind = 'increase') \
                 ELSE sum(value * minutes) / sum(minutes) END, \
            CASE WHEN max(kind = 'increase') THEN 'increase' ELSE 'gauge' END, \
            CASE WHEN max(kind = 'increase') THEN sum(minutes) FILTER (WHERE kind = 'increase') \
                 ELSE sum(minutes) END \
     FROM samples WHERE ts >= ?1 AND ts < ?2 GROUP BY name, step \
     ON CONFLICT(name, ts) DO UPDATE SET \
         value = excluded.value, kind = excluded.kind, minutes = excluded.minutes";

/// Where the last run stopped, or, before the first one, the step of the
/// oldest sample.
fn start(transaction: &Transaction<'_>) -> rusqlite::Result<Option<i64>> {
    let kept: Option<String> = transaction
        .query_row("SELECT value FROM memory WHERE key = ?", [KEPT], |row| {
            row.get(0)
        })
        .optional()?;
    if let Some(at) = kept.and_then(|text| text.parse().ok()) {
        return Ok(Some(at));
    }
    let oldest: Option<i64> =
        transaction.query_row("SELECT min(ts) FROM samples", [], |row| row.get(0))?;
    Ok(oldest.map(|at| at - at.rem_euclid(STEP)))
}

/// Thins up to one day of samples, from where the last run stopped, and never
/// closer to `minute` than eight days. All of it or nothing: a step is never
/// left with its minutes and their sum both.
pub(super) fn thin(transaction: &mut Transaction<'_>, minute: i64) -> rusqlite::Result<()> {
    let Some(from) = start(transaction)? else {
        return Ok(());
    };
    let horizon = minute - FINE;
    let to = (from + MOST).min(horizon - horizon.rem_euclid(STEP));
    if to <= from {
        return Ok(());
    }
    let savepoint = transaction.savepoint()?;
    savepoint.execute(THIN, params![from, to, STEP])?;
    savepoint.execute(
        "DELETE FROM samples WHERE ts >= ?1 AND ts < ?2 AND ts % ?3 != 0",
        params![from, to, STEP],
    )?;
    savepoint.execute(
        "INSERT INTO memory VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![KEPT, to.to_string()],
    )?;
    savepoint.commit()
}

#[cfg(test)]
mod tests;
