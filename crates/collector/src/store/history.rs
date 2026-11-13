//! The metric history of a range in buckets, as the dashboard draws it.
//!
//! A sample stands for the minutes it holds: one, or up to ten where the
//! store thinned it (thinning.rs). Gauges are averaged over those minutes and
//! increases summed, so a thinned history reads as the minutes did. A thinned
//! sample lies in the bucket of its first minute.

use rusqlite::{Connection, params};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::values::float;

/// The history periods the interface offers: seconds and buckets.
pub const PERIODS: [(&str, i64, usize); 4] = [
    ("24h", 86400, 48),
    ("7d", 7 * 86400, 56),
    ("30d", 30 * 86400, 60),
    ("90d", 90 * 86400, 90),
];

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("Invalid time range or resolution")]
    Invalid,
    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// The recorded samples of a time range in buckets. The series are whatever
/// the providers stored, so each point is a map from a series' name to its
/// value in that bucket, or `null` where nothing was recorded.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct History {
    pub from: i64,
    pub to: i64,
    /// One per bucket, each with the `timestamp` of the bucket's middle.
    pub points: Vec<Map<String, Value>>,
    /// The sum of each counter's increases in the range.
    pub totals: Map<String, Value>,
    /// The first and the last minute that have a sample, and how many minutes
    /// have one; a thinned sample counts for the minutes it holds.
    pub coverage_from: Option<i64>,
    pub coverage_to: Option<i64>,
    pub sampled_minutes: i64,
    pub counter_resets: i64,
    /// The newest value of each gauge in the range.
    pub latest: Map<String, Value>,
}

/// Where each bucket of a range of `seconds` begins: bucket `index` holds the
/// seconds from `[index]` up to, not including, `[index + 1]`, counted from
/// the start of the range; the last entry is `seconds`.
///
/// A second's bucket is `second / span`, cut off to a whole number. Each limit
/// is the first second that expression puts into its bucket or a later one,
/// found by halving the range, so a second at a limit lies in the bucket the
/// expression gives it, also when the span is no whole number.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn bucket_limits(seconds: i64, buckets: usize) -> Vec<i64> {
    let span = seconds as f64 / buckets as f64;
    let bucket_of = |second: i64| (second as f64 / span) as usize;
    (0..=buckets)
        .map(|index| {
            let (mut first, mut beyond) = (0, seconds);
            while first < beyond {
                let middle = first + (beyond - first) / 2;
                if bucket_of(middle) < index {
                    first = middle + 1;
                } else {
                    beyond = middle;
                }
            }
            first
        })
        .collect()
}

/// The names of all series, in order. Each step asks the primary key for the
/// next name, so the samples themselves are not read.
fn series(db: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut statement = db.prepare(
        "WITH RECURSIVE series(name) AS (\
           SELECT min(name) FROM samples \
           UNION ALL \
           SELECT (SELECT min(name) FROM samples WHERE name > series.name) \
           FROM series WHERE series.name IS NOT NULL) \
         SELECT name FROM series WHERE name IS NOT NULL",
    )?;
    statement.query_map([], |row| row.get(0))?.collect()
}

/// The minutes a sample stands for, as SQL. A reader may meet a database the
/// collector has not migrated yet, for a moment after an upgrade: there every
/// sample is one minute.
fn weight(db: &Connection) -> rusqlite::Result<&'static str> {
    let version: i64 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    Ok(if version >= 2 { "minutes" } else { "1" })
}

/// Samples in buckets: gauges are averaged over their minutes, increases are
/// summed. Missing data stays missing (`null`), never zero.
///
/// Each series is read bucket by bucket along the primary key (name, time),
/// and SQLite aggregates the rows as it passes them. One query that groups
/// all samples of the range had to sort them first, which took longer than a
/// reader's time budget once a host held 90 days of them.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
pub fn history(
    db: &Connection,
    start: i64,
    end: i64,
    buckets: usize,
) -> Result<History, HistoryError> {
    let seconds = end.checked_sub(start).unwrap_or(0);
    if !(1..=730 * 86400).contains(&seconds) || !(1..=1440).contains(&buckets) {
        return Err(HistoryError::Invalid);
    }
    let span = seconds as f64 / buckets as f64;
    let mut points: Vec<Map<String, Value>> = (0..buckets)
        .map(|index| {
            let mut point = Map::new();
            let middle = start as f64 + (index as f64 + 0.5) * span;
            point.insert("timestamp".into(), json!(middle as i64));
            point
        })
        .collect();
    let limits = bucket_limits(seconds, buckets);
    // `weight` is one of two fixed words, never text from outside.
    let weight = weight(db)?;
    let mut bucket = db.prepare(&format!(
        "SELECT sum(value * {weight}) FILTER (WHERE kind = 'gauge') \
                / sum({weight}) FILTER (WHERE kind = 'gauge'), \
                sum(value) FILTER (WHERE kind = 'increase') \
         FROM samples WHERE name = ? AND ts >= ? AND ts < ?"
    ))?;
    let mut newest = db.prepare(
        "SELECT value FROM samples WHERE name = ? AND kind = 'gauge' AND ts >= ? AND ts < ? \
         ORDER BY ts DESC LIMIT 1",
    )?;
    let mut totals: Map<String, Value> = Map::new();
    let mut latest = Map::new();
    let mut names: Vec<String> = Vec::new();
    for name in series(db)? {
        let (mut total, mut sampled, mut gauge) = (0.0, false, false);
        for (index, point) in points.iter_mut().enumerate() {
            let (from, to) = (start + limits[index], start + limits[index + 1]);
            if from == to {
                continue;
            }
            let (average, sum): (Option<f64>, Option<f64>) = bucket
                .query_row(params![name, from, to], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?;
            if let Some(value) = average {
                point.insert(name.clone(), float(value));
                gauge = true;
            }
            // A name used as a gauge and as a counter shows its increases.
            if let Some(value) = sum {
                point.insert(name.clone(), float(value));
                total += value;
                totals.insert(name.clone(), float(total));
            }
            sampled |= average.is_some() || sum.is_some();
        }
        if gauge {
            let value: f64 = newest.query_row(params![name, start, end], |row| row.get(0))?;
            latest.insert(name.clone(), float(value));
        }
        if sampled {
            names.push(name);
        }
    }
    for point in &mut points {
        for name in &names {
            point.entry(name.clone()).or_insert(Value::Null);
        }
    }
    // The series of one run share its minute, so a minute counts once; a
    // thinned one counts for the most minutes any series holds there.
    let (first, last, minutes): (Option<i64>, Option<i64>, i64) = db.query_row(
        &format!(
            "SELECT min(ts), max(ts), coalesce(sum(held), 0) FROM \
             (SELECT ts, max({weight}) AS held FROM samples WHERE ts >= ? AND ts < ? GROUP BY ts)"
        ),
        [start, end],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let resets: i64 = db.query_row(
        "SELECT count(*) FROM resets WHERE ts >= ? AND ts < ?",
        [start, end],
        |row| row.get(0),
    )?;
    Ok(History {
        from: start,
        to: end,
        points,
        totals,
        coverage_from: first,
        coverage_to: last,
        sampled_minutes: minutes,
        counter_resets: resets,
        latest,
    })
}

#[cfg(test)]
mod tests;
