//! The metric history, read bucket by bucket, against one query that groups
//! every sample of the range at once and must give the same answer.

use std::time::Duration;

use garrison_core::sqlite::{out_of_time, reading};
use garrison_testing::noise::Noise;

use super::*;

/// What the comparison looks at.
struct Grouped {
    points: Vec<Map<String, Value>>,
    totals: Map<String, Value>,
    latest: Map<String, Value>,
}

/// Points, totals and newest gauge values as one grouping query gives them.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn grouped_at_once(db: &Connection, start: i64, end: i64, buckets: usize) -> Grouped {
    let span = (end - start) as f64 / buckets as f64;
    let mut points: Vec<Map<String, Value>> = (0..buckets)
        .map(|index| {
            let middle = start as f64 + (index as f64 + 0.5) * span;
            Map::from_iter([("timestamp".to_owned(), json!(middle as i64))])
        })
        .collect();
    let mut statement = db
        .prepare(
            "SELECT name, kind, CAST((ts - ?) / ? AS INTEGER) AS bucket, \
             CASE kind WHEN 'gauge' THEN avg(value) ELSE sum(value) END AS value \
             FROM samples WHERE ts >= ? AND ts < ? GROUP BY name, kind, bucket",
        )
        .unwrap();
    let mut rows = statement.query(params![start, span, start, end]).unwrap();
    let mut totals = Map::new();
    let mut sums: BTreeMap<String, f64> = BTreeMap::new();
    let mut names: Vec<String> = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        let (name, kind): (String, String) = (row.get(0).unwrap(), row.get(1).unwrap());
        let bucket = usize::try_from(row.get::<_, i64>(2).unwrap()).unwrap();
        let value: f64 = row.get(3).unwrap();
        points[bucket].insert(name.clone(), float(value));
        if kind == "increase" {
            let total = sums.entry(name.clone()).or_insert(0.0);
            *total += value;
            totals.insert(name.clone(), float(*total));
        }
        if !names.contains(&name) {
            names.push(name);
        }
    }
    for point in &mut points {
        for name in &names {
            point.entry(name.clone()).or_insert(Value::Null);
        }
    }
    let mut latest = Map::new();
    let mut statement = db
        .prepare(
            "SELECT s.name, s.value FROM samples s JOIN (SELECT name, max(ts) AS ts FROM samples \
             WHERE kind='gauge' AND ts >= ? AND ts < ? GROUP BY name) m \
             ON s.name = m.name AND s.ts = m.ts",
        )
        .unwrap();
    let mut rows = statement.query([start, end]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        latest.insert(row.get(0).unwrap(), float(row.get(1).unwrap()));
    }
    Grouped {
        points,
        totals,
        latest,
    }
}

/// Five series over about three hours, at seconds that no bucket is aligned
/// to: a gauge, a counter, one name used as both, one with a long gap and one
/// that ends early.
fn uneven_samples(db: &Connection) {
    let mut noise = Noise::new(53);
    let mut insert = db
        .prepare("INSERT OR IGNORE INTO samples VALUES(?,?,?,?)")
        .unwrap();
    let mut at = 10_000;
    while at < 21_000 {
        at += 1 + i64::try_from(noise.below(90)).unwrap();
        let value =
            |noise: &mut Noise| f64::from(u32::try_from(noise.below(100_000)).unwrap()) / 7.0;
        insert
            .execute(params!["a_gauge", at, value(&mut noise), "gauge"])
            .unwrap();
        insert
            .execute(params!["b_counter", at + 1, value(&mut noise), "increase"])
            .unwrap();
        let kind = if noise.below(2) == 0 {
            "gauge"
        } else {
            "increase"
        };
        insert
            .execute(params!["c_both", at, value(&mut noise), kind])
            .unwrap();
        if !(13_000..18_000).contains(&at) {
            insert
                .execute(params!["d_gap", at, value(&mut noise), "gauge"])
                .unwrap();
        }
        if at < 12_500 {
            insert
                .execute(params!["e_early", at, value(&mut noise), "increase"])
                .unwrap();
        }
    }
}

#[test]
fn every_range_and_bucket_count_gives_what_one_grouping_query_gives() {
    let directory = tempfile::tempdir().unwrap();
    let store = StatusStore::open(&directory.path().join("status.sqlite"), 90).unwrap();
    uneven_samples(&store.db);
    let ranges = [
        (10_000, 21_000),
        (9_000, 23_000),
        (10_007, 20_993),
        (12_500, 13_000),
        (13_100, 17_900),
        (20_000, 20_059),
        (0, 9_999),
    ];
    let mut compared = 0;
    for (start, end) in ranges {
        // Spans that are whole numbers of seconds and spans that are not,
        // down to more buckets than the range has seconds.
        for buckets in [1, 2, 7, 48, 56, 60, 90, 97, 1440] {
            let found = history(&store.db, start, end, buckets).unwrap();
            let grouped = grouped_at_once(&store.db, start, end, buckets);
            let context = format!("{start}..{end} in {buckets}");
            // As text, so that the order of the names counts as well.
            assert_eq!(
                json!(found.points).to_string(),
                json!(grouped.points).to_string(),
                "{context}"
            );
            assert_eq!(
                json!(found.totals).to_string(),
                json!(grouped.totals).to_string(),
                "{context}"
            );
            assert_eq!(
                json!(found.latest).to_string(),
                json!(grouped.latest).to_string(),
                "{context}"
            );
            compared += found.points.iter().map(Map::len).sum::<usize>();
        }
    }
    assert!(compared > 50_000, "{compared}");
    // The range before the first sample names no series at all.
    let empty = history(&store.db, 0, 9_999, 3).unwrap();
    assert_eq!(empty.points.iter().map(Map::len).sum::<usize>(), 3);
    assert!(empty.totals.is_empty() && empty.latest.is_empty());
}

/// SQLite asks a reader for the time after 10,000 steps of one statement.
/// With so few samples no statement of a history takes that many in one run.
/// The bucket statement is prepared once, though, so its steps add up over
/// the buckets, and the history stops as one long query would.
#[test]
fn a_history_stops_when_its_reader_runs_out_of_time() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    let store = StatusStore::open(&path, 90).unwrap();
    for minute in 0..100 {
        store
            .db
            .execute(
                "INSERT INTO samples VALUES('queue', ?, 1.5, 'gauge')",
                [minute * 60],
            )
            .unwrap();
    }
    let hurried = reading(&path, Duration::ZERO).unwrap().unwrap();
    match history(&hurried, 0, 6_000, 1440) {
        Err(HistoryError::Sqlite(error)) => assert!(out_of_time(&error), "{error}"),
        other => panic!("{other:?}"),
    }
    // In few buckets the same history is short enough for any reader.
    assert!(history(&hurried, 0, 6_000, 10).is_ok());
    let patient = reading(&path, Duration::from_secs(60)).unwrap().unwrap();
    assert_eq!(
        history(&patient, 0, 6_000, 1440).unwrap(),
        history(&store.db, 0, 6_000, 1440).unwrap()
    );
}

#[test]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn a_second_lies_in_the_bucket_its_quotient_names() {
    let mut pairs = vec![
        (1, 1),
        (1, 1440),
        (59, 60),
        (60, 60),
        (86_400, 48),
        (7 * 86_400, 56),
    ];
    pairs.extend(
        (1..=400).flat_map(|seconds| [1, 2, 3, 7, 60, 97].map(|buckets| (seconds, buckets))),
    );
    for (seconds, buckets) in pairs {
        let limits = bucket_limits(seconds, buckets);
        assert_eq!(limits.len(), buckets + 1);
        assert_eq!(
            (limits[0], limits[buckets]),
            (0, seconds),
            "{seconds} in {buckets}"
        );
        assert!(limits.is_sorted(), "{seconds} in {buckets}");
        let span = seconds as f64 / buckets as f64;
        for second in 0..seconds.min(20_000) {
            let named = (second as f64 / span) as usize;
            assert!(
                limits[named] <= second && second < limits[named + 1],
                "second {second} of {seconds} in {buckets}"
            );
        }
    }
    // The longest range in the most buckets, at every limit.
    let (seconds, buckets) = (730 * 86_400, 1440);
    let limits = bucket_limits(seconds, buckets);
    let span = seconds as f64 / buckets as f64;
    for (index, limit) in limits.iter().enumerate().take(buckets) {
        assert_eq!((*limit as f64 / span) as usize, index);
        assert!(*limit == 0 || ((*limit - 1) as f64 / span) as usize == index - 1);
    }
}
