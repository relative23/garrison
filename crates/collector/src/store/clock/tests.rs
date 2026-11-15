use super::*;
use crate::store::StatusStore;

/// 2026-10-28T10:00:00Z.
const T0: i64 = 1_793_181_600;
const DAY: i64 = 86400;
const YEAR: i64 = 365 * DAY;

/// What each run at `times` cleans up by and says, each run after the one
/// before, in a store whose memory holds `memory` first. `previous` is when
/// the run before the first one collected.
fn runs_with(memory: &[(&str, &str)], previous: Option<i64>, times: &[i64]) -> Vec<Cleaned> {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StatusStore::open(&directory.path().join("status.sqlite"), 90).unwrap();
    for (key, value) in memory {
        store
            .db
            .execute("INSERT INTO memory VALUES(?, ?)", [key, value])
            .unwrap();
    }
    let mut previous = previous;
    times
        .iter()
        .map(|&now| {
            let transaction = store.db.transaction().unwrap();
            let cleaned = cleaned_by(&transaction, now, previous).unwrap();
            transaction.commit().unwrap();
            previous = Some(now);
            cleaned
        })
        .collect()
}

/// What each run at `times` cleans up by.
fn cleaned_with(memory: &[(&str, &str)], previous: Option<i64>, times: &[i64]) -> Vec<i64> {
    runs_with(memory, previous, times)
        .into_iter()
        .map(|cleaned| cleaned.by)
        .collect()
}

/// The journal lines of the runs at `times` in a new store, each with the
/// run's place among them.
fn journal(times: &[i64]) -> Vec<(usize, Level, String)> {
    runs_with(&[], None, times)
        .into_iter()
        .enumerate()
        .filter_map(|(run, cleaned)| cleaned.said.map(|(level, line)| (run, level, line)))
        .collect()
}

fn cleaned(times: &[i64]) -> Vec<i64> {
    cleaned_with(&[], None, times)
}

/// Runs every `every` seconds from `from` for `span` seconds, `from` first.
fn runs(from: i64, every: i64, span: i64) -> Vec<i64> {
    (0..=span / every).map(|run| from + run * every).collect()
}

#[test]
fn a_run_up_to_ten_minutes_later_or_any_earlier_is_believed() {
    let times = [
        T0,
        T0 + 600,
        T0 + 659,
        T0 + 659 - DAY,
        T0 + 659 - DAY + 1,
        T0 + 659 - YEAR,
    ];
    assert_eq!(cleaned(&times), times);
}

/// A jump is not counted, the runs at the time ahead are.
#[test]
fn a_run_further_ahead_cleans_up_by_the_collectors_run_time() {
    assert_eq!(cleaned(&[T0, T0 + 601]), [T0, T0]);
    assert_eq!(
        cleaned(&[T0, T0 + YEAR, T0 + YEAR + 60, T0 + YEAR + 120]),
        [T0, T0, T0 + 60, T0 + 120]
    );
}

#[test]
fn a_time_ahead_is_believed_once_the_collector_has_run_at_it_for_a_day() {
    // A downtime of a month, or a clock that nobody put right.
    let mut times = vec![T0];
    times.extend(runs(T0 + 30 * DAY, 600, DAY));
    let cleaned = cleaned(&times);
    let expected: Vec<i64> = (0..144).map(|run| T0 + run * 600).collect();
    assert_eq!(cleaned[1..145], expected[..]);
    assert_eq!(cleaned[145], T0 + 31 * DAY);
    // From then on the runs are believed one by one.
    times.push(T0 + 31 * DAY + 60);
    assert_eq!(cleaned_with(&[], None, &times)[146], T0 + 31 * DAY + 60);
}

/// Half a day at a year ahead, then another year: the second jump neither
/// ends the day nor begins it again, and is not counted itself.
#[test]
fn a_second_jump_ahead_neither_ends_nor_begins_the_day() {
    let mut times = vec![T0];
    times.extend(runs(T0 + YEAR, 600, DAY / 2));
    let again = T0 + 2 * YEAR + DAY / 2;
    times.extend(runs(again, 600, DAY / 2));
    let cleaned = cleaned(&times);
    let (held, last) = cleaned.split_at(cleaned.len() - 1);
    assert_eq!(last, [again + DAY / 2]);
    // Until then the history goes by the half days the collector ran.
    assert_eq!(held.iter().max(), Some(&(T0 + DAY - 600)));
}

/// From a year ahead back to half a year ahead: a time still ahead of the
/// run time, but another one, begins the day again.
#[test]
fn a_step_back_to_another_time_ahead_begins_the_day_again() {
    let mut times = vec![T0];
    times.extend(runs(T0 + YEAR, 600, DAY / 2));
    let back = T0 + YEAR / 2;
    times.extend(runs(back, 600, DAY));
    let cleaned = cleaned(&times);
    assert_eq!(cleaned.last(), Some(&(back + DAY)));
    assert!(cleaned[..cleaned.len() - 1].iter().all(|by| *by < back));
    // A step back of ten minutes or less is no other time.
    let mut times = vec![T0];
    times.extend(runs(T0 + YEAR, 600, DAY / 2));
    times.extend(runs(T0 + YEAR + DAY / 2 - 300, 600, DAY / 2));
    let cleaned = cleaned_with(&[], None, &times);
    assert_eq!(cleaned.last(), Some(times.last().unwrap()));
}

/// Five hours a year ahead, then the clock is put right: the run time went
/// on meanwhile, so the right time is within ten minutes of it at once.
#[test]
fn a_clock_put_right_after_hours_ahead_is_believed_at_once() {
    let mut times = vec![T0];
    times.extend(runs(T0 + YEAR, 600, 5 * 3600));
    times.extend([T0 + 5 * 3600 + 600, T0 + 5 * 3600 + 1200]);
    let cleaned = cleaned(&times);
    assert_eq!(
        cleaned[cleaned.len() - 3..],
        [T0 + 5 * 3600, T0 + 5 * 3600 + 600, T0 + 5 * 3600 + 1200]
    );
    // The same with a run every minute.
    let mut times = vec![T0];
    times.extend(runs(T0 + YEAR, 60, 5 * 3600));
    times.push(T0 + 5 * 3600 + 60);
    assert_eq!(
        cleaned_with(&[], None, &times).last(),
        Some(&(T0 + 5 * 3600 + 60))
    );
}

/// A day back is believed at once, since it removes nothing; the way
/// forward again is a time ahead like any other.
#[test]
fn a_clock_that_goes_back_and_forward_again() {
    let mut times = vec![T0, T0 - DAY, T0 - DAY + 600];
    times.extend(runs(T0 + 1200, 600, DAY));
    let cleaned = cleaned(&times);
    assert_eq!(cleaned[..4], [T0, T0 - DAY, T0 - DAY + 600, T0 - DAY + 600]);
    assert_eq!(cleaned[4], T0 - DAY + 1200);
    assert_eq!(cleaned.last(), Some(&(T0 + 1200 + DAY)));
}

/// Sixteen hours of runs every ten minutes, then eight hours of nothing:
/// the history never goes by a time more than two nights behind.
#[test]
fn a_host_that_is_off_every_night_lags_by_two_nights_at_the_most() {
    let times: Vec<i64> = (0..10)
        .flat_map(|day| runs(T0 + day * DAY, 600, 57000))
        .collect();
    let cleaned = cleaned(&times);
    let lag = times
        .iter()
        .zip(&cleaned)
        .map(|(at, by)| at - by)
        .max()
        .unwrap();
    assert_eq!(lag, 2 * (DAY - 57000));
    // And every other day the clock is believed again.
    for day in [2, 4, 6, 8] {
        let believed = times
            .iter()
            .zip(&cleaned)
            .filter(|(at, by)| at == by && (T0 + day * DAY..T0 + (day + 1) * DAY).contains(*at))
            .count();
        assert!(believed > 0, "day {day}");
    }
}

/// Every step is longer than ten minutes: each counts as one run of the
/// timer, and the 1440 runs of a day come after 15 days.
#[test]
fn a_collector_that_runs_only_every_quarter_hour_finds_its_way_back() {
    let times = runs(T0, 900, 1500 * 900);
    let cleaned = cleaned(&times);
    assert!(cleaned[1..1441].iter().all(|by| *by == T0));
    assert_eq!(cleaned[1441], times[1441]);
}

/// The journal says once where a stretch at a time ahead begins, and once
/// where it ends, the clock put right or a day of runs at the new time;
/// nothing between, and nothing of an ordinary run.
#[test]
fn the_journal_says_where_a_time_ahead_begins_and_where_it_ends() {
    let back = "The clock is back within ten minutes of the collector's run time; the metric history \
         is cleaned up by it again";
    assert_eq!(
        journal(&[T0, T0 + 60, T0 + YEAR, T0 + YEAR + 60, T0 + 180]),
        [
            (
                2,
                Level::Warn,
                "This collection run is dated 2027-10-28T10:00:00+00:00, more than ten minutes \
                 after the collector's own run time, 2026-10-28T10:01:00+00:00: the clock went \
                 ahead, or the collector paused. The metric history is cleaned up by the run \
                 time until the collector has run at this time for a day, or the clock comes \
                 back."
                    .to_owned()
            ),
            (4, Level::Info, back.to_owned()),
        ]
    );
    let mut times = vec![T0];
    times.extend(runs(T0 + 30 * DAY, 600, DAY));
    let said = journal(&times);
    assert_eq!(
        said.iter()
            .map(|(run, level, _)| (*run, *level))
            .collect::<Vec<_>>(),
        [(1, Level::Warn), (145, Level::Info)]
    );
    assert_eq!(
        said[1].2,
        "The collector has run for a day at its clock's new time; the metric history is \
         cleaned up by the clock again"
    );
    assert_eq!(journal(&runs(T0, 60, 3600)), []);
}

#[test]
fn a_database_of_the_release_before_goes_by_its_newest_snapshot() {
    assert_eq!(cleaned_with(&[], Some(T0), &[T0 + 60]), [T0 + 60]);
    assert_eq!(cleaned_with(&[], Some(T0), &[T0 + YEAR]), [T0]);
    // An upgrade that took an hour: the hour is not counted, the runs since are.
    assert_eq!(
        cleaned_with(&[], Some(T0), &[T0 + 3600, T0 + 3660, T0 + 3720]),
        [T0, T0 + 60, T0 + 120]
    );
    // A time that is none is no snapshot to go by.
    assert_eq!(cleaned_with(&[], Some(i64::MAX), &[T0]), [T0]);
    assert_eq!(cleaned_with(&[], Some(i64::MIN), &[T0]), [T0]);
}

#[test]
fn values_in_memory_that_are_no_time_count_for_nothing() {
    let after = |memory: &[(&str, &str)], times: &[i64]| cleaned_with(memory, Some(T0), times);
    let (max, min, start) = (i64::MAX.to_string(), i64::MIN.to_string(), T0.to_string());
    // A run time that does not read, or is none, gives way to the snapshot.
    for wrong in ["soon", "", max.as_str(), min.as_str()] {
        assert_eq!(
            after(&[(BELIEVED, wrong)], &[T0 + 60]),
            [T0 + 60],
            "{wrong:?}"
        );
    }
    // A run time far ahead is behind the run's own and gives way at once.
    assert_eq!(after(&[(BELIEVED, "253402207199")], &[T0 + 60]), [T0 + 60]);
    // A time ahead counted for longer than a day can be counts as none: the
    // day begins with the jump, and no single run ends it.
    let year = T0 + YEAR;
    for wrong in ["86400", "-1", "x", max.as_str()] {
        let memory = [(BELIEVED, start.as_str()), (AHEAD_FOR, wrong)];
        assert_eq!(
            after(&memory, &[year, year + 60]),
            [T0, T0 + 60],
            "{wrong:?}"
        );
    }
}
