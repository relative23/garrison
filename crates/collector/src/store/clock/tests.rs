use super::*;
use crate::store::StatusStore;

/// 2026-10-28T10:00:00Z.
const T0: i64 = 1_793_181_600;
const DAY: i64 = 86400;
const YEAR: i64 = 365 * DAY;

/// What each run at `times` cleans up by, each run after the one before.
/// `previous` is when the run before the first one collected.
fn cleaned_after(previous: Option<i64>, times: &[i64]) -> Vec<i64> {
    let directory = tempfile::tempdir().unwrap();
    let mut store = StatusStore::open(&directory.path().join("status.sqlite"), 90).unwrap();
    let mut previous = previous;
    times
        .iter()
        .map(|&now| {
            let transaction = store.db.transaction().unwrap();
            let by = cleaned_by(&transaction, now, previous).unwrap();
            transaction.commit().unwrap();
            previous = Some(now);
            by
        })
        .collect()
}

fn cleaned(times: &[i64]) -> Vec<i64> {
    cleaned_after(None, times)
}

/// Runs every ten minutes from `from` for `span` seconds, `from` itself first.
fn every_ten_minutes(from: i64, span: i64) -> Vec<i64> {
    (0..=span / 600).map(|run| from + run * 600).collect()
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

#[test]
fn a_run_further_ahead_cleans_up_by_the_last_one_believed() {
    assert_eq!(cleaned(&[T0, T0 + 601]), [T0, T0]);
    assert_eq!(
        cleaned(&[T0, T0 + YEAR, T0 + YEAR + 60, T0 + YEAR + 120]),
        [T0, T0, T0, T0]
    );
}

#[test]
fn a_clock_that_kept_its_new_time_for_a_day_is_believed() {
    // A downtime of a month, or a clock that nobody put right.
    let mut times = vec![T0];
    times.extend(every_ten_minutes(T0 + 30 * DAY, DAY));
    let cleaned = cleaned(&times);
    let (waited, last) = cleaned.split_at(cleaned.len() - 1);
    assert!(waited.iter().all(|by| *by == T0), "{waited:?}");
    assert_eq!(last, [T0 + 31 * DAY]);
    // From then on the runs are believed one by one.
    times.push(T0 + 31 * DAY + 60);
    assert_eq!(
        cleaned_after(None, &times).last(),
        Some(&(T0 + 31 * DAY + 60))
    );
}

#[test]
fn another_jump_while_waiting_begins_the_day_again() {
    let mut times = vec![T0];
    times.extend(every_ten_minutes(T0 + YEAR, DAY / 2));
    // Another year ahead after half a day: the day counts from there.
    let again = T0 + 2 * YEAR + DAY / 2;
    times.extend(every_ten_minutes(again, DAY));
    let cleaned = cleaned(&times);
    assert_eq!(cleaned.last(), Some(&(again + DAY)));
    assert!(cleaned[..cleaned.len() - 1].iter().all(|by| *by == T0));
    // A jump back that is still too far ahead begins it again, too.
    let mut times = vec![T0];
    times.extend(every_ten_minutes(T0 + YEAR, DAY / 2));
    let back = T0 + DAY / 2;
    times.extend(every_ten_minutes(back, DAY));
    let cleaned = cleaned_after(None, &times);
    assert_eq!(cleaned.last(), Some(&(back + DAY)));
    assert!(cleaned[..cleaned.len() - 1].iter().all(|by| *by == T0));
}

#[test]
fn a_clock_that_comes_back_is_believed_at_once() {
    // Two runs a year ahead, then the clock is right again.
    assert_eq!(
        cleaned(&[T0, T0 + YEAR, T0 + YEAR + 60, T0 + 180, T0 + 240]),
        [T0, T0, T0, T0 + 180, T0 + 240]
    );
    // A run too far ahead after that begins a wait of its own.
    let mut times = vec![T0, T0 + YEAR, T0 + 180];
    times.extend(every_ten_minutes(T0 + 2 * DAY, DAY));
    let cleaned = cleaned(&times);
    assert_eq!(
        cleaned[2..cleaned.len() - 1].iter().max(),
        Some(&(T0 + 180))
    );
    assert_eq!(cleaned.last(), Some(&(T0 + 3 * DAY)));
}

#[test]
fn a_database_of_the_release_before_goes_by_its_newest_snapshot() {
    assert_eq!(cleaned_after(Some(T0), &[T0 + 60]), [T0 + 60]);
    assert_eq!(cleaned_after(Some(T0), &[T0 + YEAR]), [T0]);
    // A time that is none is no snapshot to go by.
    assert_eq!(cleaned_after(Some(i64::MAX), &[T0]), [T0]);
}
