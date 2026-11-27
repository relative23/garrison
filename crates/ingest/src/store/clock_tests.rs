//! The receiver's history under a clock that goes ahead and comes back.

use log::Level;
use serde_json::json;

use super::tests::{event, read, store};
use super::*;

const DAY: i64 = 86_400;
/// The time the host's clock should read in these tests.
const NOW: i64 = 1_793_000_000;
/// Between two heartbeats of the receiver.
const BEAT: i64 = 30;

fn dated(seq: u64, second: i64) -> Value {
    let at = time::isoformat(time::Timestamp::from_second(second).unwrap());
    event(seq, "auth.failed", &at, &json!({}))
}

fn count(directory: &Path) -> i64 {
    read(directory)
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap()
}

/// A receiver that has run for an hour until [`NOW`] and took an event in
/// each of its minutes; the history keeps thirty days.
fn an_hour(directory: &Path) -> EventStore {
    let events = store(directory, 1000);
    events.start(NOW - 3600).unwrap();
    for minute in 0..60 {
        let at = NOW - 3600 + minute * 60;
        events.heartbeat(at).unwrap();
        let seq = u64::try_from(minute).unwrap();
        events.ingest(&[dated(seq, at)], at).unwrap();
        events.heartbeat(at + BEAT).unwrap();
    }
    events
}

/// The receiver runs from `from` for `seconds`, a heartbeat every `step`
/// and a clean-up with each.
fn runs(events: &EventStore, from: i64, seconds: i64, step: i64) {
    let mut at = from;
    while at < from + seconds {
        at += step;
        events.heartbeat(at).unwrap();
        events.enforce_limits(at).unwrap();
    }
}

#[test]
fn a_clean_up_while_the_clock_is_a_month_ahead_removes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let events = an_hour(directory.path());
    // The clock jumps 31 days ahead, and the receiver runs an hour there.
    runs(&events, NOW + 31 * DAY, 3600, BEAT);
    assert_eq!(count(directory.path()), 60, "while the clock is ahead");
    // The clock is put right.
    runs(&events, NOW + 3600, 3600, BEAT);
    assert_eq!(count(directory.path()), 60, "after the clock came back");
}

#[test]
fn a_start_with_the_clock_a_month_ahead_removes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    drop(an_hour(directory.path()));
    // The host starts with its clock ahead, before its time server answers.
    let events = store(directory.path(), 1000);
    events.start(NOW + 31 * DAY).unwrap();
    runs(&events, NOW + 31 * DAY, 600, BEAT);
    assert_eq!(count(directory.path()), 60);
}

#[test]
fn a_clock_two_days_ahead_takes_no_event_two_days_early() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    // An event of 29 days ago, taken then; the receiver ran until now.
    events.start(NOW - 29 * DAY).unwrap();
    events
        .ingest(&[dated(1, NOW - 29 * DAY)], NOW - 29 * DAY)
        .unwrap();
    runs(&events, NOW - 29 * DAY, 29 * DAY, 600);
    assert_eq!(count(directory.path()), 1);
    runs(&events, NOW + 2 * DAY, 3600, BEAT);
    assert_eq!(count(directory.path()), 1, "it has a day left");
}

#[test]
fn time_that_passes_under_the_heartbeat_still_ends_what_the_history_keeps() {
    let directory = tempfile::tempdir().unwrap();
    let events = an_hour(directory.path());
    // Thirty days less the last minute's event: all sixty are still kept.
    runs(&events, NOW, 30 * DAY - 3600, 600);
    assert_eq!(count(directory.path()), 60);
    // Half an hour on, the events of the hour's first half are over.
    runs(&events, NOW + 30 * DAY - 3600, 1800, 600);
    assert_eq!(count(directory.path()), 30);
}

#[test]
fn a_clock_that_stays_ahead_is_believed_after_a_day() {
    let directory = tempfile::tempdir().unwrap();
    let events = an_hour(directory.path());
    // No jump: the host was off for 31 days, and its clock is right.
    let back = NOW + 31 * DAY;
    events.start(back).unwrap();
    runs(&events, back, DAY - 600, 600);
    assert_eq!(count(directory.path()), 60, "ten minutes before the day");
    runs(&events, back + DAY - 600, 600, 600);
    assert_eq!(count(directory.path()), 0, "the day is over");
}

#[test]
fn an_event_written_before_the_clock_went_ahead_is_taken_after_it() {
    let directory = tempfile::tempdir().unwrap();
    let events = an_hour(directory.path());
    // Stalwart wrote it at the right time and sends it a minute later,
    // when the clock has jumped 31 days ahead.
    let ahead = NOW + 31 * DAY;
    events.heartbeat(ahead).unwrap();
    assert_eq!(
        events.ingest(&[dated(100, NOW + 10)], ahead + 60).unwrap(),
        Outcome {
            stored: 1,
            ..Outcome::default()
        }
    );
    assert_eq!(events.health().failing_since, None);
}

#[test]
fn the_journal_says_once_when_the_clock_goes_ahead_and_when_it_is_back() {
    let directory = tempfile::tempdir().unwrap();
    let events = an_hour(directory.path());
    let state = events.state();
    let look = |now: i64, previous: i64| clock::looked(&state.db, now, Some(previous)).unwrap();
    let ahead = NOW + 31 * DAY;
    assert_eq!(look(NOW + 2 * BEAT, NOW + BEAT), None);
    assert_eq!(
        look(ahead, NOW + 2 * BEAT),
        Some((
            Level::Warn,
            "The receiver's clock reads 2026-11-26T07:33:20+00:00, more than ten minutes after \
             its own run time, 2026-10-26T07:34:20+00:00: the clock went ahead, or the receiver \
             paused. Old events are removed by the run time until the receiver has run at this \
             time for a day, or the clock comes back."
                .to_owned()
        ))
    );
    assert_eq!(look(ahead + BEAT, ahead), None);
    assert_eq!(
        look(NOW + 4 * BEAT, ahead + BEAT),
        Some((
            Level::Info,
            "The clock is back within ten minutes of the receiver's run time; old events are \
             removed by it again"
                .to_owned()
        ))
    );
    assert_eq!(look(NOW + 5 * BEAT, NOW + 4 * BEAT), None);
}
