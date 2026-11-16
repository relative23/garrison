//! The counts over a history that does not hold the week: a receiver that
//! stopped reporting, events lost within the week and a history without the
//! receiver's own records leave no summary in order, and what was counted
//! stays in view.

use rusqlite::Connection;
use serde_json::json;

use super::read::DAY;
use super::tests::{Event, event, observed, observed_from, of, rows};
use super::*;
use crate::testing::{Canned, Receiver, Remembered, config, table};

/// A week with mail on every day: ham, a milter that accepted, TLS both ways.
fn busy_week() -> Vec<Event> {
    let mut events = Vec::new();
    for day in 0..7 {
        let ago = day * DAY + 600;
        events.push(event("message-ingest.ham", ago, json!({"accountId": 1})));
        events.push(event("milter.action-accept", ago, json!({})));
        events.push(event("smtp.dkim-pass", ago, json!({})));
        events.push(event("delivery.start-tls", ago, json!({})));
    }
    events
}

#[test]
fn a_receiver_that_stopped_reporting_leaves_no_summary_in_order() {
    // The receiver last reported a day ago: what happened since is not in
    // the history, and a quiet day there is no quiet server.
    let quiet = Receiver {
        quiet_for: DAY,
        ..Receiver::default()
    };
    let observations = observed_from(&quiet, &busy_week(), None, &Remembered::default(), 0);
    assert!(observations.len() >= 4, "{observations:?}");
    for observation in &observations {
        assert_eq!(observation.state, State::Unknown, "{}", observation.id);
        assert_eq!(
            observation.findings,
            [
                "The event history is not current: the event receiver has not reported since \
              2026-10-28T12:00:00+00:00. What is counted here may be too little."
            ],
            "{}",
            observation.id
        );
    }
    // The numbers that were read stay in view.
    assert_eq!(rows(of(&observations, "flow.spam")).len(), 7);
    // A receiver that reports is taken at its word.
    let current = observed(&busy_week(), None, &Remembered::default(), 0);
    for observation in &current {
        assert_eq!(observation.state, State::Ok, "{}", observation.id);
        assert_eq!(
            observation.findings,
            Vec::<String>::new(),
            "{}",
            observation.id
        );
    }
}

#[test]
fn events_lost_within_the_week_leave_no_summary_in_order() {
    // The receiver was away for six hours three days ago, and for a day
    // nine days ago, which is before the week.
    let lost = |windows: &[(i64, i64)]| Receiver {
        quiet_for: 0,
        lost: windows.to_vec(),
    };
    let before = lost(&[(10 * DAY, 9 * DAY)]);
    for observation in observed_from(&before, &busy_week(), None, &Remembered::default(), 0) {
        assert_eq!(observation.state, State::Ok, "{}", observation.id);
    }
    let within = lost(&[(10 * DAY, 9 * DAY), (3 * DAY, 3 * DAY - 6 * 3600)]);
    let observations = observed_from(&within, &busy_week(), None, &Remembered::default(), 0);
    for observation in &observations {
        assert_eq!(observation.state, State::Unknown, "{}", observation.id);
        assert_eq!(
            observation.findings,
            [
                "The event history is not current: events between 2026-10-26T12:00:00+00:00 and \
              2026-10-26T18:00:00+00:00 were lost while the event receiver was away. What is \
              counted here may be too little."
            ],
            "{}",
            observation.id
        );
    }
}

#[test]
fn a_milter_that_was_not_reached_stays_a_warning_over_an_incomplete_history() {
    let mut events = busy_week();
    events.push(event("milter.timeout", 3600, json!({})));
    let quiet = Receiver {
        quiet_for: DAY,
        ..Receiver::default()
    };
    let observations = observed_from(&quiet, &events, None, &Remembered::default(), 0);
    let milter = of(&observations, "flow.milter");
    // What was seen is not unsaid by what may be missing.
    assert_eq!(milter.state, State::Warning);
    assert_eq!(milter.findings.len(), 2, "{:?}", milter.findings);
    assert!(milter.findings[0].contains("could not be reached 1 times"));
    assert!(milter.findings[1].contains("has not reported since"));
}

#[test]
fn a_history_without_the_receivers_own_records_counts_nothing_as_in_order() {
    // An events table and nothing else: no receiver made this database.
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let path = config.database(garrison_core::config::Database::Events);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TABLE events(seq INTEGER PRIMARY KEY, created_at INTEGER, type TEXT, span_id TEXT, fields TEXT)",
        )
        .unwrap();
    let runner = Canned(String::new());
    let context = crate::testing::context(&config, &runner);
    let provider = Flow::new(&table("type = \"mail-flow\"")).unwrap();
    for observation in provider.collect(&context).unwrap().observations {
        assert_eq!(observation.state, State::Unknown, "{}", observation.id);
        assert!(
            observation.findings[0].starts_with("The event history is not current: what the event receiver recorded about itself cannot be read"),
            "{:?}",
            observation.findings
        );
    }
}
