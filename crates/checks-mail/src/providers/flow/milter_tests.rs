//! The card "Milter verdicts": what the milters answered by day, and what
//! of it is a warning.

use garrison_core::modules::ModuleId;
use garrison_core::observations::State;
use serde_json::json;

use super::read::DAY;
use super::tests::{Event, event, observed, of, rows};
use crate::testing::Remembered;

/// A milter whose answer is larger than Stalwart reads gave no verdict for
/// that mail, which Stalwart then defers or lets pass by the milter's
/// setting: a warning that says so, and a count of its own by day.
#[test]
fn a_milter_whose_answer_is_larger_than_stalwart_reads_is_a_warning() {
    let events = [
        event("milter.action-accept", 60, json!({})),
        event("milter.frame-too-large", 61, json!({"details": 67_108_864})),
        event("milter.frame-too-large", 62, json!({"details": 67_108_864})),
    ];
    let observations = observed(&events, None, &Remembered::default(), 0);
    let milter = of(&observations, "flow.milter");
    assert_eq!(milter.state, State::Warning);
    assert_eq!(
        milter.findings[0],
        "A milter answered 2 times since yesterday with more than Stalwart reads of an answer, \
         so it gave no verdict for that mail. What Stalwart does with mail then, defer it or \
         let it pass unscanned, is the milter's setting there."
    );
    assert_eq!(rows(milter)[0], "2026-10-29 | 1 | 0 | 0 | 0 | 0 | 0 | 2");
}

#[test]
fn a_milter_that_could_not_be_reached_is_a_warning_and_a_host_without_one_has_no_card() {
    let events = [
        event("milter.action-accept", 60, json!({})),
        event("milter.action-accept", 61, json!({})),
        event("milter.action-reject", 62, json!({})),
        event("milter.timeout", 63, json!({})),
        event("milter.action-connection-failure", DAY + 60, json!({})),
        event("milter.action-temp-fail", 3 * DAY, json!({})),
    ];
    let observations = observed(&events, None, &Remembered::default(), 0);
    let milter = of(&observations, "flow.milter");
    assert_eq!(
        (milter.state, milter.modules.clone()),
        (State::Warning, [ModuleId::Antivirus].into())
    );
    assert!(
        milter.findings[0].starts_with("The milter could not be reached 2 times since yesterday."),
        "{:?}",
        milter.findings
    );
    let by_day = rows(milter);
    assert_eq!(by_day[0], "2026-10-29 | 2 | 1 | 0 | 0 | 0 | 1 | 0");
    assert_eq!(by_day[3], "2026-10-26 | 0 | 0 | 0 | 1 | 0 | 0 | 0");
    // A quiet week: in order. No milter event at all: nothing to show.
    let quiet = observed(&events[..3], None, &Remembered::default(), 0);
    assert_eq!(of(&quiet, "flow.milter").state, State::Ok);
    let none = observed(&[], None, &Remembered::default(), 0);
    assert!(
        none.iter()
            .all(|observation| observation.id != "flow.milter")
    );
    let ids: Vec<&str> = none
        .iter()
        .map(|observation| observation.id.as_str())
        .collect();
    assert_eq!(ids, ["flow.authentication", "flow.spam", "flow.tls"]);
}

#[test]
fn a_milter_that_deferred_everything_since_yesterday_is_a_warning_and_own_replies_count_apart() {
    // A scanner that cannot scan defers each message: nothing was judged.
    let deferred: Vec<Event> = (0..3)
        .map(|second| event("milter.action-temp-fail", 60 + second, json!({})))
        .collect();
    let milter = |events: &[Event]| {
        of(
            &observed(events, None, &Remembered::default(), 0),
            "flow.milter",
        )
        .clone()
    };
    let card = milter(&deferred);
    assert_eq!(
        (card.state, card.findings),
        (
            State::Warning,
            vec![
                "Every message shown to the milters since yesterday was deferred (3 in all), so \
                 their senders were asked to try again later. A scanner that cannot scan answers \
                 so, as clamav-milter does while clamd is down."
                    .to_owned()
            ]
        )
    );
    // One it passed is a verdict.
    let mut passed = deferred.clone();
    passed.push(event("milter.action-accept", 120, json!({})));
    assert_eq!(milter(&passed).state, State::Ok);
    // A reply in the milter's own words may
    // have refused: it is counted apart, and is no deferral.
    let mut replied = deferred.clone();
    replied.push(event("milter.action-reply-code", 120, json!({})));
    replied.push(event("milter.action-reply-code", 121, json!({})));
    let card = milter(&replied);
    assert_eq!(card.state, State::Ok, "{:?}", card.findings);
    assert_eq!(rows(&card)[0], "2026-10-29 | 0 | 0 | 0 | 3 | 2 | 0 | 0");
    // Deferrals before yesterday are history.
    let older: Vec<Event> = (0..3)
        .map(|second| event("milter.action-temp-fail", 3 * DAY + second, json!({})))
        .collect();
    assert_eq!(milter(&older).state, State::Ok);
}

#[test]
fn every_message_one_of_two_milters_deferred_is_a_warning() {
    // One milter passes each message and clamav-milter, its
    // clamd down, defers it: Stalwart records both answers in the message's
    // session (measured with Stalwart 1.2.0), and every message was deferred.
    let mut events: Vec<Event> = Vec::new();
    for (ago, span) in [(60, "1"), (61, "2"), (62, "3")] {
        events.push(("milter.action-accept", ago, Some(span), json!({})));
        events.push(("milter.action-temp-fail", ago, Some(span), json!({})));
    }
    let milter = |events: &[Event]| {
        of(
            &observed(events, None, &Remembered::default(), 0),
            "flow.milter",
        )
        .clone()
    };
    let card = milter(&events);
    assert_eq!(
        (card.state, card.findings),
        (
            State::Warning,
            vec![
                "Every message shown to the milters since yesterday was deferred (3 in all), so \
                 their senders were asked to try again later. A scanner that cannot scan answers \
                 so, as clamav-milter does while clamd is down."
                    .to_owned()
            ]
        )
    );
    // One message that both passed is a verdict.
    events.push(("milter.action-accept", 120, Some("4"), json!({})));
    events.push(("milter.action-accept", 120, Some("4"), json!({})));
    assert_eq!(milter(&events).state, State::Ok);
}
