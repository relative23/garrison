//! What is told when: a check that changes between failing and warning,
//! one that is missing from a run, one that stays away, and channels that
//! have not carried a message yet.

use garrison_testing::http::{answer, serve};
use serde_json::json;

use super::tests::{body, observed, run};
use super::*;
use crate::testing::Remembered;

/// The titles of the messages a stand-in for ntfy was sent.
fn titles(requests: &[String]) -> Vec<String> {
    requests
        .iter()
        .map(|request| body(request)["title"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_return_to_order_is_told_whatever_the_check_was_last() {
    let server = serve(vec![answer(200, "{}"), answer(200, "{}")]);
    let url = format!("{}/topic", server.url);
    let memory = Remembered::default();
    // Told as failed, then one run of a warning, then in order.
    for state in [State::Failed, State::Failed, State::Warning, State::Ok] {
        run(&url, &memory, &[observed("disk", state, "Nearly full.")]);
    }
    assert_eq!(
        titles(&server.requests()),
        [
            "Garrison on garrison.example.org: 1 failed",
            "Garrison on garrison.example.org: 1 in order again"
        ]
    );
}

#[test]
fn a_check_that_fails_and_warns_by_turns_is_told_and_only_once() {
    let server = serve(vec![answer(200, "{}"), answer(200, "{}")]);
    let url = format!("{}/topic", server.url);
    let memory = Remembered::default();
    // Never the same state twice in a row, and never in order.
    for state in [State::Warning, State::Failed, State::Warning, State::Failed] {
        run(&url, &memory, &[observed("queue", state, "")]);
    }
    let last = run(&url, &memory, &[observed("queue", State::Ok, "")]);
    // In the second run it was not in order twice, and it failed just then:
    // told there, once, and its return after it.
    assert_eq!(
        titles(&server.requests()),
        [
            "Garrison on garrison.example.org: 1 failed",
            "Garrison on garrison.example.org: 1 in order again"
        ]
    );
    assert_eq!(last.fields[1].value, json!(0));
}

#[test]
fn a_check_that_is_missing_from_a_run_keeps_its_place_and_its_return() {
    let server = serve(vec![answer(200, "{}"), answer(200, "{}")]);
    let url = format!("{}/topic", server.url);
    let memory = Remembered::default();
    let failing = [observed("stalwart.queue", State::Failed, "Stuck.")];
    run(&url, &memory, &failing);
    run(&url, &memory, &failing);
    // Stalwart's API is away: only another observation is left of the run.
    let away = [observed("stalwart.api", State::Unknown, "")];
    for _ in 0..3 {
        let during = run(&url, &memory, &away);
        assert_eq!(during.fields[1].value, json!(1), "still not in order");
    }
    run(&url, &memory, &[observed("stalwart.queue", State::Ok, "")]);
    assert_eq!(
        titles(&server.requests()),
        [
            "Garrison on garrison.example.org: 1 failed",
            "Garrison on garrison.example.org: 1 in order again"
        ]
    );
}

#[test]
fn a_check_that_stays_away_is_forgotten_after_a_day_of_runs() {
    let entry = |missing| Open {
        state: "failed".to_owned(),
        title: "Check gone".to_owned(),
        detail: String::new(),
        runs: 5,
        failed_runs: 5,
        told: true,
        told_as: Some("failed".to_owned()),
        due: None,
        missing,
    };
    let open = Opens::from([("gone".to_owned(), entry(FORGOTTEN - 1))]);
    let (next, news) = compare(&open, &[]);
    assert_eq!(next["gone"].missing, FORGOTTEN);
    assert!(news.is_empty());
    // One run more and it is no longer among the checks that are not in
    // order: a check that was taken out of the configuration says nothing.
    let (next, news) = compare(&next, &[]);
    assert!(next.is_empty() && news.is_empty());
    // What the status database kept before these fields existed still reads.
    let kept: Opens = serde_json::from_str(
        r#"{"disk": {"state": "warning", "title": "Disk", "detail": "", "runs": 4, "told": true}}"#,
    )
    .unwrap();
    assert_eq!(kept["disk"].severity_told(), Some("warning"));
    let (_, news) = compare(&kept, &[observed("disk", State::Ok, "")]);
    assert_eq!(news.recovered, ["Disk"]);
}

#[test]
fn channels_that_never_carried_a_message_are_not_known_to_work() {
    let server = serve(vec![answer(200, "{}")]);
    let url = format!("{}/topic", server.url);
    let memory = Remembered::default();
    // Nothing to tell, so nothing was sent: that the channels are named
    // does not show that a message would arrive.
    let before = run(&url, &memory, &[observed("disk", State::Ok, "")]);
    assert_eq!(before.state, State::Unknown);
    assert_eq!(
        before.findings,
        [
            "No message has gone out on these channels yet, so it is not known whether one \
          would arrive. `garrison notify-test` sends a test message; this check is in order \
          once the first notification has gone out."
        ]
    );
    let failing = [observed("disk", State::Failed, "Full.")];
    run(&url, &memory, &failing);
    // The first message went out: the channel is known to work.
    let after = run(&url, &memory, &failing);
    assert_eq!((after.state, after.findings.len()), (State::Ok, 0));
    assert_eq!(server.requests().len(), 1);
}
