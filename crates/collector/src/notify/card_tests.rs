//! The channels' card is the state now: a channel taken out of the
//! configuration is no longer judged by the last notification, one named
//! since is not known to work, and a notification that a channel did not
//! take is named with its time.

use garrison_testing::http::{answer, serve};

use super::tests::observed;
use super::*;
use crate::testing::{Remembered, now};

/// A topic and a webhook at stand-ins.
fn both(topic: &str, hook: &str) -> Channels {
    Channels {
        host: "garrison.example.org".to_owned(),
        ntfy: Some(Address {
            url: format!("{topic}/mailserver"),
            ..Address::default()
        }),
        webhook: Some(Address {
            url: format!("{hook}/hooks/garrison"),
            ..Address::default()
        }),
        mail: None,
    }
}

/// The card after a run of `observations` on `channels`.
fn card_of(channels: &Channels, memory: &Remembered, observations: &[Observation]) -> Observation {
    after_run(channels, observations, memory, now(), Deadline::NONE).unwrap()
}

const AT: &str = "2026-10-29T12:00:00+00:00";

/// The webhook did not take the last notification; once it is taken out of
/// the configuration the card is in order, as the topic took it, and what
/// a release before this one reads says so too.
#[test]
fn a_channel_taken_out_is_no_longer_judged_by_the_last_notification() {
    let topic = serve(vec![answer(200, "{}")]);
    let hook = serve(vec![answer(500, "broken")]);
    let channels = both(&topic.url, &hook.url);
    let memory = Remembered::default();
    let failing = [observed("backup", State::Failed, "The last run failed.")];
    card_of(&channels, &memory, &failing);
    let told = card_of(&channels, &memory, &failing);
    let without = Channels {
        webhook: None,
        ..channels
    };
    let after = card_of(&without, &memory, &failing);
    assert_eq!((after.state, after.findings), (State::Ok, Vec::new()));
    assert_eq!(memory.recall("notify.problem").as_deref(), Some(""));
    // While the webhook was named, the card said which notification it did
    // not take, and when.
    assert_eq!(told.state, State::Failed);
    assert_eq!(
        told.findings,
        [format!(
            "The notification of {AT} did not go out: webhook: it answered 500."
        )]
    );
    topic.requests();
    hook.requests();
}

/// With every channel taken out, what the last notification did is
/// forgotten: the webhook named again has carried no message since, and
/// is not known to work, not failed.
#[test]
fn a_channel_named_again_is_not_judged_by_what_one_of_its_name_did_before() {
    let hook = serve(vec![answer(500, "broken")]);
    let channels = Channels {
        ntfy: None,
        ..both("http://127.0.0.1:9", &hook.url)
    };
    let memory = Remembered::default();
    let failing = [observed("backup", State::Failed, "The last run failed.")];
    card_of(&channels, &memory, &failing);
    assert_eq!(card_of(&channels, &memory, &failing).state, State::Failed);
    assert_eq!(
        after_run(
            &Channels::default(),
            &failing,
            &memory,
            now(),
            Deadline::NONE
        ),
        None
    );
    // Nothing to tell in this run: no message goes out on it.
    let again = card_of(&channels, &memory, &[]);
    assert_eq!(again.state, State::Unknown);
    assert!(
        again.findings[0].starts_with("No message has gone out on these channels yet"),
        "{:?}",
        again.findings
    );
    hook.requests();
}

/// The topic took the last notification; a webhook named since has carried
/// none, so whether one would arrive there is not known.
#[test]
fn a_channel_named_since_the_last_notification_is_not_known_to_work() {
    let topic = serve(vec![answer(200, "{}")]);
    let channels = both(&topic.url, "http://127.0.0.1:9");
    let only_topic = Channels {
        webhook: None,
        ..channels.clone()
    };
    let memory = Remembered::default();
    let failing = [observed("backup", State::Failed, "The last run failed.")];
    card_of(&only_topic, &memory, &failing);
    assert_eq!(card_of(&only_topic, &memory, &failing).state, State::Ok);
    let added = card_of(&channels, &memory, &failing);
    assert_eq!(added.state, State::Unknown);
    assert_eq!(
        added.findings,
        [format!(
            "No message has gone out on webhook at {} yet, so it is not known whether one would \
             arrive there. `garrison notify-test` sends a test message; this check is in order \
             once a notification has gone out on each.",
            "127.0.0.1:9"
        )]
    );
    topic.requests();
}

/// A release before this one kept the failures on one line and no time:
/// each counts for the channel of its kind, as long as one is configured,
/// but not with its words, which may name all of the channel's address.
#[test]
fn what_an_earlier_release_kept_counts_for_the_channels_of_its_kinds() {
    let memory = Remembered::default();
    memory.keep(
        "notify.problem",
        "webhook: the certificate is not valid for this name; it is for localhost; mail: the \
         mail server did not sign in (535)",
    );
    memory.keep("notify.sent", "1793270000");
    let channels = both("http://127.0.0.1:9", "http://127.0.0.1:9");
    let card = card_of(&channels, &memory, &[]);
    assert_eq!(card.state, State::Failed);
    assert_eq!(
        card.findings,
        [
            "The last notification did not go out on webhook at 127.0.0.1:9. `garrison \
             notify-test` shows whether one goes out now."
        ]
    );
    // Its line for a release before this one names what still counts.
    assert_eq!(
        memory.recall("notify.problem").as_deref(),
        Some("webhook: it did not take it")
    );
    // Without the webhook, the topic took it.
    let topic = Channels {
        webhook: None,
        ..channels
    };
    assert_eq!(card_of(&topic, &memory, &[]).state, State::Ok);
}
