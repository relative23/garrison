//! The time a run has for its checks: once it is up, the resolver is asked
//! nothing more, and both cards say that not everything was asked.

use std::time::{Duration, Instant};

use garrison_core::observations::{Observation, State};

use super::tests::{Zone, address, mail_host, pointer, provider, rows};
use super::*;
use crate::context::Deadline;
use crate::providers::dns::tests::resolver as stand_in;
use crate::testing::{Canned, Remembered, assert_dated, config};

/// The two observations of `provider` with `deadline`, and how long they took.
fn observed(
    provider: &Reputation,
    memory: &Remembered,
    deadline: Deadline,
) -> (Observation, Observation, Duration) {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = Context {
        deadline,
        memory,
        ..crate::testing::context(&config, &runner)
    };
    let began = Instant::now();
    let mut observations = provider.collect(&context).unwrap().observations;
    let took = began.elapsed();
    let reverse = observations.remove(1);
    (observations.remove(0), reverse, took)
}

const RUN_OVER: &str =
    "Not every address or list was asked: the collection run's time was used up.";

#[test]
fn once_the_runs_time_is_up_the_resolver_is_asked_nothing_more() {
    // The second list's question goes unanswered: three seconds pass, and
    // with them the run's time.
    let (resolver, handle) = stand_in(mail_host(), Some("5.113.0.203.bl.spamcop.net"), 5);
    let memory = Remembered::default();
    let (blocklists, reverse, took) = observed(
        &provider(resolver, ""),
        &memory,
        Deadline::within(Duration::from_secs(1)),
    );
    // A, its reverse name and that name's A, then two lists; nothing after.
    assert_eq!(handle.join().unwrap().len(), 5);
    assert!(took < Duration::from_secs(5), "{took:?}");
    let rows = rows(&blocklists);
    assert_eq!(rows[0], "203.0.113.5 | zen.spamhaus.org | not listed");
    assert!(
        rows[1].starts_with("203.0.113.5 | bl.spamcop.net | no verdict: the resolver "),
        "{}",
        rows[1]
    );
    let not_asked = "no verdict: not asked: the collection run's time was used up";
    assert_eq!(
        rows[2..],
        [
            format!("203.0.113.5 | psbl.surriel.com | {not_asked}"),
            format!("203.0.113.5 | bl.mailspike.net | {not_asked}"),
        ]
    );
    // The IPv6 address was never looked up. What was asked is in order, so
    // the cards are Partial, never Ok, and say why.
    assert_eq!(
        (blocklists.state, reverse.state),
        (State::Partial, State::Partial)
    );
    assert_eq!(blocklists.findings, [RUN_OVER]);
    assert_eq!(reverse.findings, [RUN_OVER]);
    // Such a reading is asked again after an hour, not after six.
    assert_dated(&blocklists, 0, AGAIN);
    assert_dated(&reverse, 0, AGAIN);
}

#[test]
fn a_run_without_time_asks_nothing_and_says_so() {
    let mut zone = Zone::new();
    address(&mut zone, "mail.example.test", "203.0.113.5");
    pointer(&mut zone, "203.0.113.5", "mail.example.test");
    // The stand-in takes no question at all.
    let (resolver, handle) = stand_in(zone, None, 0);
    let (blocklists, reverse, _) = observed(
        &provider(resolver, ""),
        &Remembered::default(),
        Deadline::within(Duration::ZERO),
    );
    assert_eq!(handle.join().unwrap(), Vec::<u16>::new());
    assert_eq!(
        (blocklists.state, reverse.state),
        (State::Unknown, State::Unknown)
    );
    // Not "no list gave a verdict" and not "the mail hosts have no
    // address": nothing was asked.
    assert_eq!(blocklists.findings, [RUN_OVER]);
    assert_eq!(reverse.findings, [RUN_OVER]);
}
