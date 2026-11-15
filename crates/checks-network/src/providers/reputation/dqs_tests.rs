//! A zone of Spamhaus' Data Query Service holds the subscriber's key as its
//! first label, `KEY.zen.dq.spamhaus.net`. It is asked as configured, and
//! named without the key on the card, in its findings and in what the
//! status database keeps of the reading.

use garrison_core::observations::{Observation, State};
use garrison_core::time;
use serde_json::json;

use super::tests::{V4, listed, mail_host, provider, rows};
use super::*;
use crate::context::DqsKey;
use crate::providers::dns::stand_in::resolver as stand_in;
use crate::testing::{Canned, Remembered, config, now};

const KEY: &str = "abcdefghijklmnopqrstuvwxyz";

fn zone() -> String {
    format!("{KEY}.zen.dq.spamhaus.net")
}

/// The blocklists card of a run `later` seconds after the tests' clock.
fn blocklists(provider: &Reputation, memory: &Remembered, later: i64) -> Observation {
    keyed(provider, memory, later, DqsKey::Unset)
}

/// The same, where the collector read `key` for the run.
fn keyed(provider: &Reputation, memory: &Remembered, later: i64, key: DqsKey) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = Context {
        now: time::Timestamp::from_second(now().as_second() + later).unwrap(),
        memory,
        dqs_key: key,
        ..crate::testing::context(&config, &runner)
    };
    provider.collect(&context).unwrap().observations.remove(0)
}

/// Everything the status database would keep.
fn kept(memory: &Remembered) -> String {
    memory
        .0
        .borrow()
        .values()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_key_of_a_dqs_zone_is_asked_but_neither_shown_nor_kept() {
    let mut answers = mail_host();
    listed(&mut answers, V4, &zone(), [127, 0, 0, 2]);
    let (resolver, _) = stand_in(answers, None, 64);
    let lists = format!("lists = [\"{}\"]\nlists_ipv6 = []", zone());
    let memory = Remembered::default();
    let card = blocklists(&provider(resolver, &lists), &memory, 0);
    // Only the zone as configured answers so: it was asked with its key.
    assert_eq!(card.state, State::Failed);
    assert_eq!(
        card.findings,
        ["203.0.113.5 is listed on ….zen.dq.spamhaus.net (127.0.0.2)."]
    );
    assert_eq!(
        rows(&card),
        ["203.0.113.5 | ….zen.dq.spamhaus.net | listed (127.0.0.2)"]
    );
    let shown = serde_json::to_string(&card).unwrap();
    assert!(!shown.contains(KEY), "{shown}");
    assert!(!kept(&memory).contains(KEY), "{}", kept(&memory));
    assert!(kept(&memory).contains("….zen.dq.spamhaus.net"));
}

/// An error may repeat the name a question asked: the key leaves it too.
/// A label longer than DNS allows makes no question at all. The options
/// refuse such a zone (`names_tests.rs`); a reading names it without its key
/// all the same.
#[test]
fn an_error_that_repeats_the_question_names_the_zone_without_its_key() {
    let long = "k".repeat(64);
    let (resolver, _) = stand_in(mail_host(), None, 64);
    let provider = Reputation {
        lists: vec![format!("{long}.zen.dq.spamhaus.net")],
        ..provider(resolver, "lists_ipv6 = []")
    };
    let memory = Remembered::default();
    let card = blocklists(&provider, &memory, 0);
    assert_eq!(
        rows(&card),
        ["203.0.113.5 | ….zen.dq.spamhaus.net | no verdict: \
          5.113.0.203.….zen.dq.spamhaus.net is no DNS name"]
    );
    let shown = serde_json::to_string(&card).unwrap();
    assert!(!shown.contains(&long), "{shown}");
    assert!(!kept(&memory).contains(&long), "{}", kept(&memory));
}

/// A reading that an earlier release kept names the zone with its key: the
/// next run asks again at once, keeps the new reading without it, and the
/// card shows none.
#[test]
fn a_reading_kept_with_the_key_is_asked_again_at_once() {
    let (resolver, _) = stand_in(mail_host(), None, 64);
    let lists = format!("lists = [\"{}\"]\nlists_ipv6 = []", zone());
    let earlier = json!({
        "at": now().as_second() - 3600,
        "hosts": ["mail.example.test"],
        "addresses": [{"host": "mail.example.test", "address": V4,
                       "pointer": "mail.example.test", "confirmed": true,
                       "lists": [[zone(), "Clear"]]}],
        "problem": null,
    });
    let memory = Remembered::default();
    memory
        .0
        .borrow_mut()
        .insert("reputation.read".to_owned(), earlier.to_string());
    let card = blocklists(&provider(resolver, &lists), &memory, 0);
    assert_eq!(
        rows(&card),
        ["203.0.113.5 | ….zen.dq.spamhaus.net | not listed"]
    );
    assert!(!kept(&memory).contains(KEY), "{}", kept(&memory));
    let asked: serde_json::Value =
        serde_json::from_str(&memory.0.borrow()["reputation.read"]).unwrap();
    assert_eq!(asked["at"], now().as_second());
}

#[test]
fn only_the_key_of_a_dqs_zone_is_left_out() {
    for (zone, named) in [
        (zone().as_str(), "….zen.dq.spamhaus.net"),
        ("….zen.dq.spamhaus.net", "….zen.dq.spamhaus.net"),
        ("key.sbl-xbl.dq.spamhaus.net", "….sbl-xbl.dq.spamhaus.net"),
        // Without a label before the list's there is no key to leave out.
        ("zen.dq.spamhaus.net", "zen.dq.spamhaus.net"),
        ("zen.spamhaus.org", "zen.spamhaus.org"),
        ("bl.notdq.spamhaus.net", "bl.notdq.spamhaus.net"),
    ] {
        assert_eq!(shown(zone), named, "{zone}");
    }
}

/// A zone written without its key, `zen.dq.spamhaus.net`, is asked with the
/// key the collector read for the run: only the name with the key answers
/// here. The key is in the question alone.
#[test]
fn a_zone_written_without_its_key_is_asked_with_the_runs_key() {
    let mut answers = mail_host();
    listed(&mut answers, V4, &zone(), [127, 0, 0, 2]);
    let (resolver, _) = stand_in(answers, None, 64);
    let provider = provider(
        resolver,
        "lists = [\"zen.dq.spamhaus.net\"]\nlists_ipv6 = []",
    );
    let memory = Remembered::default();
    let card = keyed(&provider, &memory, 0, DqsKey::Key(KEY.to_owned()));
    assert_eq!(card.state, State::Failed);
    assert_eq!(
        card.findings,
        ["203.0.113.5 is listed on zen.dq.spamhaus.net (127.0.0.2)."]
    );
    assert_eq!(
        rows(&card),
        ["203.0.113.5 | zen.dq.spamhaus.net | listed (127.0.0.2)"]
    );
    let shown = serde_json::to_string(&card).unwrap();
    assert!(!shown.contains(KEY), "{shown}");
    assert!(!kept(&memory).contains(KEY), "{}", kept(&memory));
}

/// Without a key for the run such a zone is not asked: no verdict, never a
/// listing, and the card says why; the next run that has the key asks at
/// once.
#[test]
fn a_zone_without_its_key_is_not_asked_without_a_key_and_at_once_with_one() {
    let mut answers = mail_host();
    listed(&mut answers, V4, &zone(), [127, 0, 0, 2]);
    let (resolver, _) = stand_in(answers, None, 64);
    let lists = "lists = [\"zen.dq.spamhaus.net\", \"bl.example.net\"]\nlists_ipv6 = []";
    let provider = provider(resolver, lists);
    let memory = Remembered::default();
    let why = "/etc/garrison/credentials/spamhaus-dqs-key is empty; write the key of Spamhaus' \
               Data Query Service into it";
    let card = keyed(&provider, &memory, 0, DqsKey::Missing(why.to_owned()));
    // The other list answered; this one is not known.
    assert_eq!(card.state, State::Partial);
    assert_eq!(
        rows(&card),
        [
            format!("203.0.113.5 | zen.dq.spamhaus.net | no verdict: not asked: {why}"),
            "203.0.113.5 | bl.example.net | not listed".to_owned(),
        ]
    );
    assert_eq!(
        card.findings,
        [format!(
            "The lists of Spamhaus' Data Query Service written without their key were not \
             asked: {why}."
        )]
    );
    // Still no key a minute later, for the same reason: the reading stands.
    let unchanged = keyed(&provider, &memory, 60, DqsKey::Missing(why.to_owned()));
    assert_eq!(unchanged.findings, card.findings);
    // Another reason is asked anew, and said.
    let unset = keyed(&provider, &memory, 90, DqsKey::Unset);
    assert_eq!(
        unset.findings,
        [
            "The lists of Spamhaus' Data Query Service written without their key were not asked: \
          collector.dqs_key is not set."
        ]
    );
    let listed = keyed(&provider, &memory, 120, DqsKey::Key(KEY.to_owned()));
    assert_eq!(listed.state, State::Failed);
    assert_eq!(
        listed.findings,
        ["203.0.113.5 is listed on zen.dq.spamhaus.net (127.0.0.2)."]
    );
    assert!(!kept(&memory).contains(KEY), "{}", kept(&memory));
}

#[test]
fn a_zone_without_its_key_and_without_the_setting_is_not_asked() {
    let (resolver, _) = stand_in(mail_host(), None, 64);
    let provider = provider(
        resolver,
        "lists = [\"zen.dq.spamhaus.net\"]\nlists_ipv6 = []",
    );
    let card = blocklists(&provider, &Remembered::default(), 0);
    assert_eq!(card.state, State::Unknown);
    assert_eq!(
        card.findings,
        [
            "The lists of Spamhaus' Data Query Service written without their key were not asked: \
          collector.dqs_key is not set."
        ]
    );
}

/// check-config learns of each zone of the service and whether it holds
/// its key there, named as the cards name it.
#[test]
fn the_zones_of_the_service_are_named_with_whether_they_hold_their_key() {
    let (resolver, _) = stand_in(mail_host(), None, 64);
    let lists = format!(
        "lists = [\"zen.dq.spamhaus.net\", \"{KEY}.sbl.dq.spamhaus.net\", \"bl.spamcop.net\"]\n\
         lists_ipv6 = [\"zen.dq.spamhaus.net\"]"
    );
    assert_eq!(
        provider(resolver, &lists).dqs_zones(),
        [
            ("lists", "zen.dq.spamhaus.net".to_owned(), false),
            ("lists", "….sbl.dq.spamhaus.net".to_owned(), true),
            ("lists_ipv6", "zen.dq.spamhaus.net".to_owned(), false),
        ]
    );
}
