//! A resolver that did not answer a question is asked no more questions of
//! that kind in the reading: no more reverse names after one went
//! unanswered, and no more of where they lead after one, as a list that did
//! not answer is asked no more. Each would wait out its three seconds, and
//! the run has only so long. The lists are asked as before: the resolver
//! answered for the mail hosts, and the lists' zones are others. One that
//! did not answer for a mail host is asked nothing more, and what it
//! answered before counts.

use std::time::{Duration, Instant};

use garrison_core::observations::State;

use super::tests::{V4, Zone, address, listed, mail_host, observed, pointer, provider, rows};
use super::*;
use crate::providers::dns::stand_in::resolver_until;
use crate::testing::{Remembered, assert_dated, table};

/// One list, asked about IPv4 addresses only.
const LIST: &str = "lists = [\"up.example.org\"]\nlists_ipv6 = []";
/// What is said of an address whose question was not asked.
const BEFORE: &str = "the resolver did not answer such a question before";

/// The mail host's four IPv4 addresses, 203.0.113.5 to 203.0.113.8.
fn four_addresses() -> Zone {
    let mut zone = Zone::new();
    for last in 5..9 {
        address(&mut zone, "mail.example.test", &format!("203.0.113.{last}"));
    }
    zone
}

fn question(name: &str, kind: Kind) -> (String, u16) {
    (name.to_owned(), kind.code())
}

/// The questions a reading of [`four_addresses`] asks: the host's A record,
/// then for each address `reverse` (its reverse name, and where that
/// leads) where it is asked and the list, then the host's AAAA record.
fn questions(reverse: impl Fn(u8) -> Vec<(String, u16)>) -> Vec<(String, u16)> {
    let mut asked = vec![question("mail.example.test", Kind::A)];
    for last in 5..9 {
        asked.extend(reverse(last));
        asked.push(question(
            &format!("{last}.113.0.203.up.example.org"),
            Kind::A,
        ));
    }
    asked.push(question("mail.example.test", Kind::Aaaa));
    asked
}

#[test]
fn a_reverse_name_the_resolver_does_not_answer_leaves_the_others_unasked() {
    let (resolver, stopping) =
        resolver_until(four_addresses(), |name| name.ends_with(".in-addr.arpa"));
    let began = Instant::now();
    let (blocklists, reverse) = observed(&provider(resolver, LIST), &Remembered::default(), 0);
    let took = began.elapsed();
    // One reverse name waited out its time; the others were not asked.
    let first = |last| {
        if last == 5 {
            vec![question("5.113.0.203.in-addr.arpa", Kind::Ptr)]
        } else {
            Vec::new()
        }
    };
    assert_eq!(
        (stopping.questions(), took < Duration::from_secs(6)),
        (questions(first), true),
        "{took:?}"
    );
    let named_rows = rows(&reverse);
    assert!(
        named_rows[0].starts_with("203.0.113.5 | mail.example.test | - | not read: the resolver "),
        "{}",
        named_rows[0]
    );
    assert_eq!(
        named_rows[1..],
        (6..9)
            .map(|last| format!("203.0.113.{last} | mail.example.test | - | not read: {BEFORE}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(reverse.state, State::Unknown);
    assert_eq!(
        reverse.findings[1],
        format!("The reverse name of 203.0.113.6 could not be read: {BEFORE}.")
    );
    // Every list was asked about every address, as before.
    assert_eq!((blocklists.state, rows(&blocklists).len()), (State::Ok, 4));
    // Not everything could be read: asked again after an hour.
    assert_dated(&reverse, 0, AGAIN);
}

#[test]
fn where_a_reverse_name_leads_the_resolver_does_not_answer_leaves_the_others_unasked() {
    let mut zone = four_addresses();
    for last in 5..9 {
        pointer(
            &mut zone,
            &format!("203.0.113.{last}"),
            "relay.example.test",
        );
    }
    let (resolver, stopping) = resolver_until(zone, |name| name == "relay.example.test");
    let began = Instant::now();
    let (blocklists, reverse) = observed(&provider(resolver, LIST), &Remembered::default(), 0);
    let took = began.elapsed();
    // Every reverse name was read; where it leads, once.
    let named = |last| {
        let mut asked = vec![question(
            &format!("{last}.113.0.203.in-addr.arpa"),
            Kind::Ptr,
        )];
        if last == 5 {
            asked.push(question("relay.example.test", Kind::A));
        }
        asked
    };
    assert_eq!(
        (stopping.questions(), took < Duration::from_secs(6)),
        (questions(named), true),
        "{took:?}"
    );
    let named_rows = rows(&reverse);
    assert!(
        named_rows[0].starts_with(
            "203.0.113.5 | mail.example.test | relay.example.test | not followed back: the \
             resolver "
        ),
        "{}",
        named_rows[0]
    );
    assert_eq!(
        named_rows[1..],
        (6..9)
            .map(|last| format!(
                "203.0.113.{last} | mail.example.test | relay.example.test | not followed back: \
                 {BEFORE}"
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        reverse.findings[1],
        format!(
            "203.0.113.6 names relay.example.test; whether that leads back to it could not be \
             read: {BEFORE}."
        )
    );
    assert_eq!((blocklists.state, rows(&blocklists).len()), (State::Ok, 4));
}

/// The mail host answers, and one of its addresses is listed; the second
/// mail host's first question goes unanswered. Nothing more is asked, but
/// the listing found before is reported, and both cards say why not every
/// address was asked.
#[test]
fn what_the_resolver_answered_before_it_went_silent_for_a_mail_host_counts() {
    let mut zone = mail_host();
    listed(&mut zone, V4, "up.example.org", [127, 0, 0, 2]);
    let (resolver, stopping) = resolver_until(zone, |name| name == "mx2.example.test");
    let provider = Reputation::new(&table(&format!(
        "type = \"reputation\"\nresolver = \"{resolver}\"\n\
         hosts = [\"mail.example.test\", \"mx2.example.test\"]\n{LIST}"
    )))
    .unwrap();
    let (blocklists, reverse) = observed(&provider, &Remembered::default(), 0);
    let asked = stopping.questions();
    // The second mail host's A question was the last one asked.
    assert_eq!(
        asked.last(),
        Some(&question("mx2.example.test", Kind::A)),
        "{asked:?}"
    );
    let silent = "Not every address or list was asked: the resolver ";
    assert_eq!(
        (blocklists.state, blocklists.findings[0].as_str()),
        (
            State::Failed,
            "203.0.113.5 is listed on up.example.org (127.0.0.2)."
        )
    );
    assert!(
        blocklists.findings[1].starts_with(silent),
        "{:?}",
        blocklists.findings
    );
    // Both addresses of the mail host fit; the card is not in order for
    // what was not asked.
    assert_eq!(
        (reverse.state, rows(&reverse).len()),
        (State::Partial, 2),
        "{:?}",
        reverse.findings
    );
    assert!(
        reverse.findings[0].starts_with(silent),
        "{:?}",
        reverse.findings
    );
    // Not everything was asked: asked again after an hour.
    assert_dated(&blocklists, 0, AGAIN);
    assert_dated(&reverse, 0, AGAIN);
}

/// A mail host whose answer over UDP is cut off and whose question over TCP
/// fails is that host's alone: the resolver answered, so the next mail host
/// is asked, and the cards name the host whose addresses could not be read.
#[test]
fn a_mail_host_whose_question_over_tcp_fails_is_that_hosts_alone() {
    use crate::providers::dns::stand_in::{Fault, resolver_faulty};

    let mut zone = Zone::new();
    address(&mut zone, "mx2.example.test", "203.0.113.9");
    pointer(&mut zone, "203.0.113.9", "mx2.example.test");
    let closed =
        std::collections::BTreeMap::from([(question("mail.example.test", Kind::A), Fault::Closed)]);
    let (resolver, stopping) = resolver_faulty(zone, closed);
    let hosts = "hosts = [\"mail.example.test\", \"mx2.example.test\"]";
    let check = Reputation::new(&table(&format!(
        "type = \"reputation\"\nresolver = \"{resolver}\"\n{hosts}\n{LIST}"
    )))
    .unwrap();
    let (blocklists, reverse) = observed(&check, &Remembered::default(), 0);
    stopping.questions();
    let unread = "The IPv4 addresses of mail.example.test could not be read: the resolver's answer \
                  is cut off, and the question over TCP failed: the resolver closed the \
                  connection before it answered.";
    assert_eq!(
        (
            blocklists.state,
            blocklists.findings.clone(),
            rows(&blocklists)
        ),
        (
            State::Partial,
            vec![unread.to_owned()],
            vec!["203.0.113.9 | up.example.org | not listed".to_owned()]
        )
    );
    assert_eq!(
        (reverse.state, reverse.findings.clone(), rows(&reverse)),
        (
            State::Partial,
            vec![unread.to_owned()],
            vec!["203.0.113.9 | mx2.example.test | mx2.example.test | fits".to_owned()]
        )
    );
}
