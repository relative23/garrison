//! A reading asks about so many mail hosts and addresses at the most. What
//! it leaves out by those limits it says, and its cards are not in order
//! for what was not asked.

use std::time::Duration;

use garrison_core::observations::{Observation, State};
use serde_json::json;

use super::asker::SLOW;
use super::tests::{Zone, address, pointer, rows};
use super::*;
use crate::providers::dns::stand_in::resolver as stand_in;
use crate::testing::{Canned, Remembered, assert_dated, config, now, table};

/// The two cards of `provider`.
fn observed(provider: &Reputation) -> (Observation, Observation) {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let memory = Remembered::default();
    let context = Context {
        memory: &memory,
        ..crate::testing::context(&config, &runner)
    };
    let mut observations = provider.collect(&context).unwrap().observations;
    let reverse = observations.remove(1);
    (observations.remove(0), reverse)
}

fn provider(resolver: SocketAddr, hosts: &[String]) -> Reputation {
    provider_with(resolver, hosts, "lists = [\"up.example.org\"]")
}

/// A provider for `hosts` with the `lists` line given.
fn provider_with(resolver: SocketAddr, hosts: &[String], lists: &str) -> Reputation {
    let hosts: Vec<String> = hosts.iter().map(|host| format!("\"{host}\"")).collect();
    Reputation::new(&table(&format!(
        "type = \"reputation\"\nresolver = \"{resolver}\"\nhosts = [{}]\n{lists}\nlists_ipv6 = []",
        hosts.join(", ")
    )))
    .unwrap()
}

/// An address of `host` with a reverse name that leads back to it.
fn fitting(zone: &mut Zone, host: &str, text: &str) {
    address(zone, host, text);
    pointer(zone, text, host);
}

#[test]
fn mail_hosts_after_the_first_eight_are_named_and_keep_the_cards_from_being_in_order() {
    let hosts: Vec<String> = (1..=9)
        .map(|number| format!("mx{number}.example.test"))
        .collect();
    let mut zone = Zone::new();
    fitting(&mut zone, &hosts[0], "203.0.113.5");
    // A and AAAA of eight hosts, then the reverse name, its address and the
    // list for the one address: nothing of the ninth.
    let (resolver, handle) = stand_in(zone, None, 19);
    let (blocklists, reverse) = observed(&provider(resolver, &hosts));
    assert_eq!(handle.join().unwrap().len(), 19);
    assert_eq!(
        rows(&blocklists),
        ["203.0.113.5 | up.example.org | not listed"]
    );
    let left_out = "There are 9 mail hosts; only the first 8 are asked.";
    assert_eq!(blocklists.findings, [left_out]);
    assert_eq!(reverse.findings, [left_out]);
    assert_eq!(
        (blocklists.state, reverse.state),
        (State::Partial, State::Partial)
    );
}

#[test]
fn addresses_after_the_first_twelve_are_named_and_keep_the_cards_from_being_in_order() {
    let mut zone = Zone::new();
    for last in 1..=13 {
        fitting(&mut zone, "mail.example.test", &format!("203.0.113.{last}"));
    }
    // A and AAAA, then the reverse name, its address and the list of each
    // of twelve addresses.
    let (resolver, handle) = stand_in(zone, None, 2 + 12 * 3);
    let (blocklists, reverse) = observed(&provider(resolver, &["mail.example.test".to_owned()]));
    assert_eq!(handle.join().unwrap().len(), 38);
    assert_eq!(rows(&blocklists).len(), 12);
    assert_eq!(rows(&reverse).len(), 12);
    let left_out = "The mail hosts have 13 addresses; only the first 12 are asked.";
    assert_eq!(blocklists.findings, [left_out]);
    assert_eq!(reverse.findings, [left_out]);
    assert_eq!(
        (blocklists.state, reverse.state),
        (State::Partial, State::Partial)
    );
    // Twelve addresses are all there is: in order.
    let mut zone = Zone::new();
    for last in 1..=12 {
        fitting(&mut zone, "mail.example.test", &format!("203.0.113.{last}"));
    }
    let (resolver, _) = stand_in(zone, None, 38);
    let (blocklists, reverse) = observed(&provider(resolver, &["mail.example.test".to_owned()]));
    assert_eq!(
        (blocklists.state, reverse.state, blocklists.findings.len()),
        (State::Ok, State::Ok, 0)
    );
}

/// The lists are asked for 30 seconds in all at the most. A list left
/// unasked then keeps the blocklists card from being in order and says why;
/// the reverse names were asked all the same.
#[test]
fn lists_left_unasked_for_their_time_keep_the_blocklists_card_from_being_in_order() {
    let mut zone = Zone::new();
    fitting(&mut zone, "mail.example.test", "203.0.113.5");
    fitting(&mut zone, "mail.example.test", "203.0.113.6");
    let host = ["mail.example.test".to_owned()];
    let lists = "lists = [\"up.example.org\", \"down.example.org\"]";
    let unasked = "Not every list was asked: the lists took too long.";
    // The second list does not answer for the first address, which takes
    // the three seconds of its question: the lists' time of one second is
    // over before the second address.
    let (resolver, handle) = stand_in(zone.clone(), Some("5.113.0.203.down.example.org"), 8);
    let impatient = provider_with(resolver, &host, lists).with_patience(Duration::from_secs(1));
    let (blocklists, reverse) = observed(&impatient);
    assert_eq!(handle.join().unwrap().len(), 8);
    let rows = rows(&blocklists);
    assert_eq!(rows[0], "203.0.113.5 | up.example.org | not listed");
    assert_eq!(
        rows[2..],
        [
            "203.0.113.6 | up.example.org | no verdict: not asked: the lists took too long",
            "203.0.113.6 | down.example.org | no verdict: the list did not answer before",
        ]
    );
    assert_eq!(blocklists.state, State::Partial);
    assert_eq!(blocklists.findings, [unasked]);
    assert_eq!((reverse.state, reverse.findings.len()), (State::Ok, 0));
    // No time at all: no list gave a verdict, because none was asked.
    let (resolver, _) = stand_in(zone, None, 6);
    let none = provider_with(resolver, &host, lists).with_patience(Duration::ZERO);
    let (blocklists, reverse) = observed(&none);
    assert_eq!(blocklists.state, State::Unknown);
    assert_eq!(blocklists.findings, [unasked]);
    assert_eq!(reverse.state, State::Ok);
}

/// The kept reading says that a list went unasked for the lists' time; the
/// words of its row are only shown. Kept with other words, as another
/// release may write them, it keeps the card from being in order all the
/// same, and is asked again after an hour.
#[test]
fn a_list_left_unasked_is_known_by_the_reading_not_by_the_words_of_its_row() {
    let reading = |row: &str, marked: bool| {
        let mut kept = json!({
            "at": now().as_second(),
            "hosts": ["mail.example.test"],
            "addresses": [{"host": "mail.example.test", "address": "203.0.113.5",
                           "pointer": "mail.example.test", "confirmed": true,
                           "lists": [["up.example.org", "Clear"],
                                     ["down.example.org", {"Unanswered": row}]]}],
            "problem": null,
        });
        if marked {
            kept["lists_unasked"] = json!(true);
        }
        let memory = Remembered::default();
        memory
            .0
            .borrow_mut()
            .insert(MEMORY.to_owned(), kept.to_string());
        // Not asked: the kept reading is used.
        let provider = provider(SocketAddr::from(([127, 0, 0, 1], 9)), &[]);
        tests::observed(&provider, &memory, 0).0
    };
    let other = "not asked: the lists had had their time";
    let blocklists = reading(other, true);
    assert_eq!(
        rows(&blocklists)[1],
        format!("203.0.113.5 | down.example.org | no verdict: {other}")
    );
    assert_eq!(blocklists.state, State::Partial);
    assert_eq!(
        blocklists.findings,
        ["Not every list was asked: the lists took too long."]
    );
    assert_dated(&blocklists, 0, AGAIN);
    // The words alone decide nothing: a reading without the mark, as 0.1.2
    // kept it, counts as it counted there until it is asked again.
    let earlier = reading(&format!("not asked: {SLOW}"), false);
    assert_eq!((earlier.state, earlier.findings.len()), (State::Ok, 0));
    assert_dated(&earlier, 0, EVERY);
}
