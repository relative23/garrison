//! An answer the check cannot use, for one address's reverse name or for
//! whether that name leads back, counts for that address alone: its row
//! says why the name could not be read, the card is not in order for it,
//! and the other addresses and every list are asked as before. It ended
//! the whole reading.

use garrison_core::observations::State;

use super::tests::{V4, V6, mail_host, observed, pointer, provider, rows};
use super::*;
use crate::providers::dns::stand_in::resolver as stand_in;
use crate::testing::{Remembered, assert_dated};

const MALFORMED: &str = "the resolver's answer is malformed";

/// A name of `octets` octets as written, of labels no longer than 63.
fn name_of(octets: usize) -> String {
    let mut name = String::new();
    while name.len() + 51 + 5 < octets {
        name.push_str(&"a".repeat(50));
        name.push('.');
    }
    name.push_str(&"b".repeat(octets - name.len() - 5));
    name.push_str(".test");
    assert_eq!(name.len(), octets);
    name
}

#[test]
fn a_reverse_name_that_cannot_be_read_counts_for_its_address_alone() {
    // A reverse name one octet longer than DNS takes, which no resolver can
    // give: the answer that holds it is malformed.
    let mut zone = mail_host();
    pointer(&mut zone, V4, &name_of(254));
    let (resolver, _) = stand_in(zone, None, 64);
    let memory = Remembered::default();
    let (blocklists, reverse) = observed(&provider(resolver, ""), &memory, 0);
    assert_eq!(
        rows(&reverse),
        [
            format!("{V4} | mail.example.test | - | not read: {MALFORMED}"),
            format!("{V6} | mail.example.test | mail.example.test | fits"),
        ]
    );
    assert_eq!(reverse.state, State::Partial);
    assert_eq!(
        reverse.findings,
        [format!(
            "The reverse name of {V4} could not be read: {MALFORMED}."
        )]
    );
    // Both addresses are still asked of the lists, and nothing is listed.
    assert_eq!(rows(&blocklists).len(), 5, "{:?}", rows(&blocklists));
    assert_eq!(
        (blocklists.state, blocklists.findings.len()),
        (State::Ok, 0)
    );
    // Not everything could be read, so the reading is asked again after an
    // hour, as one cut short is.
    assert_dated(&reverse, 0, AGAIN);
    assert_dated(&blocklists, 0, AGAIN);
}

#[test]
fn a_reverse_name_whose_way_back_cannot_be_read_counts_for_its_address_alone() {
    let mut zone = mail_host();
    pointer(&mut zone, V4, "relay.example.test");
    // An address record of three octets, which no resolver can give.
    zone.insert(
        ("relay.example.test".to_owned(), Kind::A.code()),
        vec![vec![192, 0, 2]],
    );
    let (resolver, _) = stand_in(zone, None, 64);
    let (blocklists, reverse) = observed(&provider(resolver, ""), &Remembered::default(), 0);
    assert_eq!(
        rows(&reverse),
        [
            format!(
                "{V4} | mail.example.test | relay.example.test | not followed back: {MALFORMED}"
            ),
            format!("{V6} | mail.example.test | mail.example.test | fits"),
        ]
    );
    assert_eq!(reverse.state, State::Partial);
    assert_eq!(
        reverse.findings,
        [format!(
            "{V4} names relay.example.test; whether that leads back to it could not be read: \
             {MALFORMED}."
        )]
    );
    assert_eq!(blocklists.state, State::Ok, "{:?}", blocklists.findings);
}

#[test]
fn where_no_reverse_name_can_be_read_the_card_is_unknown_and_the_lists_are_asked() {
    let mut zone = mail_host();
    pointer(&mut zone, V4, &name_of(254));
    pointer(&mut zone, V6, &name_of(255));
    let (resolver, _) = stand_in(zone, None, 64);
    let (blocklists, reverse) = observed(&provider(resolver, ""), &Remembered::default(), 0);
    assert_eq!(reverse.state, State::Unknown);
    assert_eq!(
        reverse.findings,
        [
            format!("The reverse name of {V4} could not be read: {MALFORMED}."),
            format!("The reverse name of {V6} could not be read: {MALFORMED}."),
        ]
    );
    // A problem with another address is a warning beside them.
    assert_eq!((blocklists.state, rows(&blocklists).len()), (State::Ok, 5));
    let mut zone = mail_host();
    pointer(&mut zone, V4, &name_of(254));
    pointer(&mut zone, V6, "other.example.test");
    let (resolver, _) = stand_in(zone, None, 64);
    let (_, reverse) = observed(&provider(resolver, ""), &Remembered::default(), 0);
    assert_eq!(reverse.state, State::Warning);
    assert_eq!(
        reverse.findings,
        [
            format!("{V6} names other.example.test, which does not lead back to it."),
            format!("The reverse name of {V4} could not be read: {MALFORMED}."),
        ]
    );
}
