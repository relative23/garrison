//! An answer the check cannot use, for one address's reverse name or for
//! whether that name leads back, counts for that address alone: its row
//! says why the name could not be read, the card is not in order for it,
//! and the other addresses and every list are asked as before. So does one
//! for a mail host's addresses, for that host alone. Both ended the whole
//! reading.

use std::collections::BTreeMap;

use garrison_core::observations::State;

use super::tests::{V4, V6, Zone, address, mail_host, observed, pointer, provider, rows};
use super::*;
use crate::providers::dns::stand_in::{resolver as stand_in, resolver_erring};
use crate::testing::{Remembered, assert_dated, table};

const MALFORMED: &str = "the resolver's answer is malformed";
const SERVFAIL: u8 = 2;
const REFUSED: u8 = 5;

/// The check of the two mail hosts `mail.example.test` and `mx2.example.test`.
fn two_hosts(resolver: SocketAddr) -> Reputation {
    Reputation::new(&table(&format!(
        "type = \"reputation\"\nresolver = \"{resolver}\"\n\
         hosts = [\"mail.example.test\", \"mx2.example.test\"]"
    )))
    .unwrap()
}

/// The question for the records of `kind` at `name`, for an error to answer.
fn asked(name: &str, kind: Kind) -> (String, u16) {
    (name.to_owned(), kind.code())
}

#[test]
fn a_mail_hosts_unusable_answer_counts_for_that_host_alone() {
    // mail.example.test answers as it should; mx2's address record has
    // three octets, which no resolver can give, and its IPv6 question is
    // refused.
    let mut zone = mail_host();
    zone.insert(asked("mx2.example.test", Kind::A), vec![vec![192, 0, 2]]);
    let errors = BTreeMap::from([(asked("mx2.example.test", Kind::Aaaa), REFUSED)]);
    let (resolver, _) = resolver_erring(zone, errors, 64);
    let (blocklists, reverse) = observed(&two_hosts(resolver), &Remembered::default(), 0);
    let unread = [
        format!("The IPv4 addresses of mx2.example.test could not be read: {MALFORMED}."),
        "The IPv6 addresses of mx2.example.test could not be read: the resolver refused the \
         question."
            .to_owned(),
    ];
    // The other host's addresses are asked of every list as before.
    assert_eq!(rows(&blocklists).len(), 5, "{:?}", rows(&blocklists));
    assert_eq!(
        rows(&reverse),
        [
            format!("{V4} | mail.example.test | mail.example.test | fits"),
            format!("{V6} | mail.example.test | mail.example.test | fits"),
        ]
    );
    // Both cards name the host and why, and are not in order for it.
    for card in [&blocklists, &reverse] {
        assert_eq!(card.state, State::Partial, "{}", card.id);
        assert_eq!(card.findings, unread, "{}", card.id);
        // Not everything could be read: asked again after an hour.
        assert_dated(card, 0, AGAIN);
    }
}

#[test]
fn an_error_for_one_kind_of_address_counts_for_that_kind_alone() {
    let mut zone = mail_host();
    zone.remove(&asked("mail.example.test", Kind::Aaaa));
    let errors = BTreeMap::from([(asked("mail.example.test", Kind::Aaaa), SERVFAIL)]);
    let (resolver, _) = resolver_erring(zone, errors, 64);
    let (blocklists, reverse) = observed(&provider(resolver, ""), &Remembered::default(), 0);
    assert_eq!(rows(&blocklists).len(), 4, "{:?}", rows(&blocklists));
    assert_eq!(
        rows(&reverse),
        [format!(
            "{V4} | mail.example.test | mail.example.test | fits"
        )]
    );
    for card in [&blocklists, &reverse] {
        assert_eq!(card.state, State::Partial, "{}", card.id);
        assert_eq!(
            card.findings,
            [
                "The IPv6 addresses of mail.example.test could not be read: the resolver could \
                 not answer (SERVFAIL)."
            ],
            "{}",
            card.id
        );
    }
}

#[test]
fn where_no_mail_host_can_be_read_both_cards_are_unknown() {
    let mut zone = Zone::new();
    zone.insert(asked("mail.example.test", Kind::A), vec![vec![192, 0, 2]]);
    zone.insert(asked("mail.example.test", Kind::Aaaa), vec![vec![0x20, 1]]);
    let (resolver, _) = stand_in(zone, None, 64);
    let (blocklists, reverse) = observed(&provider(resolver, ""), &Remembered::default(), 0);
    for card in [&blocklists, &reverse] {
        assert_eq!(card.state, State::Unknown, "{}", card.id);
        // One reason for both kinds is said once.
        assert_eq!(
            card.findings,
            [format!(
                "The addresses of mail.example.test could not be read: {MALFORMED}."
            )],
            "{}",
            card.id
        );
        assert_eq!(rows(card), Vec::<String>::new(), "{}", card.id);
        assert_dated(card, 0, AGAIN);
    }
    // A host that has no address of a kind is no host that could not be
    // read: here mx2 has an IPv4 address and no IPv6 one.
    let mut zone = Zone::new();
    zone.insert(asked("mail.example.test", Kind::A), vec![vec![192, 0, 2]]);
    address(&mut zone, "mx2.example.test", V4);
    pointer(&mut zone, V4, "mx2.example.test");
    let (resolver, _) = stand_in(zone, None, 64);
    let (blocklists, reverse) = observed(&two_hosts(resolver), &Remembered::default(), 0);
    let unread = [format!(
        "The IPv4 addresses of mail.example.test could not be read: {MALFORMED}."
    )];
    assert_eq!(
        (blocklists.state, &blocklists.findings),
        (State::Partial, &unread.to_vec())
    );
    assert_eq!(
        (reverse.state, &reverse.findings),
        (State::Partial, &unread.to_vec())
    );
}

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
