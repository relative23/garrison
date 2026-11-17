//! A list that gives no verdict about an address, as one that refuses this
//! resolver, answers with an error or not at all, keeps the Blocklists card
//! from being in order: the card names the list, the addresses and why, and
//! an address that no list judged, and the reading is asked again after an
//! hour. A list whose question got no usable answer is not asked about the
//! next address, and its row says so, not that the list did not answer.

use std::collections::BTreeMap;

use garrison_core::observations::State;

use super::tests::{V4, V6, Zone, address, listed, mail_host, observed, provider, rows};
use super::*;
use crate::providers::dns::stand_in::{resolver as stand_in, resolver_erring};
use crate::testing::{Remembered, assert_dated};

const REFUSES: &str = "the list gives this resolver no verdict; it refuses public resolvers";

/// With the default lists, Spamhaus alone is asked about the IPv6 address:
/// where it refuses this resolver, no list judges that address.
#[test]
fn an_address_no_list_judged_is_named_and_the_card_is_not_in_order() {
    let mut zone = mail_host();
    listed(&mut zone, V6, "zen.spamhaus.org", [127, 255, 255, 254]);
    let (resolver, _) = stand_in(zone, None, 64);
    let (blocklists, _) = observed(&provider(resolver, ""), &Remembered::default(), 0);
    assert_eq!(
        rows(&blocklists)[4],
        format!("{V6} | zen.spamhaus.org | no verdict: {REFUSES}")
    );
    assert_eq!(
        (blocklists.state, blocklists.findings.clone()),
        (
            State::Partial,
            vec![
                format!("zen.spamhaus.org gave no verdict for {V6}: {REFUSES}."),
                format!("No list gave a verdict for {V6}."),
            ]
        )
    );
    // Not everything could be judged: asked again after an hour.
    assert_dated(&blocklists, 0, AGAIN);
}

/// An error of the resolver for a list's question is said in its own words,
/// and the addresses after it, which are not asked of that list, say so.
#[test]
fn a_list_whose_question_got_an_error_is_named_with_the_error() {
    let mut zone = Zone::new();
    for last in 5..7 {
        address(&mut zone, "mail.example.test", &format!("203.0.113.{last}"));
    }
    let errors = BTreeMap::from([(
        (
            dns::reversed(V4.parse().unwrap(), Some("down.example.org")),
            Kind::A.code(),
        ),
        2,
    )]);
    let (resolver, _) = resolver_erring(zone, errors, 64);
    let lists = "lists = [\"down.example.org\", \"up.example.org\"]\nlists_ipv6 = []";
    let (blocklists, _) = observed(&provider(resolver, lists), &Remembered::default(), 0);
    let servfail = "the resolver could not answer (SERVFAIL)";
    assert_eq!(
        rows(&blocklists),
        [
            format!("{V4} | down.example.org | no verdict: {servfail}"),
            format!("{V4} | up.example.org | not listed"),
            format!(
                "203.0.113.6 | down.example.org | no verdict: not asked again after no usable \
                 answer for {V4}"
            ),
            "203.0.113.6 | up.example.org | not listed".to_owned(),
        ]
    );
    assert_eq!(
        (blocklists.state, blocklists.findings.clone()),
        (
            State::Partial,
            vec![format!(
                "down.example.org gave no verdict for {V4}, 203.0.113.6: {servfail}."
            )]
        )
    );
}
