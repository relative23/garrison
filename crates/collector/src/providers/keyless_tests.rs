//! The cards that need the collector's API key for Stalwart, and what they
//! say where the collector has none. Every type runs with the key and
//! without it while Stalwart does not answer: a card that comes out
//! otherwise needs the key, so the checks that read Stalwart with it are
//! found from what they report, not from a list. Without the key each such
//! card says why in the same words, which name what makes a key, after a
//! frame of its own, as it gives its other reasons.

use std::collections::BTreeMap;

use garrison_core::config::Config;
use garrison_core::observations::State;
use garrison_testing::NATIVE_KEY;

use super::ids_tests::{cases, history, no_resolver};
use super::*;
use crate::context::Context;
use crate::testing::{Canned, config, table};

/// What a card says: its state and findings.
type Card = (State, Vec<String>);

/// The cards `provider` reports, by id, with the collector's `key` or
/// without one; Stalwart, at the closed port of the configuration, does not
/// answer.
fn cards(provider: &dyn Provider, config: &Config, key: Option<&str>) -> BTreeMap<String, Card> {
    let runner = Canned(String::new());
    let context = Context {
        native_key: key.map(str::to_owned),
        ..crate::testing::context(config, &runner)
    };
    provider
        .collect(&context)
        .unwrap()
        .observations
        .into_iter()
        .map(|card| (card.id, (card.state, card.findings)))
        .collect()
}

/// Where the collector has no key, as where its credential file is missing
/// or empty, every card that needs one is Unknown and says so in the same
/// words, which name `garrison stalwart setup`; the certificate card also
/// offers its `endpoints`, which need no key. A card that needs no key
/// says the same with and without one.
#[test]
fn without_a_key_every_card_that_needs_one_says_so_in_the_same_words() {
    let work = tempfile::tempdir().unwrap();
    // The cards that differ, as each says it without the key.
    let mut keyless: BTreeMap<String, Option<Card>> = BTreeMap::new();
    for case in cases(work.path()) {
        // Without `hosts` and `endpoints` of their own, these two read
        // Stalwart for them.
        let options = match case.kind {
            "reputation" => format!("resolver = \"{}\"", no_resolver()),
            "tls" => String::new(),
            _ => case.options,
        };
        let raw = table(&format!("type = \"{}\"\n{options}", case.kind));
        let provider = build(&[raw]).unwrap().remove(0);
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        // The sign-in page is asked for under the issuer: no name to look up.
        config.deployment.issuer = "https://localhost:9".to_owned();
        // With a week of history the mail flow asks Stalwart for accounts.
        history(&config);
        let keyed = cards(provider.as_ref(), &config, Some(NATIVE_KEY));
        let without = cards(provider.as_ref(), &config, None);
        for id in keyed.keys().chain(without.keys()) {
            if keyed.get(id) != without.get(id) {
                keyless.insert(id.clone(), without.get(id).cloned());
            }
        }
    }
    let no_key = "the collector has no API key for Stalwart; run `garrison stalwart setup`, \
                  which makes one";
    let unknown =
        |id: &str, finding: String| (id.to_owned(), Some((State::Unknown, vec![finding])));
    assert_eq!(
        keyless,
        BTreeMap::from([
            unknown("dns.records", format!("Not asked: {no_key}.")),
            unknown(
                "flow.spam-domains",
                format!("The domains of the mailboxes are not known: {no_key}.")
            ),
            unknown(
                "reputation.blocklists",
                format!("Nothing could be asked: {no_key}.")
            ),
            unknown(
                "reputation.reverse",
                format!("Nothing could be asked: {no_key}.")
            ),
            unknown("stalwart.api", format!("Not asked: {no_key}.")),
            unknown(
                "tls.endpoints",
                format!("The endpoints are not known: {no_key}, or name `endpoints`.")
            ),
        ])
    );
}
