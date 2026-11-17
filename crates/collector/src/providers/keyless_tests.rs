//! The cards that need the collector's API key for Stalwart, and what they
//! say where the collector has none. Every type runs with the key and
//! without it while Stalwart does not answer: a card that comes out
//! otherwise needs the key, so the checks that read Stalwart with it are
//! found from what they report, not from a list. Without the key each such
//! card says why in the same words, which name what makes a key, after a
//! frame of its own, as it gives its other reasons. A reading such a check
//! keeps from a run without the key is made again once a run has one.

use std::collections::BTreeMap;

use garrison_core::config::Config;
use garrison_core::observations::State;
use garrison_core::time::Timestamp;
use garrison_testing::NATIVE_KEY;

use super::ids_tests::{Case, cases, history, no_resolver};
use super::*;
use crate::context::{Context, Forgetful, Memory};
use crate::testing::{Canned, Remembered, config, now, table};

/// What a card says: its state and findings.
type Card = (State, Vec<String>);

/// The cards `provider` reports, by id, with the collector's `key` or
/// without one, `later` seconds after the tests' clock, keeping what it
/// keeps in `memory`; Stalwart, at the closed port of the configuration,
/// does not answer.
fn cards_at(
    provider: &dyn Provider,
    config: &Config,
    key: Option<&str>,
    memory: &dyn Memory,
    later: i64,
) -> BTreeMap<String, Card> {
    let runner = Canned(String::new());
    let context = Context {
        native_key: key.map(str::to_owned),
        now: Timestamp::from_second(now().as_second() + later).unwrap(),
        memory,
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

/// The cards of a run that keeps nothing, at the tests' clock.
fn cards(provider: &dyn Provider, config: &Config, key: Option<&str>) -> BTreeMap<String, Card> {
    cards_at(provider, config, key, &Forgetful, 0)
}

/// Each type as it reads Stalwart: without `hosts` and `endpoints` of
/// their own the reputation and certificate checks ask Stalwart for them;
/// with a configuration of its own, as the mail flow asks for accounts
/// only over a week of history.
fn reading_stalwart(case: Case) -> (Box<dyn Provider>, tempfile::TempDir, Config) {
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
    history(&config);
    (provider, directory, config)
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
        let (provider, _directory, config) = reading_stalwart(case);
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

/// A reading a check keeps from a run without the key, as of the mail hosts
/// or the domains of the mailboxes, is made again in the first run that has
/// one, as one without the key of Spamhaus' Data Query Service is: a minute
/// after a run without the key, each card that needs it says what it says
/// in a run with the key that kept nothing before.
#[test]
fn a_reading_kept_without_the_key_is_made_again_once_there_is_one() {
    let work = tempfile::tempdir().unwrap();
    let mut kept: BTreeMap<String, Option<Card>> = BTreeMap::new();
    for case in cases(work.path()) {
        let (provider, _directory, config) = reading_stalwart(case);
        let provider = provider.as_ref();
        let keyed = cards_at(provider, &config, Some(NATIVE_KEY), &Forgetful, 60);
        let keyless = cards_at(provider, &config, None, &Forgetful, 60);
        let memory = Remembered::default();
        cards_at(provider, &config, None, &memory, 0);
        let after = cards_at(provider, &config, Some(NATIVE_KEY), &memory, 60);
        for id in keyed.keys().chain(keyless.keys()) {
            if keyed.get(id) != keyless.get(id) && after.get(id) != keyed.get(id) {
                kept.insert(id.clone(), after.get(id).cloned());
            }
        }
    }
    assert_eq!(kept, BTreeMap::new());
}

/// A run with the key, then one without it a minute later on the same
/// memory: the cards of a check that keeps its reading show that reading,
/// without a word of the key, until the check reads Stalwart again. So the
/// collector's journal says only that each card says so when its check next
/// reads Stalwart. The blocklist and reverse-name cards are not among them:
/// their check reads Stalwart again in the next run.
#[test]
fn a_reading_kept_with_the_key_stands_until_its_check_reads_stalwart_again() {
    let work = tempfile::tempdir().unwrap();
    let mut standing = std::collections::BTreeSet::new();
    for case in cases(work.path()) {
        let (provider, _directory, config) = reading_stalwart(case);
        let provider = provider.as_ref();
        let keyed = cards_at(provider, &config, Some(NATIVE_KEY), &Forgetful, 60);
        let keyless = cards_at(provider, &config, None, &Forgetful, 60);
        let memory = Remembered::default();
        cards_at(provider, &config, Some(NATIVE_KEY), &memory, 0);
        let after = cards_at(provider, &config, None, &memory, 60);
        for id in keyed.keys().chain(keyless.keys()) {
            if keyed.get(id) != keyless.get(id) && after.get(id) != keyless.get(id) {
                standing.insert(id.clone());
            }
        }
    }
    let standing: Vec<String> = standing.into_iter().collect();
    assert_eq!(standing, ["flow.spam-domains"]);
}
