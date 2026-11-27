//! The rule of a card that is told. A notification carries a card's title
//! and its first finding, so a card that is a warning or failed says first
//! what made it so. Held over every card the checks of this crate report:
//! each way a card is told, beside what else it says; a card that is never
//! told is named with why. A card of these checks that is in neither list
//! fails here.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use garrison_core::observations::{Observation, State};
use serde_json::json;

use super::*;
use crate::context::Provider;
use crate::testing::{Canned, Remembered, config, context, table};

/// A way of a card to be told: the card, and the words its first finding
/// holds where it names what made the card's state.
struct Told {
    what: &'static str,
    card: Observation,
    cause: &'static str,
}

/// The two antivirus cards: a policy that lets mail pass beside a directive
/// set twice, which is a note, and a daily database that is days old.
fn antivirus() -> Vec<Told> {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name);
    std::fs::write(
        path("milter.conf"),
        "OnInfected Reject\nOnInfected Reject\nOnFail Accept\n",
    )
    .unwrap();
    std::fs::write(path("scan.conf"), "ScanArchive yes\n").unwrap();
    std::fs::write(path("daily.cld"), "signatures").unwrap();
    let provider = Clamav::new(&table(&format!(
        "type = \"clamav\"\nmilter_config = \"{0}/milter.conf\"\nclamd_config = \"{0}/scan.conf\"\ndatabase_directory = \"{0}\"",
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = context(&config, &runner);
    let checked = SystemTime::UNIX_EPOCH
        + Duration::from_secs(u64::try_from(context.now.as_second()).unwrap());
    let daily = std::fs::File::options()
        .write(true)
        .open(path("daily.cld"))
        .unwrap();
    daily
        .set_modified(checked - Duration::from_hours(52))
        .unwrap();
    let mut cards = provider.collect(&context).unwrap().observations;
    let signatures = cards.remove(1);
    vec![
        Told {
            what: "a policy that lets mail pass, beside a directive set twice",
            card: cards.remove(0),
            cause: "Scanner failures are handled with Accept, not Defer.",
        },
        Told {
            what: "a daily database that is days old",
            card: signatures,
            cause: "daily.cld was last updated 52 hours ago",
        },
    ]
}

/// The milter's card of the week where the milter could not be reached.
fn milter() -> Vec<Told> {
    let events = [
        flow::tests::event("milter.action-accept", 60, json!({})),
        flow::tests::event("milter.timeout", 63, json!({})),
    ];
    let cards = flow::tests::observed(&events, None, &Remembered::default(), 0);
    vec![Told {
        what: "a milter that could not be reached since yesterday",
        card: flow::tests::of(&cards, "flow.milter").clone(),
        cause: "The milter could not be reached 1 times since yesterday",
    }]
}

/// The senders' card where an address sent to more than a burst allows.
fn senders() -> Vec<Told> {
    let strict = Senders::new(&table("type = \"senders\"\nburst = 10")).unwrap();
    let events = [senders::tests::queued(
        "anna@example.test",
        60,
        20,
        "192.0.2.1",
    )];
    vec![Told {
        what: "an address that sent to more recipients than a burst allows",
        card: senders::tests::observed(&strict, &events, 20, &Remembered::default(), 0),
        cause: "anna@example.test: 20 recipients within one hour.",
    }]
}

/// The test messages' card where the server took the test file.
fn mail_test() -> Vec<Told> {
    let (port, handle) = mailtest::tests::server([
        "250 2.0.0 Message queued with id a.",
        "250 2.0.0 Message queued with id b.",
    ]);
    let provider = mailtest::tests::provider(port);
    let memory = Remembered::default();
    mailtest::tests::collected(&provider, &memory, 0, &[]);
    let card = mailtest::tests::collected(&provider, &memory, 120, &[("11", "message-ingest.ham")]);
    handle.join().unwrap();
    vec![Told {
        what: "a test file the server accepted",
        card,
        cause: "Antivirus test file (EICAR): accepted",
    }]
}

/// The cards of these checks that are never a warning or failed, and why.
const NEVER_TOLD: [(&str, &str); 5] = [
    (
        "flow.spam",
        "counts what was filed as spam and judges it not: OK, Partial or Unknown",
    ),
    (
        "flow.spam-domains",
        "counts by domain and judges none: OK, Partial or Unknown",
    ),
    (
        "flow.authentication",
        "sums the checks of senders and judges none: OK, Partial or Unknown",
    ),
    (
        "flow.failing-senders",
        "names the domains that failed and judges none: OK, Partial or Unknown",
    ),
    (
        "flow.tls",
        "counts mail without TLS and judges it not: OK, Partial or Unknown",
    ),
];

#[test]
fn every_card_that_is_told_says_first_what_made_it_so() {
    let mut broken = Vec::new();
    let mut covered: BTreeSet<String> = NEVER_TOLD.iter().map(|(id, _)| (*id).to_owned()).collect();
    let ways = [antivirus(), milter(), senders(), mail_test()];
    for way in ways.into_iter().flatten() {
        covered.insert(way.card.id.clone());
        let told = matches!(way.card.state, State::Warning | State::Failed);
        let first = way.card.findings.first().map_or("", String::as_str);
        if !told || !first.contains(way.cause) {
            broken.push(format!(
                "{}: {:?} {:?}",
                way.what, way.card.state, way.card.findings
            ));
        }
    }
    assert_eq!(broken, Vec::<String>::new());
    // Every card of the checks is in one list or the other.
    let ids: BTreeSet<String> = [
        Clamav::new(&table("type = \"clamav\"")).unwrap().ids(),
        Flow::new(&table("type = \"mail-flow\"")).unwrap().ids(),
        Senders::new(&table("type = \"senders\"")).unwrap().ids(),
        mailtest::tests::provider(25).ids(),
    ]
    .concat()
    .into_iter()
    .collect();
    assert_eq!(covered, ids);
}
