//! The rule of a card that is told. A notification carries a card's title
//! and its first finding, so a card that is a warning or failed says first
//! what made it so. Held over every card the checks of this crate report:
//! each way a card is told, beside what else it says; a card that is never
//! told is named with why. A card of these checks that is in neither list
//! fails here.

use std::collections::BTreeSet;

use garrison_core::config::{Config, Database};
use garrison_core::observations::{Observation, State};
use garrison_testing::http::{answer, json as answer_json, serve};
use serde_json::json;

use super::*;
use crate::context::{Context, Provider, Scrape};
use crate::testing::{Canned, Remembered, config, now, table};

/// A way of a card to be told: the card, and the words its first finding
/// holds where it names what made the card's state.
struct Told {
    what: &'static str,
    card: Observation,
    cause: &'static str,
}

/// The card `id` among `cards`.
fn the(cards: &[Observation], id: &str) -> Observation {
    cards
        .iter()
        .find(|card| card.id == id)
        .cloned()
        .unwrap_or_else(|| panic!("no card {id}"))
}

/// A user account with `used` of its `quota`.
fn account(address: &str, used: u64, quota: u64) -> serde_json::Value {
    json!({"@type": "User", "emailAddress": address, "usedDiskQuota": used,
           "quotas": {"maxDiskQuota": quota}})
}

/// The milter and mailbox cards: two milters that let mail pass where one
/// is named, and a full mailbox among more accounts than are listed.
fn stalwart() -> Vec<Told> {
    let milter = json!({"host": "127.0.0.1", "port": 7357, "enable": true,
                        "tempFailOnError": false, "stages": {"data": true}});
    let answers = json!({"methodResponses": [
        ["x:SpamSettings/get", {"list": [{"enable": true}]}, "0"],
        ["x:SpamClassifier/get", {"list": [{}]}, "1"],
        ["x:SpamRule/query", {"total": 3}, "2"],
        ["x:SpamTrainingSample/query", {"total": 0}, "3"],
        ["x:QueuedMessage/query", {"total": 1}, "4"],
        ["x:MtaMilter/get", {"list": [milter, milter]}, "5"],
        ["x:Account/get", {"list": [
            account("a@example.test", 1, 100),
            account("b@example.test", 2, 100),
            account("full@example.test", 95, 100),
        ]}, "6"],
    ]});
    let server = serve(vec![answer_json(&answers)]);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&server.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".to_owned()),
        ..crate::testing::context(&config, &runner)
    };
    let provider = Stalwart::new(&table(
        "type = \"stalwart\"\nmilter_port = 7357\nmax_accounts = 2",
    ))
    .unwrap();
    let cards = provider.collect(&context).unwrap().observations;
    server.requests();
    vec![
        Told {
            what: "milters whose errors let mail pass, more than the one named",
            card: the(&cards, "stalwart.milter"),
            cause: "do not cause a temporary rejection",
        },
        Told {
            what: "a full mailbox among more accounts than are listed",
            card: the(&cards, "stalwart.mailboxes"),
            cause: "full@example.test uses 90 % or more of its quota",
        },
    ]
}

/// The exporter's card where its gauges are not all there.
fn exporter() -> Vec<Told> {
    let server = serve(vec![answer(200, "stalwart_server_memory_bytes 1024\n")]);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&server.url);
    let runner = Canned(String::new());
    let context = Context {
        metrics_credential: Scrape::Credential("metrics".into(), "secret".into()),
        ..crate::testing::context(&config, &runner)
    };
    let provider = Prometheus::new(&table("type = \"prometheus\"")).unwrap();
    let cards = provider.collect(&context).unwrap().observations;
    server.requests();
    vec![Told {
        what: "an exporter without some of its gauges",
        card: the(&cards, "prometheus.exporter"),
        cause: "The exporter has no",
    }]
}

/// A history in which Stalwart 1.1.0 started.
fn started(config: &Config) {
    let path = config.database(Database::Events);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE events(created_at INTEGER, type TEXT, fields TEXT);\
         INSERT INTO events VALUES(1793000000, 'server.startup', '{\"version\": \"1.1.0\"}');",
    )
    .unwrap();
}

/// The release cards, from answers kept a minute ago that name a newer
/// release while GitHub gave none since.
fn releases() -> Vec<Told> {
    let memory = Remembered::default();
    for (product, latest) in [("garrison", "99.0.0"), ("stalwart", "99.0.0")] {
        let kept = json!({"at": now().as_second() - 60, "latest": latest,
                          "answeredAt": now().as_second() - 90_000,
                          "problem": "GitHub answered 503", "every": false});
        memory
            .0
            .borrow_mut()
            .insert(format!("release.{product}"), kept.to_string());
    }
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    started(&config);
    let runner = Canned(String::new());
    let context = Context {
        memory: &memory,
        ..crate::testing::context(&config, &runner)
    };
    let provider = Releases::new(&table("type = \"releases\"")).unwrap();
    let cards = provider.collect(&context).unwrap().observations;
    vec![
        Told {
            what: "a newer release of Garrison, while GitHub gives no answer",
            card: the(&cards, "release.garrison"),
            cause: "Garrison 99.0.0 is available",
        },
        Told {
            what: "a newer release of Stalwart, while GitHub gives no answer",
            card: the(&cards, "release.stalwart"),
            cause: "Stalwart 99.0.0 is available",
        },
    ]
}

/// The sign-in card where the page is not there.
fn sign_in() -> Vec<Told> {
    let server = serve(vec![answer(404, "")]);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.issuer.clone_from(&server.url);
    let runner = Canned(String::new());
    let context = crate::testing::context(&config, &runner);
    let provider = SignIn::new(&table("type = \"sign-in\"")).unwrap();
    let cards = provider.collect(&context).unwrap().observations;
    server.requests();
    vec![Told {
        what: "a sign-in page that is not there",
        card: the(&cards, "signin.page"),
        cause: "answers 404",
    }]
}

/// The cards of these checks that are never a warning or failed, and why.
const NEVER_TOLD: [(&str, &str); 4] = [
    (
        "version.stalwart",
        "the version a recorded start reported: OK, or Unknown",
    ),
    (
        "stalwart.api",
        "names what Stalwart did not answer: Unknown only",
    ),
    (
        "stalwart.spam",
        "shows the configured values and judges none: OK, or Unknown",
    ),
    (
        "stalwart.queue",
        "counts the queue and judges it not: OK, or Unknown",
    ),
];

#[test]
fn every_card_that_is_told_says_first_what_made_it_so() {
    let mut broken = Vec::new();
    let mut covered: BTreeSet<String> = NEVER_TOLD.iter().map(|(id, _)| (*id).to_owned()).collect();
    let ways = [stalwart(), exporter(), releases(), sign_in()];
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
        Stalwart::new(&table("type = \"stalwart\"")).unwrap().ids(),
        Prometheus::new(&table("type = \"prometheus\""))
            .unwrap()
            .ids(),
        Releases::new(&table("type = \"releases\"")).unwrap().ids(),
        SignIn::new(&table("type = \"sign-in\"")).unwrap().ids(),
    ]
    .concat()
    .into_iter()
    .collect();
    assert_eq!(covered, ids);
}
