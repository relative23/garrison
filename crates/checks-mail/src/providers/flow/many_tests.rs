//! Stalwart's accounts as many as it has: the card by domain names the
//! domain of every mailbox among the accounts the flow reads, in pages, and
//! says how many it leaves. Stalwart gives a request for all of its
//! accounts the first 500 alone and says nothing of the rest (measured on
//! 1.1.0).

use garrison_stalwart::ids::encode_native_id;
use garrison_testing::http::{json as answer_json, serve};
use serde_json::{Value, json};

use super::read::Limits;
use super::tests::{Event, event, history, of, rows};
use super::*;
use crate::context::Deadline;
use crate::testing::objects::objects;
use crate::testing::{Canned, Receiver, table};

/// `count` accounts in Stalwart's order: number 1 is anna@a.example, number
/// 550 ben@b.example, every other one has an address of other.example.
fn accounts(count: u64) -> Vec<Value> {
    (0..count)
        .map(|number| {
            let address = match number {
                1 => "anna@a.example".to_owned(),
                550 => "ben@b.example".to_owned(),
                _ => format!("user{number}@other.example"),
            };
            json!({"id": encode_native_id(number), "emailAddress": address})
        })
        .collect()
}

/// Ham for account 1, spam for account 550.
fn mail() -> [Event; 2] {
    [
        event("message-ingest.ham", 60, json!({"accountId": 1})),
        event("message-ingest.spam", 90, json!({"accountId": 550})),
    ]
}

/// The card by domain over `mail()`, where Stalwart at `url` has the
/// accounts, read within `limits` by a run whose time ends at `deadline`.
fn by_domain_at(url: &str, limits: &Limits, deadline: Deadline) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let mut config = history(directory.path(), &Receiver::default(), &mail(), 0);
    config.deployment.stalwart_url = url.to_owned();
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".to_owned()),
        deadline,
        ..crate::testing::context(&config, &runner)
    };
    let flow = Flow::new(&table("type = \"mail-flow\"")).unwrap();
    let read = Flow::counted_within(&context, limits);
    let report = flow.cards(&context, &read).unwrap();
    of(&report.observations, "flow.spam-domains").clone()
}

/// The same where Stalwart has `count` accounts.
fn by_domain_within(count: u64, limits: &Limits, deadline: Deadline) -> Observation {
    let stalwart = objects("Account", accounts(count));
    let card = by_domain_at(&stalwart.url, limits, deadline);
    stalwart.requests();
    card
}

/// The card by domain as a collection run makes it, where Stalwart has
/// `count` accounts.
fn by_domain(count: u64) -> Observation {
    let stalwart = objects("Account", accounts(count));
    let directory = tempfile::tempdir().unwrap();
    let mut config = history(directory.path(), &Receiver::default(), &mail(), 0);
    config.deployment.stalwart_url.clone_from(&stalwart.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".to_owned()),
        ..crate::testing::context(&config, &runner)
    };
    let provider = Flow::new(&table("type = \"mail-flow\"")).unwrap();
    let observations = provider.collect(&context).unwrap().observations;
    stalwart.requests();
    of(&observations, "flow.spam-domains").clone()
}

#[test]
fn mail_to_an_account_after_the_first_500_is_counted_under_its_domain() {
    let card = by_domain(600);
    assert_eq!(
        (card.state, card.findings.clone(), rows(&card)),
        (
            State::Ok,
            Vec::<String>::new(),
            vec![
                "a.example | 1 | 0 | 0 %".to_owned(),
                "b.example | 0 | 1 | 100 %".to_owned()
            ]
        )
    );
}

/// What the card says and shows where account 550 was not read: its mail
/// under "unknown", and the card a part.
fn left(said: &str) -> (State, Vec<String>, Vec<String>) {
    (
        State::Partial,
        vec![format!(
            "Stalwart has 600 accounts; {said}, and mail to the others is counted under \
             \"unknown\"."
        )],
        vec![
            "a.example | 1 | 0 | 0 %".to_owned(),
            "unknown | 0 | 1 | 100 %".to_owned(),
        ],
    )
}

#[test]
fn accounts_after_the_first_the_flow_reads_are_counted_and_said() {
    let few = Limits {
        accounts: 100,
        ..Limits::WEEK
    };
    let card = by_domain_within(600, &few, Deadline::NONE);
    assert_eq!(
        (card.state, card.findings.clone(), rows(&card)),
        left("only the first 100 are read")
    );
}

#[test]
fn accounts_left_for_want_of_the_runs_time_are_said() {
    // The run's time is up before the second page.
    let card = by_domain_within(600, &Limits::WEEK, Deadline::within(Duration::ZERO));
    assert_eq!(
        (card.state, card.findings.clone(), rows(&card)),
        left("only 500 of them were read before the collection run's time was used up")
    );
}

#[test]
fn accounts_left_where_the_pages_gave_no_more_are_said() {
    // Stalwart counts 600 accounts, and its second page gives the first
    // page's again, as where accounts were taken out meanwhile.
    let page = answer_json(&json!({"methodResponses": [
        ["x:Account/query", {"ids": ["b"], "position": 0, "total": 600}, "0"],
        ["x:Account/get", {"list": [{"id": "b", "emailAddress": "anna@a.example"}]}, "1"]
    ]}));
    let stalwart = serve(vec![page.clone(), page]);
    let card = by_domain_at(&stalwart.url, &Limits::WEEK, Deadline::NONE);
    assert_eq!(stalwart.requests().len(), 2);
    assert_eq!(
        (card.state, card.findings.clone(), rows(&card)),
        left("only 1 of them could be read")
    );
}
