//! The accounts' pages where one of them fails or is refused: the pages
//! read stand, and the cards name the method that failed.

use garrison_testing::http::{answer, json as answer_json};
use serde_json::{Value, json};

use super::limit_tests::cards;
use super::*;

/// What Stalwart answers the check's first request where every call
/// answers.
fn first() -> String {
    answer_json(&json!({"methodResponses": [
        ["x:SpamSettings/get", {"list": [{"enable": true}]}, "0"],
        ["x:SpamClassifier/get", {"list": [{}]}, "1"],
        ["x:SpamRule/query", {"total": 3}, "2"],
        ["x:SpamTrainingSample/query", {"total": 0}, "3"],
        ["x:QueuedMessage/query", {"total": 1}, "4"],
        ["x:MtaMilter/get", {"list": []}, "5"],
    ]}))
}

/// The first page of 600 accounts: 500 user accounts of which the one at
/// `full` uses 95 % of its quota.
fn first_page(full: usize) -> String {
    let ids: Vec<String> = (0..500).map(|number| format!("a{number}")).collect();
    let list: Vec<Value> = (0..500)
        .map(|number| {
            let quota = if number == full {
                1_103_764
            } else {
                104_857_600
            };
            json!({"id": format!("a{number}"), "@type": "User",
                   "emailAddress": format!("user{number}@example.test"),
                   "usedDiskQuota": 1_048_576, "quotas": {"maxDiskQuota": quota}})
        })
        .collect();
    answer_json(&json!({"methodResponses": [
        ["x:Account/query", {"ids": ids, "position": 0, "total": 600}, "0"],
        ["x:Account/get", {"list": list, "notFound": []}, "1"],
    ]}))
}

fn card(cards: &[Observation], id: &str) -> Observation {
    cards.iter().find(|card| card.id == id).cloned().unwrap()
}

/// A later page that Stalwart does not complete takes nothing of the pages
/// before it: a full mailbox among them is warned of, the card says how
/// many accounts were read and why not the rest, and the Management API
/// card names the request that failed.
#[test]
fn a_later_page_of_accounts_that_fails_keeps_the_pages_read() {
    let cards = cards(vec![first(), first_page(10), answer(503, "")]);
    let mailboxes = card(&cards, "stalwart.mailboxes");
    assert_eq!(
        (mailboxes.state, mailboxes.findings),
        (
            State::Warning,
            vec![
                "user10@example.test uses 90 % or more of its quota.".to_owned(),
                "Stalwart has 600 accounts; 500 of them could be read: Stalwart unavailable."
                    .to_owned(),
            ]
        )
    );
    let api = card(&cards, "stalwart.api");
    assert_eq!(
        (api.state, api.findings),
        (
            State::Unknown,
            vec!["Not readable (x:Account/query): Stalwart unavailable.".to_owned()]
        )
    );
}

/// A key that may query the accounts and not get them is refused the get:
/// the Management API card names that method, not the query that answered.
#[test]
fn a_refused_get_of_the_accounts_is_named_as_the_get() {
    let refused = answer_json(&json!({"methodResponses": [
        ["x:Account/query", {"ids": ["a0"], "position": 0, "total": 1}, "0"],
        ["error", {"type": "forbidden"}, "1"],
    ]}));
    let cards = cards(vec![first(), refused]);
    assert_eq!(
        card(&cards, "stalwart.api").findings,
        [
            "Not readable: access denied to x:Account/get; run `garrison stalwart setup` again, \
             which gives the collector's API key the permissions it needs."
        ]
    );
}
