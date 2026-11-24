//! Stalwart's accounts as many as it has: the mailbox storage reads up to
//! `max_accounts` of them in pages, and says how many it left. Stalwart
//! gives a request for all of its accounts the first 500 alone (measured on
//! 1.2.0), so a full mailbox after them was never seen.

use serde_json::{Value, json};

use super::*;
use crate::testing::objects::objects;
use crate::testing::{Canned, config, table};

/// `count` user accounts of 1 MiB each, of which the one at `full` uses 95 %
/// of its quota and the others 1 %.
fn accounts(count: usize, full: usize) -> Vec<Value> {
    (0..count)
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
        .collect()
}

/// The mailbox storage card where Stalwart has `accounts`, of a check with
/// `options`.
fn mailbox_storage(accounts: Vec<Value>, options: &str) -> Observation {
    let stalwart = objects("Account", accounts);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&stalwart.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        ..crate::testing::context(&config, &runner)
    };
    let provider = Stalwart::new(&table(&format!("type = \"stalwart\"\n{options}"))).unwrap();
    let cards = provider.collect(&context).unwrap().observations;
    stalwart.requests();
    cards
        .into_iter()
        .find(|card| card.id == "stalwart.mailboxes")
        .unwrap()
}

fn field(card: &Observation, label: &str) -> Value {
    card.fields
        .iter()
        .find(|field| field.label == label)
        .unwrap()
        .value
        .clone()
}

#[test]
fn a_full_mailbox_after_the_first_500_accounts_is_found() {
    let card = mailbox_storage(accounts(600, 550), "");
    assert_eq!(
        (card.state, card.findings.clone()),
        (
            State::Warning,
            vec!["user550@example.test uses 90 % or more of its quota.".to_owned()]
        )
    );
    assert_eq!(field(&card, "User accounts"), json!(600));
}

#[test]
fn accounts_after_the_first_max_accounts_are_counted_and_named() {
    let card = mailbox_storage(accounts(600, 550), "max_accounts = 100");
    assert_eq!(
        (card.state, card.findings.clone()),
        (
            State::Partial,
            vec![
                "Stalwart has 600 accounts; only the first 100 are read (`max_accounts`)."
                    .to_owned()
            ]
        )
    );
    assert_eq!(field(&card, "User accounts"), json!(100));
}

/// The first `max_accounts` are the oldest, as earlier releases read them:
/// the oldest account's full mailbox is warned of, and the account made
/// after the first `max_accounts` is the one left out.
#[test]
fn the_oldest_accounts_are_read_and_a_newer_one_is_left_out() {
    let card = mailbox_storage(accounts(101, 0), "max_accounts = 100");
    assert_eq!(
        (card.state, card.findings.clone()),
        (
            State::Warning,
            vec![
                "user0@example.test uses 90 % or more of its quota.".to_owned(),
                "Stalwart has 101 accounts; only the first 100 are read (`max_accounts`)."
                    .to_owned()
            ]
        )
    );
    let rows = &card.table.as_ref().unwrap().rows;
    assert!(
        rows.iter()
            .all(|row| row[0] != json!("user100@example.test"))
    );
}
