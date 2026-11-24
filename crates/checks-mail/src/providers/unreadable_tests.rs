//! A value in the event history of another type than the event receiver
//! writes, as the user who writes the history can put there, costs its
//! event alone: the checks that read the history report their cards, and
//! each card that the event would have changed says that an event was left
//! out. The places are every event the mail flow and the sending addresses
//! read, with its time and, where a check reads them, its fields changed
//! in turn to every other type.

use std::collections::BTreeMap;

use garrison_core::observations::State;
use rusqlite::Connection;
use rusqlite::types::Value as Sql;
use serde_json::{Value, json};

use super::*;
use crate::context::Provider;
use crate::testing::{Canned, Receiver, config, now, table};

/// What one card says: its state and findings.
type Card = (State, Vec<String>);

/// What a card says of the one event it left out.
const LEFT_OUT: &str = "1 event of the history could not be read and is left out.";

/// Every kind of event the two checks read, with fields as Stalwart sends
/// them, and whether a check reads its fields.
fn events() -> Vec<(&'static str, Value, bool)> {
    let account = json!({"accountId": 1});
    vec![
        ("message-ingest.ham", account.clone(), true),
        ("message-ingest.spam", account, true),
        ("spam.train-completed", json!({}), false),
        ("milter.action-accept", json!({}), false),
        ("smtp.dkim-pass", json!({}), false),
        (
            "smtp.spf-from-fail",
            json!({"from": "a@forged.example", "result": "spf.fail"}),
            true,
        ),
        (
            "smtp.dmarc-fail",
            json!({"domain": "forged.example", "result": "dmarc.fail"}),
            true,
        ),
        (
            "smtp.mail-from",
            json!({"from": "b@plain.example", "localPort": 25}),
            true,
        ),
        ("delivery.start-tls", json!({}), false),
        (
            "delivery.start-tls-unavailable",
            json!({"hostname": "mx.plain.example"}),
            true,
        ),
        (
            "queue.authenticated-message-queued",
            json!({"from": "anna@example.test", "to": ["x@example.org"], "remoteIp": "192.0.2.1"}),
            true,
        ),
        (
            "delivery.dsn-perm-fail",
            json!({"from": "anna@example.test"}),
            true,
        ),
    ]
}

/// The cards of both checks over the history of `events()`, a minute old,
/// with `changed` put in place of column `column` of event `index`.
fn cards(changed: Option<(usize, &str, &Sql)>) -> BTreeMap<String, Card> {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let path = config.database(garrison_core::config::Database::Events);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE events(seq INTEGER PRIMARY KEY, created_at INTEGER, type TEXT, span_id TEXT, \
         fields TEXT)",
    )
    .unwrap();
    for (index, (kind, fields, _)) in events().into_iter().enumerate() {
        let mut values = [
            Sql::Integer(now().as_second() - 60),
            Sql::Text(fields.to_string()),
        ];
        if let Some((at, column, value)) = &changed
            && *at == index
        {
            values[usize::from(*column == "fields")] = (*value).clone();
        }
        let [created_at, fields] = values;
        db.execute(
            "INSERT INTO events(created_at,type,span_id,fields) VALUES(?,?,?,?)",
            (created_at, kind, format!("span-{index}"), fields),
        )
        .unwrap();
    }
    Receiver::default().record(&db, now().as_second());
    drop(db);
    let runner = Canned(String::new());
    let context = crate::testing::context(&config, &runner);
    let checks: [Box<dyn Provider>; 2] = [
        Box::new(Flow::new(&table("type = \"mail-flow\"")).unwrap()),
        Box::new(Senders::new(&table("type = \"senders\"")).unwrap()),
    ];
    checks
        .iter()
        .flat_map(|check| check.collect(&context).unwrap().observations)
        .map(|card| (card.id, (card.state, card.findings)))
        .collect()
}

#[test]
fn a_value_of_another_type_in_the_history_costs_its_event_alone() {
    let whole = cards(None);
    for (id, (_, findings)) in &whole {
        assert!(
            !findings.iter().any(|finding| finding.contains("left out")),
            "{id}: {findings:?}"
        );
    }
    let times = [
        Sql::Text("yesterday".to_owned()),
        Sql::Blob(vec![0]),
        Sql::Real(f64::from(i32::try_from(now().as_second() - 60).unwrap()) - 0.5),
    ];
    let fields = [
        Sql::Blob(b"{}".to_vec()),
        Sql::Integer(7),
        Sql::Text("not JSON".to_owned()),
        Sql::Text("[1]".to_owned()),
    ];
    // Each change with the cards it made wrong: one that failed a reading,
    // changed without a word or did not say that an event was left out.
    let mut wrong: BTreeMap<String, Vec<(String, Card)>> = BTreeMap::new();
    for (index, (kind, _, fields_read)) in events().into_iter().enumerate() {
        let changes = times.iter().map(|value| ("created_at", value)).chain(
            fields
                .iter()
                .filter(|_| fields_read)
                .map(|value| ("fields", value)),
        );
        for (column, value) in changes {
            let found = cards(Some((index, column, value)));
            let mut said = false;
            for (id, card) in &found {
                let failed = card
                    .1
                    .iter()
                    .any(|finding| finding.contains("could not be read:"));
                let says = card.1.iter().any(|finding| finding == LEFT_OUT);
                said |= says;
                if failed || (whole.get(id) != Some(card) && !says) {
                    wrong
                        .entry(format!("{kind} {column} {value:?}"))
                        .or_default()
                        .push((id.clone(), card.clone()));
                }
            }
            if !said {
                wrong
                    .entry(format!("{kind} {column} {value:?}"))
                    .or_default()
                    .push(("(no card said so)".to_owned(), (State::Unknown, Vec::new())));
            }
        }
    }
    assert_eq!(wrong, BTreeMap::new());
}
