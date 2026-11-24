//! A value in the event history of another type than the event receiver
//! writes, as the user who writes the history can put there, costs its
//! event alone: an event whose time cannot be read is out of every reading,
//! so each card is that of the history without it; one whose fields cannot
//! be read stays in the counts by day, which need no fields, so each card is
//! that of the history with it or without it. Each card that would have
//! counted it says that an event was left out, and no reading fails. The places are
//! every event the mail flow and the sending addresses read, among them a
//! deferral in a session of its own, with its time and, where a check reads
//! them, its fields changed in turn to every other type; the sending
//! addresses are read whole and once more with a limit that leaves the
//! oldest submission unread. Beside them, one event of every type the
//! receiver records, each value changed for all of them at once, fails no
//! reading.

use std::collections::BTreeMap;

use garrison_core::observations::State;
use garrison_ingest::event_type::EventType;
use rusqlite::Connection;
use rusqlite::types::Value as Sql;
use serde_json::{Value, json};

use super::*;
use crate::context::Provider;
use crate::testing::{Canned, Receiver, config, now, table};

/// What one card says, and what it shows.
#[derive(Clone, Debug, PartialEq)]
struct Card {
    state: State,
    findings: Vec<String>,
    fields: Value,
    table: Value,
}

/// What a card says of the one event it left out.
const LEFT_OUT: &str = "1 event of the history could not be read and is left out.";

/// Every kind of event the two checks read, with fields as Stalwart sends
/// them, and whether a check reads its fields. Each event is a session of
/// its own; two submissions, so that a limit of one leaves the first.
fn events() -> Vec<(&'static str, Value, bool)> {
    let account = json!({"accountId": 1});
    let submission =
        json!({"from": "anna@example.test", "to": ["x@example.org"], "remoteIp": "192.0.2.1"});
    vec![
        ("message-ingest.ham", account.clone(), true),
        ("message-ingest.spam", account, true),
        ("spam.train-completed", json!({}), false),
        ("milter.action-accept", json!({}), false),
        ("milter.action-temp-fail", json!({}), false),
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
            submission.clone(),
            true,
        ),
        ("queue.authenticated-message-queued", submission, true),
        (
            "delivery.dsn-perm-fail",
            json!({"from": "anna@example.test"}),
            true,
        ),
    ]
}

/// The column of an event, its time or its fields, and the value put there.
type Change = (&'static str, Sql);

/// The cards of both checks over the history of `events`, a minute old,
/// with `changed` put in place of a column of each event it names; the
/// sending addresses read at most `most` submissions where it says so.
fn cards(
    events: &[(&str, Value)],
    changed: &dyn Fn(usize) -> Option<Change>,
    most: Option<usize>,
) -> BTreeMap<String, Card> {
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
    for (index, (kind, fields)) in events.iter().enumerate() {
        let mut values = [
            Sql::Integer(now().as_second() - 60),
            Sql::Text(fields.to_string()),
        ];
        if let Some((column, value)) = changed(index) {
            values[usize::from(column == "fields")] = value;
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
    let senders = Senders::new(&table("type = \"senders\"")).unwrap();
    let checks: [Box<dyn Provider>; 2] = [
        Box::new(Flow::new(&table("type = \"mail-flow\"")).unwrap()),
        Box::new(match most {
            Some(most) => senders.reading_at_most(most),
            None => senders,
        }),
    ];
    checks
        .iter()
        .flat_map(|check| check.collect(&context).unwrap().observations)
        .map(|card| {
            let shown = Card {
                state: card.state,
                findings: card.findings,
                fields: json!(card.fields),
                table: json!(card.table),
            };
            (card.id, shown)
        })
        .collect()
}

/// Whether a card failed its reading.
fn failed(card: &Card) -> bool {
    card.findings
        .iter()
        .any(|finding| finding.contains("could not be read:"))
}

/// Whether a card says that it left the event out.
fn says(card: &Card) -> bool {
    card.findings.iter().any(|finding| finding == LEFT_OUT)
}

/// Whether `found` is a card of the other histories' `bases`, each part of
/// it as one of them has it: its fields, its table, its findings but the
/// one that it left the event out, and its state, Partial where it says so
/// for an otherwise Ok.
fn like(found: &Card, bases: &[Option<&Card>]) -> bool {
    let bases: Vec<&Card> = bases.iter().flatten().copied().collect();
    let rest: Vec<&String> = found
        .findings
        .iter()
        .filter(|finding| *finding != LEFT_OUT)
        .collect();
    let state = |base: &Card| {
        if says(found) && base.state == State::Ok {
            State::Partial
        } else {
            base.state
        }
    };
    !bases.is_empty()
        && bases.iter().any(|base| found.fields == base.fields)
        && bases.iter().any(|base| found.table == base.table)
        && bases
            .iter()
            .any(|base| rest == base.findings.iter().collect::<Vec<_>>())
        && bases.iter().any(|base| found.state == state(base))
}

/// The values a time is changed to, and the values fields are.
fn changes() -> (Vec<Sql>, Vec<Sql>) {
    let times = vec![
        Sql::Text("yesterday".to_owned()),
        Sql::Blob(vec![0]),
        Sql::Real(f64::from(i32::try_from(now().as_second() - 60).unwrap()) - 0.5),
    ];
    let fields = vec![
        Sql::Blob(b"{}".to_vec()),
        Sql::Integer(7),
        Sql::Text("not JSON".to_owned()),
        Sql::Text("[1]".to_owned()),
    ];
    (times, fields)
}

#[test]
fn a_value_of_another_type_in_the_history_costs_its_event_alone() {
    let listed = events();
    let history: Vec<(&str, Value)> = listed
        .iter()
        .map(|(kind, fields, _)| (*kind, fields.clone()))
        .collect();
    let whole = cards(&history, &|_| None, None);
    for (id, card) in &whole {
        assert!(
            !card
                .findings
                .iter()
                .any(|finding| finding.contains("left out")),
            "{id}: {card:?}"
        );
    }
    let (times, fields) = changes();
    // Each change with the cards it made wrong: one that failed a reading,
    // differs from the history without the event, or no card that said it.
    let mut wrong: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (index, (kind, _, fields_read)) in listed.iter().enumerate() {
        let mut without_it = history.clone();
        without_it.remove(index);
        let without = cards(&without_it, &|_| None, None);
        let column_changes = times.iter().map(|value| ("created_at", value)).chain(
            fields
                .iter()
                .filter(|_| *fields_read)
                .map(|value| ("fields", value)),
        );
        for (column, value) in column_changes {
            let name = format!("{index} {kind} {column} {value:?}");
            let change = |at: usize| (at == index).then(|| (column, value.clone()));
            let found = cards(&history, &change, None);
            let bases = if column == "created_at" {
                vec![&without]
            } else {
                vec![&whole, &without]
            };
            let mut said = false;
            for (id, card) in &found {
                said |= says(card);
                let of: Vec<Option<&Card>> = bases.iter().map(|base| base.get(id)).collect();
                if failed(card) || !like(card, &of) {
                    wrong
                        .entry(name.clone())
                        .or_default()
                        .push(format!("{id}: {card:?}"));
                }
            }
            if !bases.iter().any(|base| base.keys().eq(found.keys())) {
                let ids: Vec<&String> = found.keys().collect();
                wrong
                    .entry(name.clone())
                    .or_default()
                    .push(format!("other cards: {ids:?}"));
            }
            if !said {
                wrong
                    .entry(name.clone())
                    .or_default()
                    .push("no card said so".to_owned());
            }
            // The sending addresses with a limit that leaves the first
            // submission unread: no reading fails.
            for (id, card) in cards(&history, &change, Some(1)) {
                if failed(&card) {
                    wrong
                        .entry(format!("{name}, cut"))
                        .or_default()
                        .push(format!("{id}: {card:?}"));
                }
            }
        }
    }
    assert_eq!(wrong, BTreeMap::new());
}

#[test]
fn a_value_of_another_type_in_an_event_of_any_kind_fails_no_reading() {
    let history: Vec<(&str, Value)> = EventType::ALL
        .iter()
        .map(|kind| (kind.as_str(), json!({})))
        .chain(events().into_iter().map(|(kind, fields, _)| (kind, fields)))
        .collect();
    let (times, fields) = changes();
    let mut wrong = Vec::new();
    for (column, value) in times
        .into_iter()
        .map(|value| ("created_at", value))
        .chain(fields.into_iter().map(|value| ("fields", value)))
    {
        let change = |_: usize| Some((column, value.clone()));
        for most in [None, Some(1)] {
            for (id, card) in cards(&history, &change, most) {
                if failed(&card) {
                    wrong.push(format!("{column} {value:?}, {most:?}: {id} {card:?}"));
                }
            }
        }
    }
    assert_eq!(wrong, Vec::<String>::new());
}
