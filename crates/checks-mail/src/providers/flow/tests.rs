use garrison_core::time;
use rusqlite::Connection;
use serde_json::{Value, json};

use super::read::DAY;
use super::*;
use crate::testing::objects::objects;
use crate::testing::{Canned, Receiver, Remembered, assert_dated, config, now, table};

/// One event: its type, how many seconds before the tests' clock, its span
/// and its fields.
pub(in crate::providers) type Event = (&'static str, i64, Option<&'static str>, Value);

pub(in crate::providers) fn event(kind: &'static str, ago: i64, fields: Value) -> Event {
    (kind, ago, None, fields)
}

/// The observations over a history of `events`, with Stalwart naming
/// `accounts`; `later` seconds after the tests' clock.
pub(in crate::providers) fn observed(
    events: &[Event],
    accounts: Option<&Value>,
    memory: &Remembered,
    later: i64,
) -> Vec<Observation> {
    observed_from(&Receiver::default(), events, accounts, memory, later)
}

/// The same over a history whose receiver recorded `receiver` about itself.
pub(super) fn observed_from(
    receiver: &Receiver,
    events: &[Event],
    accounts: Option<&Value>,
    memory: &Remembered,
    later: i64,
) -> Vec<Observation> {
    let directory = tempfile::tempdir().unwrap();
    let mut config = history(directory.path(), receiver, events, later);
    let stalwart =
        accounts.map(|accounts| objects("Account", accounts.as_array().unwrap().clone()));
    if let Some(stalwart) = &stalwart {
        config.deployment.stalwart_url.clone_from(&stalwart.url);
    }
    let runner = Canned(String::new());
    let context = Context {
        now: time::Timestamp::from_second(now().as_second() + later).unwrap(),
        memory,
        native_key: stalwart.as_ref().map(|_| "key".to_owned()),
        ..crate::testing::context(&config, &runner)
    };
    let provider = Flow::new(&table("type = \"mail-flow\"")).unwrap();
    let observations = provider.collect(&context).unwrap().observations;
    if let Some(stalwart) = stalwart {
        stalwart.requests();
    }
    observations
}

/// The configuration of a test in `directory`, whose event history holds
/// `events` and what `receiver` recorded about itself `later` seconds after
/// the tests' clock.
pub(super) fn history(
    directory: &std::path::Path,
    receiver: &Receiver,
    events: &[Event],
    later: i64,
) -> garrison_core::config::Config {
    let config = config(directory);
    let path = config.database(garrison_core::config::Database::Events);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE events(seq INTEGER PRIMARY KEY, created_at INTEGER, type TEXT, span_id TEXT, fields TEXT)",
    )
    .unwrap();
    db.execute_batch("BEGIN").unwrap();
    for (kind, ago, span, fields) in events {
        db.execute(
            "INSERT INTO events(created_at,type,span_id,fields) VALUES(?,?,?,?)",
            (now().as_second() - ago, kind, span, fields.to_string()),
        )
        .unwrap();
    }
    db.execute_batch("COMMIT").unwrap();
    receiver.record(&db, now().as_second() + later);
    config
}

pub(in crate::providers) fn of<'a>(observations: &'a [Observation], id: &str) -> &'a Observation {
    observations
        .iter()
        .find(|observation| observation.id == id)
        .unwrap_or_else(|| {
            panic!(
                "no {id} among {:?}",
                observations.iter().map(|o| &o.id).collect::<Vec<_>>()
            )
        })
}

pub(super) fn rows(observation: &Observation) -> Vec<String> {
    let table = observation.table.as_ref().unwrap();
    table
        .rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|cell| {
                    cell.as_str()
                        .map_or_else(|| cell.to_string(), str::to_owned)
                })
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .collect()
}

fn field<'a>(observation: &'a Observation, label: &str) -> &'a Value {
    &observation
        .fields
        .iter()
        .find(|field| field.label == label)
        .unwrap()
        .value
}

#[test]
fn spam_and_ham_are_counted_by_day_and_by_the_domain_of_the_mailbox() {
    let mut events = Vec::new();
    // Today: three ham and one spam for account 1, one spam for account 33.
    for _ in 0..3 {
        events.push(event("message-ingest.ham", 60, json!({"accountId": 1})));
    }
    events.push(event("message-ingest.spam", 90, json!({"accountId": 1})));
    events.push(event("message-ingest.spam", 120, json!({"accountId": 33})));
    // Two days ago one ham, and a training run; eight days ago is out of the week.
    events.push(event(
        "message-ingest.ham",
        2 * DAY,
        json!({"accountId": 99}),
    ));
    events.push(event("spam.train-completed", 2 * DAY, json!({})));
    events.push(event(
        "message-ingest.spam",
        8 * DAY,
        json!({"accountId": 1}),
    ));
    let accounts = json!([
        {"id": "b", "emailAddress": "anna@Example.Test"},
        {"id": "bb", "emailAddress": "ben@other.test"},
        {"id": "c", "emailAddress": null},
    ]);
    let observations = observed(&events, Some(&accounts), &Remembered::default(), 0);
    let spam = of(&observations, "flow.spam");
    assert_eq!(
        (spam.state, spam.modules.clone()),
        (State::Ok, [ModuleId::Spam].into())
    );
    let by_day = rows(spam);
    assert_eq!(by_day.len(), 7);
    // The newest day first: the tests' clock is 2026-10-29 12:00 UTC.
    assert_eq!(by_day[0], "2026-10-29 | 3 | 2 | 40 %");
    assert_eq!(by_day[1], "2026-10-28 | 0 | 0 | –");
    assert_eq!(by_day[2], "2026-10-27 | 1 | 0 | 0 %");
    assert_eq!(field(spam, "Training runs in these days"), &json!(1));
    assert_eq!(
        rows(of(&observations, "flow.spam-domains")),
        [
            "example.test | 3 | 1 | 25 %",
            "other.test | 0 | 1 | 100 %",
            "unknown | 1 | 0 | 0 %",
        ]
    );
}

#[test]
fn the_checks_of_senders_are_summed_and_only_real_failures_name_a_domain() {
    let events = [
        event("smtp.spf-from-pass", 60, json!({"from": "a@good.example"})),
        event(
            "smtp.spf-from-fail",
            61,
            json!({"from": "x@Forged.Example", "result": "spf.fail"}),
        ),
        event(
            "smtp.spf-from-fail",
            62,
            json!({"from": "y@forged.example", "result": "spf.soft-fail"}),
        ),
        // No record to check against: not passed, but nobody's failure.
        event(
            "smtp.spf-from-fail",
            63,
            json!({"from": "z@norecord.example", "result": "spf.none"}),
        ),
        event(
            "smtp.dmarc-fail",
            64,
            json!({"domain": "forged.example", "result": "dmarc.fail", "policy": "reject"}),
        ),
        event(
            "smtp.dmarc-fail",
            65,
            json!({"domain": "norecord.example", "result": "dmarc.none"}),
        ),
        event("smtp.dmarc-pass", 66, json!({"domain": "good.example"})),
        event("smtp.dkim-pass", 67, json!({})),
        event("smtp.dkim-pass", 68, json!({})),
        event("smtp.dkim-fail", 69, json!({"result": "none"})),
        // As a release before the outcome was kept stored it.
        event("smtp.dmarc-fail", DAY, json!({"domain": "old.example"})),
    ];
    let observations = observed(&events, None, &Remembered::default(), 0);
    assert_eq!(
        rows(of(&observations, "flow.authentication")),
        [
            "SPF of the greeting (EHLO) | 0 | 0 | –",
            "SPF of the sender | 1 | 3 | 25 %",
            "DKIM | 2 | 1 | 67 %",
            "DMARC | 1 | 3 | 25 %",
            "ARC | 0 | 0 | –",
            "Reverse name | 0 | 0 | –",
        ]
    );
    assert_eq!(
        rows(of(&observations, "flow.failing-senders")),
        ["forged.example | 2 | 1", "old.example | 0 | 1"]
    );
}

#[test]
fn mail_without_tls_is_counted_in_both_directions_with_who_it_was() {
    let mail = |ago: i64, span: &'static str, from: &str, port: i64| -> Event {
        (
            "smtp.mail-from",
            ago,
            Some(span),
            json!({"from": from, "localPort": port}),
        )
    };
    let events = [
        mail(60, "1", "a@secure.example", 25),
        ("smtp.start-tls", 61, Some("1"), json!({})),
        mail(70, "2", "b@plain.example", 25),
        mail(80, "3", "c@plain.example", 25),
        // Submission with TLS from the first byte is not a matter of STARTTLS.
        mail(90, "4", "anna@example.test", 465),
        event(
            "delivery.start-tls",
            100,
            json!({"hostname": "mx.good.example"}),
        ),
        event(
            "delivery.start-tls",
            101,
            json!({"hostname": "mx.good.example"}),
        ),
        event(
            "delivery.start-tls",
            102,
            json!({"hostname": "mx.good.example"}),
        ),
        event(
            "delivery.start-tls-unavailable",
            103,
            json!({"hostname": "MX.Old.Example"}),
        ),
    ];
    let observations = observed(&events, None, &Remembered::default(), 0);
    let tls = of(&observations, "flow.tls");
    assert_eq!(tls.modules, [ModuleId::DnsTls].into());
    assert_eq!(field(tls, "Incoming with TLS"), &json!(1));
    assert_eq!(field(tls, "Incoming without TLS"), &json!(2));
    assert_eq!(field(tls, "Incoming share with TLS"), &json!("33 %"));
    assert_eq!(field(tls, "Outgoing share with TLS"), &json!("75 %"));
    assert_eq!(
        rows(tls),
        [
            "incoming | plain.example | 2",
            "outgoing | mx.old.example | 1"
        ]
    );
}

/// A kept reading of another shape, as a damaged or hand-edited status
/// database holds it, is read anew rather than shown.
#[test]
fn a_kept_week_whose_counts_miss_days_is_read_anew() {
    use crate::context::Memory;
    let ham = [event("message-ingest.ham", 60, json!({"accountId": 1}))];
    let memory = Remembered::default();
    observed(&ham, None, &memory, 0);
    let mut kept: Value = serde_json::from_str(&memory.recall(MEMORY).unwrap()).unwrap();
    kept["week"]["counts"]["message-ingest.ham"] = json!([1]);
    memory.keep(MEMORY, &kept.to_string());
    let again = observed(&ham, None, &memory, 60);
    assert_eq!(
        rows(of(&again, "flow.spam"))[..2],
        ["2026-10-29 | 1 | 0 | 0 %", "2026-10-28 | 0 | 0 | –"]
    );
}

#[test]
fn the_history_is_read_every_ten_minutes_and_its_absence_is_unknown() {
    let memory = Remembered::default();
    let first = observed(
        &[event("message-ingest.ham", 60, json!({"accountId": 1}))],
        None,
        &memory,
        0,
    );
    assert_eq!(rows(of(&first, "flow.spam"))[0], "2026-10-29 | 1 | 0 | 0 %");
    let kept = observed(&[], None, &memory, EVERY - 1);
    assert_eq!(rows(of(&kept, "flow.spam"))[0], "2026-10-29 | 1 | 0 | 0 %");
    // Every card is as old as the reading, not as the run that repeats it.
    assert_eq!(kept.len(), 4);
    for card in &kept {
        assert_dated(card, 0, EVERY);
    }
    let read = observed(&[], None, &memory, EVERY);
    assert_eq!(rows(of(&read, "flow.spam"))[0], "2026-10-29 | 0 | 0 | –");
    assert_dated(of(&read, "flow.spam"), EVERY, EVERY);

    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = crate::testing::context(&config, &runner);
    let provider = Flow::new(&table("type = \"mail-flow\"\nchecks = [\"spam\", \"tls\"]")).unwrap();
    let missing = provider.collect(&context).unwrap().observations;
    assert_eq!(missing.len(), 2);
    for observation in &missing {
        assert_eq!(observation.state, State::Unknown);
        assert_eq!(
            observation.findings,
            ["Nothing could be counted: no events are recorded yet."]
        );
    }
    for wrong in [
        "checks = []",
        "checks = [\"weather\"]",
        "checks = [\"tls\", \"tls\"]",
        "days = 3",
    ] {
        assert!(
            Flow::new(&table(&format!("type = \"mail-flow\"\n{wrong}"))).is_err(),
            "{wrong}"
        );
    }
}
