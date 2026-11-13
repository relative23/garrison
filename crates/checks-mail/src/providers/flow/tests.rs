use garrison_testing::http::{json as answer_json, serve};
use rusqlite::Connection;
use serde_json::json;

use super::read::DAY;
use super::*;
use crate::testing::{Canned, Remembered, config, now, table};

/// One event: its type, how many seconds before the tests' clock, its span
/// and its fields.
type Event = (&'static str, i64, Option<&'static str>, Value);

fn event(kind: &'static str, ago: i64, fields: Value) -> Event {
    (kind, ago, None, fields)
}

/// The observations over a history of `events`, with Stalwart naming
/// `accounts`; `later` seconds after the tests' clock.
fn observed(
    events: &[Event],
    accounts: Option<&Value>,
    memory: &Remembered,
    later: i64,
) -> Vec<Observation> {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let path = config.database(garrison_core::config::Database::Events);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE events(seq INTEGER PRIMARY KEY, created_at INTEGER, type TEXT, span_id TEXT, fields TEXT)",
    )
    .unwrap();
    for (kind, ago, span, fields) in events {
        db.execute(
            "INSERT INTO events(created_at,type,span_id,fields) VALUES(?,?,?,?)",
            (now().as_second() - ago, kind, span, fields.to_string()),
        )
        .unwrap();
    }
    drop(db);
    let stalwart = accounts.map(|accounts| {
        serve(vec![answer_json(&json!({
            "methodResponses": [["x:Account/get", {"list": accounts}, "0"]]
        }))])
    });
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

fn of<'a>(observations: &'a [Observation], id: &str) -> &'a Observation {
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

fn rows(observation: &Observation) -> Vec<String> {
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

#[test]
fn a_milter_that_could_not_be_reached_is_a_warning_and_a_host_without_one_has_no_card() {
    let events = [
        event("milter.action-accept", 60, json!({})),
        event("milter.action-accept", 61, json!({})),
        event("milter.action-reject", 62, json!({})),
        event("milter.timeout", 63, json!({})),
        event("milter.action-connection-failure", DAY + 60, json!({})),
        event("milter.action-temp-fail", 3 * DAY, json!({})),
    ];
    let observations = observed(&events, None, &Remembered::default(), 0);
    let milter = of(&observations, "flow.milter");
    assert_eq!(
        (milter.state, milter.modules.clone()),
        (State::Warning, [ModuleId::Antivirus].into())
    );
    assert!(
        milter.findings[0].starts_with("The milter could not be reached 2 times since yesterday."),
        "{:?}",
        milter.findings
    );
    let by_day = rows(milter);
    assert_eq!(by_day[0], "2026-10-29 | 2 | 1 | 0 | 0 | 1");
    assert_eq!(by_day[3], "2026-10-26 | 0 | 0 | 0 | 1 | 0");
    // A quiet week: in order. No milter event at all: nothing to show.
    let quiet = observed(&events[..3], None, &Remembered::default(), 0);
    assert_eq!(of(&quiet, "flow.milter").state, State::Ok);
    let none = observed(&[], None, &Remembered::default(), 0);
    assert!(
        none.iter()
            .all(|observation| observation.id != "flow.milter")
    );
    let ids: Vec<&str> = none
        .iter()
        .map(|observation| observation.id.as_str())
        .collect();
    assert_eq!(ids, ["flow.authentication", "flow.spam", "flow.tls"]);
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
    let read = observed(&[], None, &memory, EVERY);
    assert_eq!(rows(of(&read, "flow.spam"))[0], "2026-10-29 | 0 | 0 | –");

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
