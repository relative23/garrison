use serde_json::json;

use super::*;
use crate::testing::{Canned, Remembered, config, now, table};

/// One event of the history: its type, how long before the tests' clock it
/// came, and its fields.
type Event = (&'static str, i64, Value);

/// A message `account` handed in `ago` seconds ago to `count` recipients.
fn queued(account: &str, ago: i64, count: usize, address: &str) -> Event {
    let to: Vec<String> = (0..count)
        .map(|index| format!("r{index}@example.org"))
        .collect();
    (
        QUEUED,
        ago,
        json!({"from": account, "to": to, "remoteIp": address}),
    )
}

fn bounced(account: &str, ago: i64) -> Event {
    (
        BOUNCED,
        ago,
        json!({"from": account, "to": "gone@example.org"}),
    )
}

/// The observation at `later` seconds after the tests' clock, over a
/// history of `events` that began `days` days ago.
fn observed(
    provider: &Senders,
    events: &[Event],
    days: i64,
    memory: &Remembered,
    later: i64,
) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let path = config.database(garrison_core::config::Database::Events);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE events(seq INTEGER PRIMARY KEY, created_at INTEGER, type TEXT, fields TEXT)",
    )
    .unwrap();
    let insert = |kind: &str, ago: i64, fields: &Value| {
        db.execute(
            "INSERT INTO events(created_at,type,fields) VALUES(?,?,?)",
            (now().as_second() - ago, kind, fields.to_string()),
        )
        .unwrap();
    };
    insert("server.startup", days * DAY, &json!({}));
    for (kind, ago, fields) in events {
        insert(kind, *ago, fields);
    }
    drop(db);
    let runner = Canned(String::new());
    let context = Context {
        now: time::Timestamp::from_second(now().as_second() + later).unwrap(),
        memory,
        ..crate::testing::context(&config, &runner)
    };
    provider.collect(&context).unwrap().observations.remove(0)
}

fn provider() -> Senders {
    Senders::new(&table("type = \"senders\"")).unwrap()
}

fn row<'a>(observation: &'a Observation, account: &str) -> &'a Vec<Value> {
    let rows = &observation.table.as_ref().unwrap().rows;
    rows.iter().find(|row| row[0] == account).unwrap()
}

/// Two weeks in which `account` sent to `a_day` recipients each day.
fn usual(account: &str, a_day: usize) -> Vec<Event> {
    (1..=USUAL_DAYS)
        .map(|day| queued(account, day * DAY + 3600, a_day, "192.0.2.1"))
        .collect()
}

#[test]
fn an_account_far_above_its_own_usual_volume_is_a_warning() {
    let mut events = usual("anna@example.test", 20);
    events.extend(usual("news@example.test", 400));
    // Today anna sends to 300, the newsletter to its usual 400.
    events.extend((0..3).map(|hour| {
        queued(
            "Anna@Example.test",
            hour * 7200 + 60,
            100 - 1,
            "198.51.100.7",
        )
    }));
    events.push(queued("anna@example.test", 80_000, 3, "192.0.2.1"));
    events
        .extend((0..8).map(|hour| queued("news@example.test", hour * 7200 + 60, 50, "192.0.2.9")));
    let observation = observed(&provider(), &events, 20, &Remembered::default(), 0);
    assert_eq!(observation.state, State::Warning);
    assert_eq!(
        observation.findings,
        ["anna@example.test: 300 recipients in 24 hours, where 20 a day is usual."]
    );
    assert_eq!(observation.id, "senders.accounts");
    assert_eq!(observation.modules, [ModuleId::Attacks].into());
    // The unusual account comes first, then the busiest.
    let rows = &observation.table.as_ref().unwrap().rows;
    assert_eq!(
        rows[0],
        json!(["anna@example.test", 4, 300, 20, 99, 0, 2])
            .as_array()
            .unwrap()
            .clone()
    );
    assert_eq!(
        rows[1],
        json!(["news@example.test", 8, 400, 400, 50, 0, 1])
            .as_array()
            .unwrap()
            .clone()
    );
}

#[test]
fn a_burst_and_a_share_of_bounces_are_warnings_of_their_own() {
    let mut events = usual("shop@example.test", 500);
    // A usual day in sum, but 150 of it within one hour, and 60 bounces.
    events.push(queued("shop@example.test", 600, 150, "192.0.2.1"));
    events.push(queued("shop@example.test", 50_000, 100, "192.0.2.1"));
    events.extend((0..60).map(|index| bounced("shop@example.test", 500 - index)));
    // Bounces of mail no account handed in today count for nobody.
    events.push(bounced("ghost@example.test", 100));
    events.push((
        "delivery.dsn-perm-fail",
        90,
        json!({"from": "<>", "to": "x@example.org"}),
    ));
    let observation = observed(&provider(), &events, 20, &Remembered::default(), 0);
    assert_eq!(
        observation.findings,
        ["shop@example.test: 150 recipients within one hour; 60 of 250 recipients bounced."]
    );
    assert_eq!(row(&observation, "shop@example.test")[5], 60);
    assert_eq!(observation.table.as_ref().unwrap().rows.len(), 1);
}

#[test]
fn without_three_days_of_history_no_usual_volume_is_named() {
    // The history began two days ago: 300 recipients cannot be held against anything.
    let events = [
        queued("anna@example.test", 60, 99, "192.0.2.1"),
        queued("anna@example.test", 90_000, 5, "192.0.2.1"),
    ];
    let observation = observed(&provider(), &events, 2, &Remembered::default(), 0);
    assert_eq!(observation.state, State::Ok);
    assert_eq!(row(&observation, "anna@example.test")[3], Value::Null);
    // A quiet account and an empty history are in order too.
    let quiet = observed(&provider(), &[], 20, &Remembered::default(), 0);
    assert_eq!((quiet.state, quiet.findings.len()), (State::Ok, 0));
}

#[test]
fn the_history_is_read_every_ten_minutes_and_its_absence_is_unknown() {
    let memory = Remembered::default();
    let busy = [queued("anna@example.test", 60, 120, "192.0.2.1")];
    let first = observed(&provider(), &busy, 20, &memory, 0);
    assert_eq!(
        first.findings,
        [
            "anna@example.test: 120 recipients in 24 hours from an account that sent nothing in the \
             14 days before; 120 recipients within one hour."
        ]
    );
    // Nine minutes later the kept reading answers, whatever the history holds now.
    let kept = observed(&provider(), &[], 20, &memory, EVERY - 1);
    assert_eq!(kept.findings, first.findings);
    let read = observed(&provider(), &[], 20, &memory, EVERY);
    assert_eq!(read.state, State::Ok);

    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = crate::testing::context(&config, &runner);
    let missing = provider().collect(&context).unwrap().observations.remove(0);
    assert_eq!(missing.state, State::Unknown);
    assert_eq!(
        missing.findings,
        ["The sending accounts are not known: no events are recorded yet."]
    );
}

#[test]
fn the_limits_can_be_set_and_are_checked() {
    let strict = Senders::new(&table(
        "type = \"senders\"\nburst = 10\nmodules = [\"alerts\"]",
    ))
    .unwrap();
    let events = [queued("anna@example.test", 60, 10, "192.0.2.1")];
    let observation = observed(&strict, &events, 20, &Remembered::default(), 0);
    assert_eq!(observation.state, State::Warning);
    assert_eq!(observation.modules, [ModuleId::Alerts].into());
    for wrong in [
        "factor = 0",
        "burst = \"many\"",
        "bounces = -1",
        "limit = 5",
    ] {
        assert!(
            Senders::new(&table(&format!("type = \"senders\"\n{wrong}"))).is_err(),
            "{wrong}"
        );
    }
}
