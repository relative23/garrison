use rusqlite::Connection;
use serde_json::{Value, json};

use garrison_core::time;

use super::*;
use crate::testing::{Canned, Receiver, Remembered, assert_dated, config, now, table};

/// One event of the history: its type, how long before the tests' clock it
/// came, and its fields.
pub(in crate::providers) type Event = (&'static str, i64, Value);

/// A message handed in under the address `sender` `ago` seconds ago to
/// `count` recipients, from the IP address `client`.
pub(in crate::providers) fn queued(sender: &str, ago: i64, count: usize, client: &str) -> Event {
    let to: Vec<String> = (0..count)
        .map(|index| format!("r{index}@example.org"))
        .collect();
    (
        QUEUED,
        ago,
        json!({"from": sender, "to": to, "remoteIp": client}),
    )
}

fn bounced(sender: &str, ago: i64) -> Event {
    (
        BOUNCED,
        ago,
        json!({"from": sender, "to": "gone@example.org"}),
    )
}

/// The observation at `later` seconds after the tests' clock, over a
/// history of `events` that began `days` days ago.
pub(in crate::providers) fn observed(
    provider: &Senders,
    events: &[Event],
    days: i64,
    memory: &Remembered,
    later: i64,
) -> Observation {
    let receiver = Receiver::default();
    observed_from(&receiver, provider, events, days, memory, later)
}

/// The same over a history whose receiver recorded `receiver` about itself.
fn observed_from(
    receiver: &Receiver,
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
    receiver.record(&db, now().as_second() + later);
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

fn row<'a>(observation: &'a Observation, sender: &str) -> &'a Vec<Value> {
    let rows = &observation.table.as_ref().unwrap().rows;
    rows.iter().find(|row| row[0] == sender).unwrap()
}

/// Two weeks in which `sender` sent to `a_day` recipients each day.
fn usual(sender: &str, a_day: usize) -> Vec<Event> {
    (1..=USUAL_DAYS)
        .map(|day| queued(sender, day * DAY + 3600, a_day, "192.0.2.1"))
        .collect()
}

#[test]
fn an_address_far_above_its_own_usual_volume_is_a_warning() {
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
    // The unusual address comes first, then the busiest.
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
    // Bounces of mail nobody handed in today count for nobody.
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
    // A quiet address and an empty history are in order too.
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
            "anna@example.test: 120 recipients in 24 hours from an address that sent nothing in the \
             14 days before; 120 recipients within one hour."
        ]
    );
    // Nine minutes later the kept reading answers, whatever the history holds now.
    let kept = observed(&provider(), &[], 20, &memory, EVERY - 1);
    assert_eq!(kept.findings, first.findings);
    // The card is as old as the reading, not as the run that repeats it.
    assert_dated(&kept, 0, EVERY);
    let read = observed(&provider(), &[], 20, &memory, EVERY);
    assert_eq!(read.state, State::Ok);
    assert_dated(&read, EVERY, EVERY);

    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = crate::testing::context(&config, &runner);
    let missing = provider().collect(&context).unwrap().observations.remove(0);
    assert_eq!(missing.state, State::Unknown);
    assert_eq!(
        missing.findings,
        ["The sending addresses are not known: no events are recorded yet."]
    );
}

#[test]
fn the_limits_apply_at_once_to_a_reading_kept_from_before() {
    // The reading is kept for ten minutes; the limits are those configured
    // now, not those of the run that read the history.
    let memory = Remembered::default();
    let events = [queued("anna@example.test", 60, 20, "192.0.2.1")];
    let first = observed(&provider(), &events, 20, &memory, 0);
    assert_eq!(first.state, State::Ok);
    let strict = Senders::new(&table("type = \"senders\"\nburst = 10")).unwrap();
    let kept = observed(&strict, &[], 20, &memory, 60);
    assert_eq!(
        (kept.state, kept.findings.clone()),
        (
            State::Warning,
            vec!["anna@example.test: 20 recipients within one hour.".to_owned()]
        )
    );
    // Still the reading of the first run.
    assert_dated(&kept, 0, EVERY);
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

#[test]
fn a_history_that_is_not_current_is_no_quiet_day() {
    let events = usual("anna@example.test", 20);
    // The receiver last reported a day ago: nothing of today is in the
    // history, and that is no day on which nobody sent.
    let quiet = Receiver {
        quiet_for: DAY,
        ..Receiver::default()
    };
    let memory = Remembered::default();
    let observation = observed_from(&quiet, &provider(), &events, 20, &memory, 0);
    assert_eq!(observation.state, State::Unknown);
    assert_eq!(
        observation.findings,
        [
            "The event history is not current: the event receiver has not reported since \
          2026-10-28T12:00:00+00:00. Mail that was handed in may be missing here."
        ]
    );
    // Events lost within the last day say the same.
    let lost = Receiver {
        quiet_for: 0,
        lost: vec![(6 * 3600, 3 * 3600)],
    };
    let observation = observed_from(&lost, &provider(), &events, 20, &Remembered::default(), 0);
    assert_eq!(observation.state, State::Unknown);
    assert!(observation.findings[0].contains("were lost while the event receiver was away"));
    // With a receiver that reports, the same history is a quiet day.
    let observation = observed(&provider(), &events, 20, &Remembered::default(), 0);
    assert_eq!(observation.state, State::Ok);
    assert_eq!(observation.findings, Vec::<String>::new());
}

#[test]
fn what_was_seen_stays_a_warning_over_an_incomplete_history() {
    let mut events = usual("anna@example.test", 20);
    events.push(queued("anna@example.test", 1800, 300, "192.0.2.1"));
    let lost = Receiver {
        quiet_for: 0,
        lost: vec![(6 * 3600, 3 * 3600)],
    };
    let observation = observed_from(&lost, &provider(), &events, 20, &Remembered::default(), 0);
    assert_eq!(observation.state, State::Warning);
    assert_eq!(observation.findings.len(), 2, "{:?}", observation.findings);
    assert!(observation.findings[0].starts_with("anna@example.test: "));
    assert!(observation.findings[1].starts_with("The event history is not current"));
}

#[test]
fn events_lost_in_the_days_before_leave_no_usual_volume_to_compare_with() {
    // Ten of the fourteen days before are missing: what is left of them is
    // no average of fourteen days, and today's ordinary volume no outlier.
    let events: Vec<Event> = (1..=4)
        .map(|day| queued("anna@example.test", day * DAY + 3600, 100, "192.0.2.1"))
        // Today 150, in three hours that are no burst.
        .chain([1, 5, 9].map(|hour| queued("anna@example.test", hour * 3600, 50, "192.0.2.1")))
        .collect();
    let lost = Receiver {
        quiet_for: 0,
        lost: vec![(15 * DAY, 5 * DAY)],
    };
    let observation = observed_from(&lost, &provider(), &events, 20, &Remembered::default(), 0);
    assert_eq!(observation.state, State::Ok);
    assert_eq!(row(&observation, "anna@example.test")[3], Value::Null);
    assert_eq!(
        observation.findings,
        [
            "No usual volume is named: events between 2026-10-14T12:00:00+00:00 and \
          2026-10-24T12:00:00+00:00 were lost while the event receiver was away."
        ]
    );
    // Without the gap, the same four days would make 150 an outlier.
    let observation = observed(&provider(), &events, 20, &Remembered::default(), 0);
    assert_eq!(observation.state, State::Warning);
}

#[test]
fn the_check_counts_by_sender_address_and_says_so() {
    // One account sends under two of its addresses, signed in once: the
    // events name the address, not the account, so each address is a row.
    let events: Vec<Event> = ["anna@example.test", "sales@example.test"]
        .iter()
        .map(|address| {
            (
                QUEUED,
                600,
                json!({"accountId": 42, "from": address, "to": ["r@example.org"], "remoteIp": "192.0.2.1"}),
            )
        })
        .collect();
    let observation = observed(&provider(), &events, 20, &Remembered::default(), 0);
    // The id is the one scripts and notifications know.
    assert_eq!(observation.id, "senders.accounts");
    assert_eq!(observation.title, "Sending addresses");
    let table = observation.table.as_ref().unwrap();
    assert_eq!(table.rows.len(), 2);
    let labels: Vec<&str> = table
        .columns
        .iter()
        .map(|column| column.label.as_str())
        .collect();
    assert_eq!(labels[0], "Sender address");
    assert_eq!(labels[6], "IP addresses");
    assert_eq!(observation.fields[0].label, "Addresses that sent");
    assert_eq!(observation.fields[0].value, json!(2));
    assert!(
        observation.scope.contains("by sender address"),
        "{}",
        observation.scope
    );
    assert!(
        observation
            .scope
            .contains("An account that sends under several addresses shows once for each"),
        "{}",
        observation.scope
    );
}

/// The card over `events`, written in that order, with at most `most`
/// submissions and bounces read.
fn read_at_most(events: &[Event], most: usize) -> Observation {
    let provider = provider().reading_at_most(most);
    observed(&provider, events, 20, &Remembered::default(), 0)
}

#[test]
fn past_its_limit_a_reading_names_the_usual_volume_of_the_whole_days_it_read() {
    // anna sends to 10 recipients on each of the 14 days before and to 60
    // today: six times her usual, a warning, the history in time's order.
    let mut events: Vec<Event> = (1..=USUAL_DAYS)
        .rev()
        .map(|day| queued("anna@example.test", day * DAY + 3600, 10, "192.0.2.1"))
        .collect();
    events.push(queued("anna@example.test", 600, 60, "192.0.2.1"));
    let whole = read_at_most(&events, MAX_EVENTS);
    assert_eq!(
        (whole.state, whole.findings.clone()),
        (
            State::Warning,
            vec![
                "anna@example.test: 60 recipients in 24 hours, where 10 a day is usual.".to_owned()
            ]
        )
    );
    // Five read: today and the four days before it, the fifth left. The usual
    // volume is that of the four, not of fourteen.
    let cut = read_at_most(&events, 5);
    assert_eq!(row(&cut, "anna@example.test")[3], json!(10));
    assert_eq!(
        (cut.state, cut.findings.clone()),
        (
            State::Warning,
            vec![
                "anna@example.test: 60 recipients in 24 hours, where 10 a day is usual.".to_owned(),
                "More mail was handed in in these 15 days than is read: the usual volumes are \
                 those of the 4 whole days before the last one that the newest 5 messages hold."
                    .to_owned()
            ]
        )
    );
    // A batch that came late: the oldest days carry the highest numbers and
    // are read first, so no whole day before the last one is read. No usual
    // volume is named, and no ordinary day is made an outlier.
    let mut late: Vec<Event> = (1..=USUAL_DAYS)
        .map(|day| queued("anna@example.test", day * DAY + 3600, 10, "192.0.2.1"))
        .collect();
    late.push(queued("anna@example.test", 600, 60, "192.0.2.1"));
    let cut = read_at_most(&late, 5);
    assert_eq!(row(&cut, "anna@example.test")[3], Value::Null);
    assert_eq!(
        (cut.state, cut.findings),
        (
            State::Ok,
            vec![
                "More mail was handed in in these 15 days than is read: no usual volume is \
                 named, since the newest 5 messages hold 0 whole days before the last one."
                    .to_owned()
            ]
        )
    );
}

#[test]
fn a_last_day_or_bounces_past_the_limit_are_a_part() {
    // Two messages today, one read: the day's figures are a part.
    let events = [
        queued("anna@example.test", 600, 3, "192.0.2.1"),
        queued("anna@example.test", 500, 3, "192.0.2.1"),
    ];
    let cut = read_at_most(&events, 1);
    assert_eq!(
        (cut.state, cut.findings),
        (
            State::Partial,
            vec![
                "More mail was handed in during the last 24 hours than is read: the figures are \
                 those of the newest 1 messages, and no usual volume is named."
                    .to_owned()
            ]
        )
    );
    // One message, two bounces, one bounce read.
    let events = [
        queued("anna@example.test", 600, 3, "192.0.2.1"),
        bounced("anna@example.test", 400),
        bounced("anna@example.test", 300),
    ];
    let cut = read_at_most(&events, 1);
    assert_eq!(
        (cut.state, cut.findings),
        (
            State::Partial,
            vec![
                "More bounces came in the last 24 hours than are counted here, which counts \
                  the newest 1."
                    .to_owned()
            ]
        )
    );
}
