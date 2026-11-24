//! The mail test against Stalwart: a test message that Stalwart defers is no
//! verdict on it.
//!
//! A milter that answers every message "not now", as a scanner that cannot
//! scan does (clamav-milter with its default `OnFail Defer` while clamd is
//! down), and a milter Stalwart cannot reach whose entry has
//! `tempFailOnError`, as `garrison stalwart setup` writes Garrison's filter
//! for `when_unreachable = "defer"`: Stalwart defers each test message at its
//! end, and the card says "not tested", Unknown. A milter that refuses every
//! message, as a scanner that fails closed does, refuses the harmless
//! message beside the tests too, and no test is judged; one that refuses
//! only the tests lets their refusals count. Beside it, the events Stalwart
//! records of what a milter answered, by which the mail flow's milter card
//! counts.
//! Needs `GARRISON_LAB_SMTP` and `GARRISON_LAB_CALLBACK_HOST` besides the
//! lab variables, as `cargo xtask lab start` prints them; run with `cargo
//! test --workspace --test contract -- --ignored`.

// Helpers fail the test by panicking, like the test itself.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use garrison_checks::context::Provider;
use garrison_checks::testing::{Canned, context, table};
use garrison_checks_mail::providers::MailTest;
use garrison_core::observations::{Observation, State};
use garrison_milter::protocol::{self, Command, Reply};
use garrison_testing::lab::Lab;
use serde_json::{Value, json};

/// One test at a time: each sets Stalwart's milters for the lab as a whole.
fn one_at_a_time() -> MutexGuard<'static, ()> {
    static LAB: Mutex<()> = Mutex::new(());
    LAB.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a stand-in milter answers at a message's end.
#[derive(Clone)]
enum Answer {
    Reply(Reply),
    /// `SMFIR_REJECT`, a refusal in the server's own words, as a filter
    /// built on libmilter sends it where it has no reply of its own.
    Reject,
}

/// What a stand-in milter makes of a message: its headers and body as
/// they came.
type Judge = Arc<dyn Fn(&[u8]) -> Answer + Send + Sync>;

/// A judge that answers every message alike.
fn always(answer: Answer) -> Judge {
    Arc::new(move |_| answer.clone())
}

/// A milter on `host` that answers each message's end as `judge` says.
fn milter(host: &str, judge: Judge) -> u16 {
    let listener = TcpListener::bind((host, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let judge = Arc::clone(&judge);
            std::thread::spawn(move || {
                let mut message = Vec::new();
                while let Ok(Some(command)) = protocol::read(&mut stream) {
                    let answer = match command {
                        Command::Negotiate { .. } => Answer::Reply(Reply::Negotiate {
                            actions: 0,
                            protocol: 0,
                        }),
                        Command::Header { name, value } => {
                            message
                                .extend([name, b": ".to_vec(), value, b"\r\n".to_vec()].concat());
                            Answer::Reply(Reply::Continue)
                        }
                        Command::Body(data) => {
                            message.extend(data);
                            Answer::Reply(Reply::Continue)
                        }
                        Command::EndOfBody => judge(&std::mem::take(&mut message)),
                        Command::Quit => break,
                        Command::Abort => {
                            message.clear();
                            continue;
                        }
                        Command::Other(b'D') => continue,
                        _ => Answer::Reply(Reply::Continue),
                    };
                    let written = match answer {
                        Answer::Reply(reply) => protocol::write(&mut stream, &reply),
                        Answer::Reject => stream.write_all(&[0, 0, 0, 1, b'r']),
                    };
                    if written.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Stalwart's milter entry to `port` on `host`, as setup writes it, read
/// again by Stalwart.
fn milter_entry(lab: &mut Lab, host: &str, port: u16) {
    lab.create(
        "MtaMilter",
        &json!({"host": host, "port": port, "tempFailOnError": true}),
    );
    reload(lab);
}

/// The entry made last taken out, and one to `port` on `host` in its place.
fn milter_entry_instead(lab: &mut Lab, host: &str, port: u16) {
    let (kind, entry) = lab.created.pop().unwrap();
    lab.call(&format!("x:{kind}/set"), &json!({"destroy": [entry]}));
    milter_entry(lab, host, port);
}

fn reload(lab: &Lab) {
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
    std::thread::sleep(Duration::from_secs(2));
}

/// The mail test's card, its tests sent to the lab's administrator.
fn tested(smtp: &str) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let runner = Canned(String::new());
    let provider = MailTest::new(&table(&format!(
        "type = \"mail-test\"\nrecipient = \"admin@example.test\"\nhost = \"{smtp}\""
    )))
    .unwrap();
    provider
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0)
}

fn results(observation: &Observation) -> Vec<String> {
    let rows = &observation.table.as_ref().unwrap().rows;
    rows.iter()
        .map(|row| row[2].as_str().unwrap().to_owned())
        .collect()
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_test_message_that_stalwart_defers_is_not_tested() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    // A scanner that cannot scan.
    let port = milter(&callback, always(Answer::Reply(Reply::TempFail)));
    milter_entry(&mut lab, &callback, port);
    let deferred = tested(&smtp);
    eprintln!("a milter that defers: {:?}", results(&deferred));
    assert_eq!(deferred.state, State::Unknown, "{deferred:?}");
    for result in results(&deferred) {
        assert!(result.starts_with("not tested: 4"), "{result}");
    }
    // A milter that does not run, its entry left behind.
    let closed = TcpListener::bind((callback.as_str(), 0)).unwrap();
    let gone = closed.local_addr().unwrap().port();
    drop(closed);
    milter_entry_instead(&mut lab, &callback, gone);
    let unreached = tested(&smtp);
    eprintln!("a milter that cannot be reached: {:?}", results(&unreached));
    assert_eq!(unreached.state, State::Unknown, "{unreached:?}");
    for result in results(&unreached) {
        assert!(result.starts_with("not tested: 4"), "{result}");
    }
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_refusal_counts_only_where_stalwart_takes_the_harmless_message() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    // A scanner that fails closed, in Stalwart's words and in its own.
    let refusing = [
        Answer::Reject,
        Answer::Reply(Reply::Refuse(
            "550 5.7.1 Refused by the contract test.".into(),
        )),
    ];
    for (round, answer) in refusing.into_iter().enumerate() {
        let port = milter(&callback, always(answer));
        if round == 0 {
            milter_entry(&mut lab, &callback, port);
        } else {
            milter_entry_instead(&mut lab, &callback, port);
        }
        let card = tested(&smtp);
        let rows = results(&card);
        eprintln!("a milter that refuses every message: {rows:?}");
        assert_eq!((card.state, rows.len()), (State::Unknown, 3), "{card:?}");
        for row in &rows[..2] {
            assert!(
                row.starts_with("not tested: refused like a harmless message: 5"),
                "{row}"
            );
        }
        assert!(rows[2].starts_with("refused: 5"), "{rows:?}");
    }
    // A scanner that refuses what it knows and takes the rest.
    let known = [
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
        "GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL",
    ];
    let port = milter(
        &callback,
        Arc::new(move |message: &[u8]| {
            let text = String::from_utf8_lossy(message);
            if known.iter().any(|known| text.contains(known)) {
                Answer::Reply(Reply::Refuse(
                    "550 5.7.1 Found by the contract test.".into(),
                ))
            } else {
                Answer::Reply(Reply::Accept)
            }
        }),
    );
    milter_entry_instead(&mut lab, &callback, port);
    let card = tested(&smtp);
    let rows = results(&card);
    eprintln!("a milter that refuses the tests alone: {rows:?}");
    assert_eq!((card.state, rows.len()), (State::Ok, 3), "{card:?}");
    for row in &rows[..2] {
        assert!(row.starts_with("refused: 5"), "{row}");
    }
    assert_eq!(rows[2], "accepted");
}

/// The events Stalwart posts to a webhook on `host`, as they come.
fn webhook(host: &str) -> (u16, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind((host, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let events = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&events);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let mut reader = BufReader::new(stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; length];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            if let Ok(batch) = serde_json::from_slice::<Value>(&body) {
                let arrived = batch["events"].as_array().cloned().unwrap_or_default();
                kept.lock().unwrap().extend(arrived);
            }
            let _ = reader
                .into_inner()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    (port, events)
}

/// What Stalwart answers at the end of one message with `subject`.
fn handed_in(smtp: &str, subject: &str) -> String {
    let mut session = garrison_testing::smtp::Smtp::connect(smtp);
    for command in [
        "EHLO contract.example.net",
        "MAIL FROM:<sender@contract.example.net>",
        "RCPT TO:<admin@example.test>",
    ] {
        let reply = session.command(command);
        assert!(reply.starts_with("250"), "{command}: {reply}");
    }
    assert!(session.command("DATA").starts_with("354"));
    let answer = session.command(&format!(
        "From: <sender@contract.example.net>\r\nTo: <admin@example.test>\r\n\
         Subject: {subject}\r\n\r\nA message for the milter.\r\n."
    ));
    session.command("QUIT");
    answer.trim_end().to_owned()
}

/// What Stalwart answered at the end of one message with `subject`, and the
/// milter events it posted for it; both printed for the record.
fn recorded(smtp: &str, events: &Mutex<Vec<Value>>, subject: &str) -> (String, Vec<Value>) {
    let before = events.lock().unwrap().len();
    let said = handed_in(smtp, subject);
    let deadline = Instant::now() + Duration::from_secs(20);
    while events.lock().unwrap().len() == before && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    // The rest of a batch, if it was split.
    std::thread::sleep(Duration::from_secs(2));
    let arrived: Vec<Value> = events.lock().unwrap()[before..].to_vec();
    (said, arrived)
}

/// A webhook to `port` on `host` for every milter event Stalwart records.
fn milter_webhook(lab: &mut Lab, host: &str, port: u16) {
    let kinds: Value = [
        "milter.action-accept",
        "milter.action-reject",
        "milter.action-discard",
        "milter.action-temp-fail",
        "milter.action-reply-code",
        "milter.action-connection-failure",
        "milter.timeout",
        "milter.io-error",
        "milter.disconnected",
    ]
    .into_iter()
    .map(|name| (name.to_owned(), json!(true)))
    .collect();
    lab.create(
        "WebHook",
        &json!({
            "url": format!("http://{host}:{port}/"),
            "events": kinds,
            "eventsPolicy": "include",
            "level": "trace",
            "timeout": 5000,
            "throttle": 500,
            "discardAfter": 60000,
            "lossy": false,
            "signatureKey": {"@type": "Value", "secret": garrison_testing::lab::random_hex(32)},
            "httpAuth": {"@type": "Unauthenticated"},
            "httpHeaders": {},
            "allowInvalidCerts": false,
            "enable": true,
        }),
    );
}

/// What the mail flow's milter card counts by: the event Stalwart records
/// for each answer of a milter. A reply of the milter's own is one event
/// whether it refuses or defers, and names no code, so the card counts it
/// apart; a milter that cannot be reached is one of the events the card
/// warns of.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn stalwart_records_what_a_milter_answered() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    let (hook, events) = webhook(&callback);
    milter_webhook(&mut lab, &callback, hook);
    let reply = Arc::new(Mutex::new(Reply::Accept));
    let now = Arc::clone(&reply);
    let port = milter(
        &callback,
        Arc::new(move |_| Answer::Reply(now.lock().unwrap().clone())),
    );
    milter_entry(&mut lab, &callback, port);
    for (subject, answer, code, kind) in [
        ("accepted", Reply::Accept, "250", "milter.action-accept"),
        (
            "deferred",
            Reply::TempFail,
            "451",
            "milter.action-temp-fail",
        ),
        (
            "refused with 550",
            Reply::Refuse("550 5.7.1 Refused by the contract test.".into()),
            "550",
            "milter.action-reply-code",
        ),
        (
            "refused with 451",
            Reply::Refuse("451 4.7.1 Not now, says the contract test.".into()),
            "451",
            "milter.action-reply-code",
        ),
    ] {
        *reply.lock().unwrap() = answer;
        let (said, arrived) = recorded(&smtp, &events, subject);
        eprintln!(
            "{subject}: SMTP {said:?}; events {}",
            Value::Array(arrived.clone())
        );
        assert!(said.starts_with(code), "{subject}: {said}");
        let types: Vec<&str> = arrived
            .iter()
            .filter_map(|event| event["type"].as_str())
            .collect();
        assert_eq!(types, [kind], "{subject}");
        // Nothing in it that the receiver keeps and that would tell a
        // refusal from a deferral.
        for field in ["code", "details", "reason"] {
            assert!(
                arrived[0]["data"].get(field).is_none(),
                "{subject}: {field}"
            );
        }
    }
    // The milter gone, its entry left: one of the events the card warns of.
    let closed = TcpListener::bind((callback.as_str(), 0)).unwrap();
    let gone = closed.local_addr().unwrap().port();
    drop(closed);
    milter_entry_instead(&mut lab, &callback, gone);
    let (said, arrived) = recorded(&smtp, &events, "unreached");
    eprintln!(
        "unreached: SMTP {said:?}; events {}",
        Value::Array(arrived.clone())
    );
    assert!(said.starts_with('4'), "{said}");
    let types: Vec<&str> = arrived
        .iter()
        .filter_map(|event| event["type"].as_str())
        .collect();
    assert!(
        !types.is_empty()
            && types.iter().all(|kind| {
                [
                    "milter.action-connection-failure",
                    "milter.timeout",
                    "milter.io-error",
                    "milter.disconnected",
                ]
                .contains(kind)
            }),
        "{types:?}"
    );
}
