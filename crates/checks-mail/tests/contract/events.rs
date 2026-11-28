//! The events Stalwart records of what a milter answered, by which the mail
//! flow's milter card counts.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use garrison_testing::lab::Lab;
use garrison_testing::milter::Reply;
use serde_json::{Value, json};

use super::{Answer, always, milter, milter_entry, milter_entry_instead, one_at_a_time, reload};

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
        "milter.frame-too-large",
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

/// A milter on `host` that answers Stalwart's first frame with one said to
/// be 64 MiB long, of which nothing follows.
fn oversized_milter(host: &str) -> u16 {
    let listener = TcpListener::bind((host, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            std::thread::spawn(move || {
                let _ = garrison_testing::milter::read(&mut stream);
                let _ = stream.write_all(&[0x04, 0, 0, 0, b'O']);
                // Held open: the answer's length alone is what Stalwart refuses.
                std::thread::sleep(Duration::from_secs(8));
            });
        }
    });
    port
}

/// A milter whose answer is larger than Stalwart reads: Stalwart defers the
/// message where the entry has `tempFailOnError` and records one event of a
/// type of its own, with the size the answer announced as a number and
/// nothing of the answer itself. No other milter event comes with it, so
/// the card counts the type apart and warns of it.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn stalwart_records_a_milter_answer_that_is_too_large_by_its_size_alone() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    let (hook, events) = webhook(&callback);
    milter_webhook(&mut lab, &callback, hook);
    let port = oversized_milter(&callback);
    milter_entry(&mut lab, &callback, port);
    let (said, arrived) = recorded(&smtp, &events, "an answer of 64 MiB");
    let seen = Value::Array(arrived.clone());
    assert!(said.starts_with("451"), "{said}; {seen}");
    let types: Vec<&str> = arrived
        .iter()
        .filter_map(|event| event["type"].as_str())
        .collect();
    assert_eq!(types, ["milter.frame-too-large"], "{seen}");
    let data = arrived[0]["data"].as_object().unwrap();
    assert_eq!(data["details"], json!(67_108_864), "{seen}");
    let mut fields: Vec<&str> = data.keys().map(String::as_str).collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "details",
            "elapsed",
            "listenerId",
            "localPort",
            "name",
            "remoteIp",
            "remotePort",
            "spanId"
        ],
        "{seen}"
    );
}

/// Two milters on one message, as another filter beside
/// clamav-milter while clamd is down: Stalwart asks the second after the
/// first passed the message, defers it for the second, and records both
/// answers under the message's session, by which the milter card counts
/// messages. A deferral asked first ends the message.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn two_milters_answer_one_message_in_its_session() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    let (hook, events) = webhook(&callback);
    milter_webhook(&mut lab, &callback, hook);
    let passing = milter(&callback, always(Answer::Reply(Reply::Accept)));
    let deferring = milter(&callback, always(Answer::Reply(Reply::TempFail)));
    for (order, first, second, expected) in [
        (
            "passing first",
            passing,
            deferring,
            &["milter.action-accept", "milter.action-temp-fail"][..],
        ),
        (
            "deferring first",
            deferring,
            passing,
            &["milter.action-temp-fail"][..],
        ),
    ] {
        milter_entry(&mut lab, &callback, first);
        milter_entry(&mut lab, &callback, second);
        let (said, arrived) = recorded(&smtp, &events, order);
        let seen = Value::Array(arrived.clone());
        assert!(said.starts_with("451"), "{order}: {said}; {seen}");
        let types: Vec<&str> = arrived
            .iter()
            .filter_map(|event| event["type"].as_str())
            .collect();
        assert_eq!(types, expected, "{order}: {seen}");
        let spans: std::collections::BTreeSet<String> = arrived
            .iter()
            .map(|event| event["data"]["spanId"].to_string())
            .collect();
        assert_eq!(spans.len(), 1, "{order}: {seen}");
        for _ in 0..2 {
            let (kind, entry) = lab.created.pop().unwrap();
            lab.call(&format!("x:{kind}/set"), &json!({"destroy": [entry]}));
        }
        reload(&lab);
    }
}
