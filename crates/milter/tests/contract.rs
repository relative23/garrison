//! Stalwart and the macro milter understand each other.
//!
//! The filter listens on an address the lab's Stalwart can reach, Stalwart
//! is told of it as `garrison stalwart setup` tells it, and mail is sent in
//! over SMTP: a message with the test document must be refused with the
//! filter's own words, one without must be taken. Needs `GARRISON_LAB_SMTP`
//! and `GARRISON_LAB_CALLBACK_HOST` besides the lab variables, as `cargo
//! xtask lab start` prints them; run with `cargo test --workspace --test
//! contract -- --ignored`.

// Helpers fail the test by panicking, like the test itself.
#![allow(clippy::unwrap_used)]

use std::net::TcpListener;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_milter::protocol::{self, Command, Reply};
use garrison_milter::sample::{NAME, document};
use garrison_milter::server::{HEADER, REFUSAL, Settings, serve};
use garrison_testing::lab::{Lab, random_hex};
use garrison_testing::smtp::Smtp;
use serde_json::json;

/// A message for the lab's administrator, with `attachment` if there is one.
fn message(subject: &str, attachment: Option<&[u8]>) -> String {
    let head = format!(
        "From: <sender@contract.example.net>\r\nTo: <admin@example.test>\r\nSubject: {subject}\r\n\
         Message-ID: <{}@contract.example.net>\r\nMIME-Version: 1.0\r\n",
        random_hex(8)
    );
    let Some(attachment) = attachment else {
        return format!("{head}Content-Type: text/plain\r\n\r\nNothing attached.\r\n.");
    };
    let encoded = STANDARD.encode(attachment);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "{head}Content-Type: multipart/mixed; boundary=\"part\"\r\n\r\n--part\r\n\
         Content-Type: text/plain\r\n\r\nSee the attachment.\r\n--part\r\n\
         Content-Type: application/vnd.ms-word.document.macroEnabled.12; name=\"{NAME}\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n--part--\r\n.",
        lines.join("\r\n")
    )
}

/// What Stalwart answers at the end of a message's data.
fn handed_in(smtp: &str, message: &str) -> String {
    let mut session = Smtp::connect(smtp);
    for command in [
        "EHLO contract.example.net",
        "MAIL FROM:<sender@contract.example.net>",
        "RCPT TO:<admin@example.test>",
    ] {
        let reply = session.command(command);
        assert!(reply.starts_with("250"), "{command}: {reply}");
    }
    assert!(session.command("DATA").starts_with("354"));
    let answer = session.command(message);
    session.command("QUIT");
    answer
}

/// The filter's header on the message with `subject` in the administrator's
/// mailbox, once the message is there; `None` if it carries none.
fn mark_of(lab: &Lab, subject: &str) -> Option<String> {
    let admin = std::env::var("GARRISON_LAB_ADMIN").unwrap();
    let session = lab.http("/jmap/session", &admin, None);
    let account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
        .as_str()
        .expect("the administrator has a mailbox")
        .to_owned();
    let property = format!("header:{HEADER}:asText");
    for _ in 0..40 {
        let answer = lab.http(
            "/jmap/",
            &admin,
            Some(&json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                "methodCalls": [
                    ["Email/query", {
                        "accountId": account, "limit": 30,
                        "sort": [{"property": "receivedAt", "isAscending": false}],
                    }, "q"],
                    ["Email/get", {
                        "accountId": account,
                        "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                        "properties": ["subject", property],
                    }, "g"],
                ],
            })),
        );
        let found = answer["methodResponses"][1][1]["list"]
            .as_array()
            .and_then(|list| list.iter().find(|mail| mail["subject"] == subject).cloned());
        if let Some(mail) = found {
            return mail[&property]
                .as_str()
                .map(|value| value.trim().to_owned());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("the message {subject:?} did not arrive");
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn stalwart_asks_the_filter_and_refuses_what_it_refuses() {
    let mut lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    let listener = TcpListener::bind((callback.as_str(), 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        serve(
            &listener,
            Settings {
                tag: false,
                max_bytes: 16 * 1024 * 1024,
            },
        );
    });
    // As setup enters it: host, port and what to do while it is away.
    let entry = lab.create(
        "MtaMilter",
        &json!({"host": callback, "port": port, "tempFailOnError": true}),
    );
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
    std::thread::sleep(Duration::from_secs(2));

    let refused = handed_in(&smtp, &message("Macro test", Some(&document())));
    assert!(refused.starts_with("550"), "{refused}");
    assert!(
        refused.contains(REFUSAL.trim_start_matches("550 5.7.1 ")),
        "{refused}"
    );
    let taken = handed_in(&smtp, &message("Macro test", None));
    assert!(taken.starts_with("250"), "{taken}");
    // A document without macros passes the filter too.
    let harmless =
        garrison_milter::sample::archive(&[("word/document.xml", b"<w:document/>", true)]);
    let taken = handed_in(&smtp, &message("Macro test", Some(&harmless)));
    assert!(taken.starts_with("250"), "{taken}");
    // Where the operator has such mail marked instead: the entry is changed
    // as setup changes it, to a filter that tags, and the message arrives
    // with the filter's header; one without macros arrives without it.
    let tagging = TcpListener::bind((callback.as_str(), 0)).unwrap();
    let tagging_port = tagging.local_addr().unwrap().port();
    std::thread::spawn(move || {
        serve(
            &tagging,
            Settings {
                tag: true,
                max_bytes: 16 * 1024 * 1024,
            },
        );
    });
    lab.call(
        "x:MtaMilter/set",
        &json!({"update": {(entry.clone()): {
            "host": callback, "port": tagging_port, "tempFailOnError": true,
        }}}),
    );
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
    std::thread::sleep(Duration::from_secs(2));
    let marked = format!("Macro test {}", random_hex(6));
    let taken = handed_in(&smtp, &message(&marked, Some(&document())));
    assert!(taken.starts_with("250"), "{taken}");
    let clean = format!("Macro test {}", random_hex(6));
    let taken = handed_in(&smtp, &message(&clean, None));
    assert!(taken.starts_with("250"), "{taken}");
    let mark = mark_of(&lab, &marked).expect("the message with macros carries the header");
    assert!(mark.starts_with("yes"), "{mark}");
    assert_eq!(mark_of(&lab, &clean), None);
    // A filter that has no room says "not now": Stalwart passes that on as a
    // temporary failure, so the sending server keeps the message.
    let busy = TcpListener::bind((callback.as_str(), 0)).unwrap();
    let busy_port = busy.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in busy.incoming() {
            let mut stream = stream.unwrap();
            while let Ok(Some(command)) = protocol::read(&mut stream) {
                // It asks for every step and answers each, as a filter of
                // the protocol's first versions does.
                let reply = match command {
                    Command::Negotiate { .. } => Reply::Negotiate {
                        actions: 0,
                        protocol: 0,
                    },
                    Command::EndOfBody => Reply::TempFail,
                    Command::Quit => break,
                    Command::Abort | Command::Other(b'D') => continue,
                    _ => Reply::Continue,
                };
                protocol::write(&mut stream, &reply).unwrap();
            }
        }
    });
    lab.call(
        "x:MtaMilter/set",
        &json!({"update": {(entry.clone()): {
            "host": callback, "port": busy_port, "tempFailOnError": true,
        }}}),
    );
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
    std::thread::sleep(Duration::from_secs(2));
    let deferred = handed_in(&smtp, &message("Macro test", None));
    assert!(deferred.starts_with('4'), "{deferred}");
}
