//! What Stalwart does with its milter entries, on which the rule of the
//! entries test stands, measured with mail: it keeps each name of this host
//! as it is written and asks it, it defers every message while it asks an
//! entry where nothing answers, and it asks its entries as it read them
//! last.

use std::time::Duration;

use garrison_testing::lab::{Lab, random_hex, unique};
use garrison_testing::smtp::Smtp;
use serde_json::json;

use super::entries::{LOOPBACK, NAMES, Ports, reload, written};

/// What Stalwart answers at the end of a message's data. Each message comes
/// from a domain of its own, as Stalwart limits what one sender may send.
fn handed_in(smtp: &str) -> String {
    let domain = format!("{}.example.net", unique());
    let mut session = Smtp::connect(smtp);
    for command in [
        "EHLO contract.example.net".to_owned(),
        format!("MAIL FROM:<sender@{domain}>"),
        "RCPT TO:<admin@example.test>".to_owned(),
        "DATA".to_owned(),
    ] {
        session.command(&command);
    }
    let message = format!(
        "From: <sender@{domain}>\r\nTo: <admin@example.test>\r\nSubject: entry\r\n\
         Message-ID: <{}@{domain}>\r\n\r\nNothing attached.\r\n.",
        random_hex(8)
    );
    let answer = session.command(&message);
    session.command("QUIT");
    answer
}

fn settle() {
    std::thread::sleep(Duration::from_secs(2));
}

/// Stalwart's own behaviour, on which the rest stands: an entry it asks in
/// vain defers every message, and it asks its entries as it read them last,
/// so an entry made or taken out counts only once it reads its settings.
pub(super) fn stalwart_asks_what_it_read_last(lab: &Lab, ports: &Ports) {
    let smtp = std::env::var("GARRISON_LAB_SMTP").unwrap();
    reload(lab);
    settle();
    let taken = handed_in(&smtp);
    assert!(taken.starts_with("250"), "before: {taken}");
    let made = lab.call(
        "x:MtaMilter/set",
        &json!({"create": {"n": written(LOOPBACK, ports.old)}}),
    );
    let id = made["created"]["n"]["id"].as_str().unwrap().to_owned();
    let unread = handed_in(&smtp);
    reload(lab);
    settle();
    let read = handed_in(&smtp);
    lab.call("x:MtaMilter/set", &json!({ "destroy": [id] }));
    let removed = handed_in(&smtp);
    reload(lab);
    settle();
    let again = handed_in(&smtp);
    for (when, answer, code) in [
        ("made, not read", &unread, "250"),
        ("made and read", &read, "451"),
        ("taken out, not read", &removed, "451"),
        ("taken out and read", &again, "250"),
    ] {
        assert!(answer.starts_with(code), "{when}: {answer}");
    }
}

/// Stalwart keeps each name of this host as it is written and asks it:
/// where nothing answers, it defers every message. What it did otherwise.
pub(super) fn every_name_is_kept_and_asked(lab: &Lab, ports: &Ports) -> Vec<String> {
    let smtp = std::env::var("GARRISON_LAB_SMTP").unwrap();
    let mut found = Vec::new();
    for name in NAMES {
        let made = lab.call(
            "x:MtaMilter/set",
            &json!({"create": {"n": written(name, ports.old)}}),
        );
        let id = made["created"]["n"]["id"].as_str().unwrap().to_owned();
        let kept = lab.call("x:MtaMilter/get", &json!({ "ids": [id] }))["list"][0]["host"].clone();
        reload(lab);
        settle();
        let answer = handed_in(&smtp);
        lab.call("x:MtaMilter/set", &json!({ "destroy": [id] }));
        if kept != name || !answer.starts_with("451") {
            found.push(format!(
                "Stalwart kept {name:?} as {kept}, and a message got {answer}"
            ));
        }
    }
    reload(lab);
    settle();
    found
}
