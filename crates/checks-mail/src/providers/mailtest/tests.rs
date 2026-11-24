use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::thread;

use super::session::{queue_id, reply};
use super::*;
use crate::context::Context;
use crate::testing::{Canned, Remembered, assert_dated, config, now, table};

/// A reply for [`server`] that is no reply: the session is taken and never
/// greeted, until the client gives up on it.
pub(super) const SILENT: &str = "(silent)";

/// A mail server for one session per reply, on one port for all of them: it
/// answers the message of each session with the reply given for it and
/// returns what it was sent. A reply that begins with `at RCPT: ` is given to
/// the recipient instead, so that the session never comes to its message.
pub(super) fn server<const SESSIONS: usize>(
    replies: [&'static str; SESSIONS],
) -> (u16, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let mut sessions = Vec::new();
        for answer in replies {
            let (stream, _) = listener.accept().unwrap();
            let mut seen = String::new();
            if answer == SILENT {
                let _ = BufReader::new(stream).read_to_string(&mut seen);
                sessions.push(seen);
                continue;
            }
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            writer
                .write_all(b"220 mail.example.test ESMTP\r\n")
                .unwrap();
            let mut in_data = false;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                seen.push_str(&line);
                let reply: String = if in_data {
                    if line != ".\r\n" {
                        continue;
                    }
                    in_data = false;
                    format!("{answer}\r\n")
                } else if let (true, Some(refusal)) =
                    (line.starts_with("RCPT"), answer.strip_prefix("at RCPT: "))
                {
                    format!("{refusal}\r\n")
                } else if line.starts_with("EHLO") {
                    "250-mail.example.test\r\n250-SIZE 100\r\n250 8BITMIME\r\n".to_owned()
                } else if line.starts_with("DATA") {
                    in_data = true;
                    "354 go ahead\r\n".to_owned()
                } else if line.starts_with("QUIT") {
                    break;
                } else {
                    "250 2.1.0 OK\r\n".to_owned()
                };
                writer.write_all(reply.as_bytes()).unwrap();
            }
            sessions.push(seen);
        }
        sessions
    });
    (port, handle)
}

pub(super) fn provider(port: u16) -> MailTest {
    MailTest::new(&table(&format!(
        "type = \"mail-test\"\nrecipient = \"garrison-test@example.test\"\nport = {port}"
    )))
    .unwrap()
}

/// One collection `later` seconds after the tests' clock, with `events` in
/// the event history as `(queue ID, type)`.
pub(super) fn collected(
    provider: &MailTest,
    memory: &Remembered,
    later: i64,
    events: &[(&str, &str)],
) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let path = config.database(garrison_core::config::Database::Events);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE events(queue_id TEXT, type TEXT)")
        .unwrap();
    for (queue, kind) in events {
        db.execute("INSERT INTO events VALUES(?,?)", [queue, kind])
            .unwrap();
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

pub(super) fn results(observation: &Observation) -> Vec<&str> {
    observation
        .table
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .map(|row| row[2].as_str().unwrap())
        .collect()
}

#[test]
fn a_refused_test_file_and_spam_text_filed_as_spam_are_in_order() {
    let (port, handle) = server([
        "550 5.7.1 Virus found: Eicar-Signature",
        "250 2.0.0 Message queued with id 4b786a6d0a00200.",
        "250 2.0.0 Message queued with id 4b786a6d0a00300.",
    ]);
    let provider = provider(port);
    let memory = Remembered::default();
    // Right after the session nothing is known of the accepted message yet.
    // The harmless message after the refusal was taken, so the refusal is
    // the scanner's.
    let first = collected(&provider, &memory, 0, &[]);
    assert_eq!(first.state, State::Unknown);
    assert_eq!(
        results(&first),
        [
            "refused: 550 5.7.1 Virus found: Eicar-Signature",
            "accepted; the event history does not show yet how it was filed",
            "accepted",
        ]
    );
    // A minute later the history has it; no second session is opened.
    let queue = u64::from_str_radix("4b786a6d0a00200", 16)
        .unwrap()
        .to_string();
    let filed = collected(
        &provider,
        &memory,
        60,
        &[
            (&queue, "queue.message-queued"),
            (&queue, "message-ingest.spam"),
        ],
    );
    assert_eq!(filed.state, State::Ok, "{:?}", filed.findings);
    assert_eq!(results(&filed)[1], "accepted and filed as spam");
    // The card is as old as the tests, not as the run that reads their result.
    assert_dated(&filed, 0, 86_400);
    assert_eq!(filed.modules, [ModuleId::Antivirus, ModuleId::Spam].into());
    let sessions = handle.join().unwrap();
    assert_eq!(sessions.len(), 3);
    // A stranger's session: no sign-in, the null sender, the named recipient.
    assert!(
        sessions[0].contains("MAIL FROM:<>\r\nRCPT TO:<garrison-test@example.test>\r\nDATA\r\n"),
        "{}",
        sessions[0]
    );
    assert!(!sessions[0].contains("AUTH"));
    assert!(sessions[0].contains("Subject: Garrison mail test: Antivirus test file (EICAR)\r\n"));
    assert!(sessions[0].contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"));
    // Stalwart takes the spam text for the test only as the whole subject.
    let text = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
    assert!(sessions[1].contains(&format!("Subject: {text}\r\n")));
    assert!(sessions[1].contains(&format!("\r\n\r\n{text}\r\n.\r\n")));
    assert!(sessions[0].contains("Date: Thu, 29 Oct 2026 12:00:00 +0000\r\n"));
}

#[test]
fn an_accepted_test_file_and_spam_delivered_as_mail_are_failures() {
    let (port, handle) = server([
        "250 2.0.0 Message queued with id a.",
        "250 2.0.0 Message queued with id b.",
    ]);
    let provider = provider(port);
    let memory = Remembered::default();
    collected(&provider, &memory, 0, &[]);
    let later = collected(&provider, &memory, 120, &[("11", "message-ingest.ham")]);
    handle.join().unwrap();
    assert_eq!(later.state, State::Failed);
    assert_eq!(
        later.findings,
        [
            "Antivirus test file (EICAR): accepted: no scanner refused the test file.",
            "Spam test text (GTUBE): accepted and delivered as ordinary mail.",
        ]
    );
    // A verdict that never comes stays unknown, in other words.
    let (port, handle) = server(["451 4.7.1 try later", "250 2.0.0 Message queued with id c."]);
    let provider = self::provider(port);
    let memory = Remembered::default();
    collected(&provider, &memory, 0, &[]);
    let waited = collected(&provider, &memory, VERDICT_WITHIN + 1, &[]);
    handle.join().unwrap();
    assert_eq!(waited.state, State::Unknown);
    assert_eq!(
        results(&waited),
        [
            "not tested: 451 4.7.1 try later",
            "accepted; the event history never showed how it was filed",
        ]
    );
}

/// What Stalwart answers at the end of a message that a milter deferred or
/// that it could not hand to a milter (measured on Stalwart 1.1.0).
const DEFERRED: &str = "451 4.3.5 Unable to accept message at this time.";

#[test]
fn a_message_the_server_defers_is_not_tested_and_is_tried_again_within_the_hour() {
    // A scanner that cannot scan defers each message, and so does Stalwart
    // where a milter it names cannot be reached: no test was judged.
    let with_macros = |port: u16| {
        MailTest::new(&table(&format!(
            "type = \"mail-test\"\nrecipient = \"garrison-test@example.test\"\nport = {port}\n\
             macro_document = true"
        )))
        .unwrap()
    };
    let (port, handle) = server([
        DEFERRED,
        DEFERRED,
        DEFERRED,
        "550 virus",
        "550 spam",
        "550 macro",
        "250 2.0.0 Message queued with id c.",
    ]);
    let memory = Remembered::default();
    let deferred = collected(&with_macros(port), &memory, 0, &[]);
    let not_tested = format!("not tested: {DEFERRED}");
    assert_eq!(
        (deferred.state, results(&deferred)),
        (State::Unknown, vec![not_tested.as_str(); 3])
    );
    assert_eq!(
        deferred.findings,
        [
            "Antivirus test file (EICAR): not tested: 451 4.3.5 Unable to accept message at this \
             time.",
            "Spam test text (GTUBE): not tested: 451 4.3.5 Unable to accept message at this time.",
            "Office document with macros (test document): not tested: 451 4.3.5 Unable to accept \
             message at this time.",
        ]
    );
    // Tried again after an hour, not a day.
    assert_dated(&deferred, 0, AGAIN);
    let again = collected(&with_macros(port), &memory, AGAIN, &[]);
    assert_eq!(again.state, State::Ok, "{:?}", again.findings);
    assert_eq!(handle.join().unwrap().len(), 7);
}

/// What a server answers that refuses every message at its end: a scanner
/// that fails closed, as clamav-milter with `OnFail Reject` while clamd is
/// down, another milter or a policy of the server.
const REFUSING: &str = "550 5.7.1 Service unavailable";

#[test]
fn a_refusal_where_the_server_refuses_a_harmless_message_too_is_not_tested() {
    let (port, handle) = server([REFUSING; 3]);
    let memory = Remembered::default();
    let refused = collected(&provider(port), &memory, 0, &[]);
    let like = format!("not tested: refused like a harmless message: {REFUSING}");
    assert_eq!(
        (refused.state, results(&refused)),
        (
            State::Unknown,
            vec![
                like.as_str(),
                like.as_str(),
                "refused: 550 5.7.1 Service unavailable"
            ]
        )
    );
    assert_eq!(
        refused.findings.last().map(String::as_str),
        Some(
            "Harmless message (control): refused: 550 5.7.1 Service unavailable. The server \
             refuses mail that carries nothing to refuse, as clamav-milter does with `OnFail \
             Reject` while clamd is down, so no refusal of a test counts."
        )
    );
    // Not a result to keep for a day.
    assert_dated(&refused, 0, AGAIN);
    let sessions = handle.join().unwrap();
    assert_eq!(sessions.len(), 3);
    // The third message carries nothing that a scanner or a filter refuses.
    let harmless = &sessions[2];
    assert!(
        harmless.contains("Subject: Garrison mail test: Harmless message (control)\r\n"),
        "{harmless}"
    );
    assert!(
        !harmless.contains("EICAR") && !harmless.contains("GTUBE"),
        "{harmless}"
    );

    // An hour later the server takes it: the tests are sent again with it,
    // and their refusals count.
    let (port, handle) = server([
        "550 virus",
        "550 spam",
        "250 2.0.0 Message queued with id c.",
    ]);
    let again = collected(&provider(port), &memory, AGAIN, &[]);
    assert_eq!(
        (again.state, results(&again)),
        (
            State::Ok,
            vec!["refused: 550 virus", "refused: 550 spam", "accepted"]
        )
    );
    assert_eq!(handle.join().unwrap().len(), 3);
}

#[test]
fn a_refusal_without_a_harmless_message_taken_beside_it_is_not_tested() {
    // The harmless message did not get through: nothing to compare with.
    let (port, handle) = server(["550 virus", "550 spam", "at RCPT: 451 4.7.1 not now"]);
    let card = collected(&provider(port), &Remembered::default(), 0, &[]);
    assert_eq!(
        (card.state, results(&card)),
        (
            State::Unknown,
            vec![
                "not tested: refused, and no harmless message got through to compare: 550 virus",
                "not tested: refused, and no harmless message got through to compare: 550 spam",
                "not tested: 451 4.7.1 not now",
            ]
        )
    );
    assert_dated(&card, 0, AGAIN);
    assert_eq!(handle.join().unwrap().len(), 3);
}

#[test]
fn the_macro_document_is_sent_where_it_is_switched_on_and_must_be_refused() {
    let with_macros = |port: u16| {
        MailTest::new(&table(&format!(
            "type = \"mail-test\"\nrecipient = \"garrison-test@example.test\"\nport = {port}\n\
             macro_document = true"
        )))
        .unwrap()
    };
    let refusal = "550 5.7.1 Message refused: an attached Office document contains macros.";
    let (port, handle) = server([
        "550 virus",
        "550 spam",
        refusal,
        "250 2.0.0 Message queued with id c.",
    ]);
    let memory = Remembered::default();
    let refused = collected(&with_macros(port), &memory, 0, &[]);
    assert_eq!(refused.state, State::Ok, "{:?}", refused.findings);
    assert_eq!(results(&refused)[2], format!("refused: {refusal}"));
    let sessions = handle.join().unwrap();
    let message = &sessions[2];
    assert!(
        message.contains(
            "Subject: Garrison mail test: Office document with macros (test document)\r\n"
        )
    );
    assert!(message.contains("Content-Type: multipart/mixed; boundary=\"garrison-mail-test\"\r\n"));
    assert!(message.contains("filename=\"garrison-macro-test.docm\"\r\n"));
    assert!(message.ends_with("\r\n--garrison-mail-test--\r\n.\r\nQUIT\r\n"));
    // What travels is what the milter's scan finds, in lines a mail may have.
    let body = message.split_once("\r\nDATA\r\n").unwrap().1;
    assert!(matches!(
        garrison_milter::scan::macros(body.as_bytes()),
        garrison_milter::scan::Outcome::Macros(_)
    ));
    // No line near the 998 bytes a mail's line may have.
    assert!(body.lines().all(|line| line.len() <= 100), "{body}");

    // The result was kept with the macro test: switched off, the provider
    // tests anew, without the document; and on again likewise.
    let (port, handle) = server([
        "550 virus",
        "550 spam",
        "250 2.0.0 Message queued with id d.",
    ]);
    let without = collected(&provider(port), &memory, 60, &[]);
    assert_eq!(
        results(&without),
        ["refused: 550 virus", "refused: 550 spam", "accepted"]
    );
    assert_eq!(handle.join().unwrap().len(), 3);

    // A document that is taken means nothing filters macros.
    let (port, handle) = server([
        "550 virus",
        "550 spam",
        "250 2.0.0 Message queued with id a.",
        "250 2.0.0 Message queued with id e.",
    ]);
    let taken = collected(&with_macros(port), &memory, 120, &[]);
    handle.join().unwrap();
    assert_eq!(taken.state, State::Failed);
    assert_eq!(
        taken.findings,
        [
            "Office document with macros (test document): accepted: no filter refused \
             the test document."
        ]
    );
}

#[test]
fn the_greeting_and_the_message_id_name_the_host_without_its_port() {
    for (origin, host) in [
        ("https://garrison.example.org:8443", "garrison.example.org"),
        ("https://[2001:db8::1]:8443", "[2001:db8::1]"),
        ("https://garrison.example.org", "garrison.example.org"),
    ] {
        let (port, handle) = server([
            "250 2.0.0 Message queued with id a.",
            "250 2.0.0 Message queued with id b.",
        ]);
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        config.deployment.public_origin = origin.to_owned();
        let runner = Canned(String::new());
        let context = crate::testing::context(&config, &runner);
        provider(port).collect(&context).unwrap();
        let sessions = handle.join().unwrap();
        for session in &sessions {
            assert!(
                session.starts_with(&format!("EHLO {host}\r\n")),
                "{origin}: {session}"
            );
            assert!(
                session.contains(&format!("@{host}>\r\n")),
                "{origin}: {session}"
            );
        }
    }
}

#[test]
fn replies_queue_ids_and_options() {
    let mut several = BufReader::new(&b"250-first\r\n250-second\r\n250 last line\r\n"[..]);
    assert_eq!(reply(&mut several), Ok((250, "250 last line".to_owned())));
    assert!(reply(&mut BufReader::new(&b""[..])).is_err());
    assert!(reply(&mut BufReader::new(&b"hello\r\n"[..])).is_err());
    assert_eq!(
        queue_id("250 2.0.0 Message queued with id 4b786a616e00000.").as_deref(),
        Some("339888344796233728")
    );
    assert_eq!(queue_id("250 2.0.0 OK"), None);
    assert_eq!(queue_id("250 queued with id zz."), None);
    for wrong in [
        "",
        "recipient = \"nobody\"",
        "recipient = \"a@example.test\"\nhost = \"mail.example.org\"",
        "recipient = \"a@example.test\"\nsender = \"<x>\"",
        "recipient = \"a@example.test\"\nevery_hours = 0",
        "recipient = \"a b@example.test\"",
        "recipient = \"a@example.test\"\nmacro_document = \"yes\"",
    ] {
        assert!(
            MailTest::new(&table(&format!("type = \"mail-test\"\n{wrong}"))).is_err(),
            "{wrong}"
        );
    }
    // The test file is not in this program as one piece.
    assert_eq!(Test::Eicar.body().len(), 68);
}

#[test]
fn a_reply_line_without_an_end_is_read_only_so_far() {
    use std::io::Read as _;
    // A greeting of 64 MiB without an end of line: the session gives up
    // after the longest line a reply may have, and reads no further.
    let mut source = BufReader::new(std::io::repeat(b'2').take(64 << 20));
    assert_eq!(
        reply(&mut source),
        Err("the server's reply is too long".to_owned())
    );
    let read = (64 << 20) - source.get_ref().limit();
    assert!(read < 64 << 10, "{read} bytes read");
}
