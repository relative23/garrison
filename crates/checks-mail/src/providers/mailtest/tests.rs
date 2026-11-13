use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;

use super::*;
use crate::context::Context;
use crate::testing::{Canned, Remembered, config, now, table};

/// A mail server for one session per reply: it answers the message of each
/// session with the reply given for it and returns what it was sent.
fn server<const SESSIONS: usize>(
    replies: [&'static str; SESSIONS],
) -> (u16, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let mut sessions = Vec::new();
        for answer in replies {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut seen = String::new();
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

fn provider(port: u16) -> MailTest {
    MailTest::new(&table(&format!(
        "type = \"mail-test\"\nrecipient = \"garrison-test@example.test\"\nport = {port}"
    )))
    .unwrap()
}

/// One collection `later` seconds after the tests' clock, with `events` in
/// the event history as `(queue ID, type)`.
fn collected(
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

fn results(observation: &Observation) -> Vec<&str> {
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
    ]);
    let provider = provider(port);
    let memory = Remembered::default();
    // Right after the session nothing is known of the accepted message yet.
    let first = collected(&provider, &memory, 0, &[]);
    assert_eq!(first.state, State::Unknown);
    assert_eq!(
        results(&first),
        [
            "refused: 550 5.7.1 Virus found: Eicar-Signature",
            "accepted; the event history does not show yet how it was filed",
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
    assert_eq!(filed.modules, [ModuleId::Antivirus, ModuleId::Spam].into());
    let sessions = handle.join().unwrap();
    assert_eq!(sessions.len(), 2);
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
            "refused: 451 4.7.1 try later",
            "accepted; the event history never showed how it was filed",
        ]
    );
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
    let (port, handle) = server(["550 virus", "550 spam", refusal]);
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
    assert!(garrison_milter::scan::macros(body.as_bytes()).is_some());
    // No line near the 998 bytes a mail's line may have.
    assert!(body.lines().all(|line| line.len() <= 100), "{body}");

    // The result was kept with the macro test: switched off, the provider
    // tests anew, without the document; and on again likewise.
    let (port, handle) = server(["550 virus", "550 spam"]);
    let without = collected(&provider(port), &memory, 60, &[]);
    assert_eq!(results(&without).len(), 2);
    assert_eq!(handle.join().unwrap().len(), 2);

    // A document that is taken means nothing filters macros.
    let (port, handle) = server([
        "550 virus",
        "550 spam",
        "250 2.0.0 Message queued with id a.",
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
fn a_test_is_repeated_only_after_its_hours_and_no_session_is_no_result() {
    // Nothing listens there: unknown, with the reason, and kept like a result.
    let silent = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let provider = provider(silent);
    let memory = Remembered::default();
    let none = collected(&provider, &memory, 0, &[]);
    assert_eq!(none.state, State::Unknown);
    assert!(
        results(&none)[0].starts_with("not tested: no session: "),
        "{:?}",
        results(&none)
    );
    // After a day the next test: now a server answers.
    let (port, handle) = server(["550 no", "550 no"]);
    let provider = self::provider(port);
    assert_eq!(
        collected(&provider, &memory, 86_399, &[]).state,
        State::Unknown
    );
    assert_eq!(collected(&provider, &memory, 86_400, &[]).state, State::Ok);
    handle.join().unwrap();
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
