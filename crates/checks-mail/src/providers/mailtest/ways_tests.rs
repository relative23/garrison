//! The card's rule, held over the ways a mail server can answer the test
//! messages: it is in order only where the scanner and the spam filter were
//! shown to refuse the test messages for what they are, each in the round
//! it was sent in; whatever is not shown is not in order, and a server that
//! takes no mail at all is a warning, which reaches an operator.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use super::tests::{collected, results};
use super::*;
use crate::context::Memory;
use crate::testing::{Remembered, now, table};

/// How a server answers a message at its end, from what it carries and how
/// many messages came before it.
type Way = fn(&str, usize) -> &'static str;

/// Every message taken gets this queue ID, 192 in the event history.
const TAKEN: &str = "250 2.0.0 Message queued with id c0.";
const REFUSED: &str = "550 5.7.1 Refused";
const DEFERRED: &str = "451 4.3.5 Unable to accept message at this time.";

/// Whether a message carries what a scanner or a filter refuses: the test
/// file, the spam text, a document with a macro project.
fn harmful(message: &str) -> bool {
    ["EICAR-STANDARD", "GTUBE-STANDARD", "macro-test.docm"]
        .iter()
        .any(|mark| message.contains(mark))
}

/// A scanner and a spam filter at work.
fn by_content(message: &str, _: usize) -> &'static str {
    if harmful(message) { REFUSED } else { TAKEN }
}

/// A scanner at work; the spam text is taken, and filed as spam.
fn by_content_but_spam(message: &str, turn: usize) -> &'static str {
    if message.contains("GTUBE-STANDARD") {
        TAKEN
    } else {
        by_content(message, turn)
    }
}

/// No scanner, no filter.
fn everything(_: &str, _: usize) -> &'static str {
    TAKEN
}

/// A scanner that fails closed while it cannot scan, as clamav-milter with
/// `OnFail Reject` while clamd is down.
fn nothing(_: &str, _: usize) -> &'static str {
    REFUSED
}

/// A scanner that cannot scan and says to try again later.
fn later(_: &str, _: usize) -> &'static str {
    DEFERRED
}

/// Every second message refused whatever it carries, the others taken
/// without a look, from the first message on.
fn by_turns(_: &str, turn: usize) -> &'static str {
    if turn.is_multiple_of(2) {
        REFUSED
    } else {
        TAKEN
    }
}

/// The same from the second message on.
fn by_other_turns(_: &str, turn: usize) -> &'static str {
    if turn.is_multiple_of(2) {
        TAKEN
    } else {
        REFUSED
    }
}

/// A scanner at work beside a policy that refuses every attachment.
fn no_attachments(message: &str, turn: usize) -> &'static str {
    if message.contains("Content-Disposition: attachment") {
        REFUSED
    } else {
        by_content(message, turn)
    }
}

/// A server that answers each message as `way` says, for as long as the
/// test runs.
struct Answering {
    port: u16,
    done: Arc<AtomicBool>,
    handle: thread::JoinHandle<Vec<String>>,
}

impl Answering {
    fn new(way: Way) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let done = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&done);
        let handle = thread::spawn(move || {
            let mut sessions = Vec::new();
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => sessions.push(session(stream, way, sessions.len())),
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
            sessions
        });
        Answering { port, done, handle }
    }

    /// What it was sent, one session after another.
    fn sessions(self) -> Vec<String> {
        self.done.store(true, Ordering::SeqCst);
        self.handle.join().unwrap()
    }
}

/// One session, whose message is the `turn`th the server answers.
fn session(stream: TcpStream, way: Way, turn: usize) -> String {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    writer
        .write_all(b"220 mail.example.test ESMTP\r\n")
        .unwrap();
    let (mut seen, mut message, mut in_data) = (String::new(), String::new(), false);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        seen.push_str(&line);
        let reply = if in_data {
            if line != ".\r\n" {
                message.push_str(&line);
                continue;
            }
            in_data = false;
            format!("{}\r\n", way(&message, turn))
        } else if line.starts_with("EHLO") {
            "250-mail.example.test\r\n250 8BITMIME\r\n".to_owned()
        } else if line.starts_with("DATA") {
            in_data = true;
            "354 go ahead\r\n".to_owned()
        } else if line.starts_with("QUIT") {
            break;
        } else {
            "250 2.1.0 OK\r\n".to_owned()
        };
        if writer.write_all(reply.as_bytes()).is_err() {
            break;
        }
    }
    seen
}

/// The mail test with the macro test where `macros`.
fn test(port: u16, macros: bool) -> MailTest {
    MailTest::new(&table(&format!(
        "type = \"mail-test\"\nrecipient = \"garrison-test@example.test\"\nport = {port}\n\
         macro_document = {macros}"
    )))
    .unwrap()
}

/// The card of a run against a server that answers `way`, after what an
/// earlier run kept in `memory`; the event history files the queue ID every
/// taken message gets as spam.
fn card(way: Way, macros: bool, memory: &Remembered) -> (Observation, Vec<String>) {
    let server = Answering::new(way);
    let card = collected(
        &test(server.port, macros),
        memory,
        0,
        &[("192", "message-ingest.spam")],
    );
    (card, server.sessions())
}

/// What a release before this one kept of two tests the server refused
/// `hours` before, made for the configuration as it is: 0.1.2 kept one time
/// for the round and nothing beside the refusals; the release after it a
/// time for each and a harmless message the server took.
fn kept_before(hours: i64, harmless: bool) -> Remembered {
    let memory = Remembered::default();
    let at = now().as_second() - hours * 3600;
    let mut refused = json!({"reply": "503 5.5.3 Message rejected.", "code": 503, "queue": null, "at_data": true});
    let mut kept = json!({"at": at, "macros": null});
    if harmless {
        refused["at"] = json!(at);
        kept["control"] =
            json!({"reply": TAKEN, "code": 250, "queue": "192", "at_data": true, "at": at});
    }
    kept["eicar"] = refused.clone();
    kept["gtube"] = refused;
    memory.keep(MEMORY, &kept.to_string());
    memory
}

#[test]
fn the_card_is_in_order_only_where_the_tests_were_refused_for_what_they_carry() {
    let ways: [(&str, Way, bool, State); 11] = [
        ("by content", by_content, false, State::Ok),
        ("by content, macro test on", by_content, true, State::Ok),
        (
            "by content, spam filed",
            by_content_but_spam,
            false,
            State::Ok,
        ),
        ("everything taken", everything, false, State::Failed),
        ("nothing taken", nothing, false, State::Warning),
        ("everything deferred", later, false, State::Unknown),
        ("by turns", by_turns, false, State::Failed),
        ("by turns, macro test on", by_turns, true, State::Failed),
        ("by the other turns", by_other_turns, false, State::Failed),
        (
            "by the other turns, macro test on",
            by_other_turns,
            true,
            State::Failed,
        ),
        (
            "no attachments, macro test on",
            no_attachments,
            true,
            State::Unknown,
        ),
    ];
    let mut wrong = Vec::new();
    for (name, way, macros, expected) in ways {
        let (card, _) = card(way, macros, &Remembered::default());
        if card.state != expected {
            wrong.push(format!("{name}: {:?} {:?}", card.state, results(&card)));
        }
    }
    // Refusals a release before kept, each from a round of its own: the
    // server takes everything now.
    for (name, hours, harmless) in [
        ("0.1.2's refusals of 20 hours before", 20, false),
        ("the next release's refusals of 2 hours before", 2, true),
    ] {
        let memory = kept_before(hours, harmless);
        let (card, _) = card(everything, false, &memory);
        if card.state != State::Failed {
            wrong.push(format!("{name}: {:?} {:?}", card.state, results(&card)));
        }
    }
    assert_eq!(wrong, Vec::<String>::new());
}
