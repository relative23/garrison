//! A milter whose answer Stalwart cannot read, through the real receiver.
//!
//! Stalwart defers the message and says why with one event and no other of
//! a milter (measured with 1.2.1): `milter.frame-invalid` for an answer that
//! is no frame of the protocol, `milter.unexpected-response` for one that
//! does not belong where it comes. Each carries the milter's frame as text.
//! The receiver records that it happened, in which session, and keeps
//! nothing of the frame: not in the event and nowhere in its database.

use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use garrison_core::sqlite::reading;
use garrison_ingest::answers::EventItem;
use garrison_ingest::queries::{self, Filter};
use garrison_ingest::store::{EventStore, Limits};
use garrison_testing::lab::{Lab, random_hex};
use garrison_testing::milter::{self as protocol, Command, Reply};
use garrison_testing::smtp::Smtp;
use serde_json::json;

use super::{create_webhook, one_at_a_time};

/// What the stand-in adds as a header without its value; no message and no
/// event holds these words otherwise.
const MARKER: &str = "X-Garrison-Frame-Marker-7f3a9c";
/// The frame's data, `h` and the marker, in base64, as Stalwart 1.2.1 sends
/// it with the event.
const MARKER_SENT: &str = "aFgtR2Fycmlzb24tRnJhbWUtTWFya2VyLTdmM2E5Yw==";

/// A milter on `host` that negotiates in order and answers each message's
/// end with `raw`.
fn answering(host: &str, raw: Vec<u8>) -> u16 {
    let listener = TcpListener::bind((host, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let (mut stream, raw) = (stream.unwrap(), raw.clone());
            std::thread::spawn(move || {
                while let Ok(Some(command)) = protocol::read(&mut stream) {
                    let written = match command {
                        Command::Negotiate { .. } => protocol::write(
                            &mut stream,
                            &Reply::Negotiate {
                                actions: 0,
                                protocol: 0,
                            },
                        ),
                        Command::EndOfBody => stream.write_all(&raw),
                        Command::Quit => break,
                        Command::Abort | Command::Other(b'D') => continue,
                        _ => protocol::write(&mut stream, &Reply::Continue),
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

/// One message to the lab's administrator; the reply to its end.
fn handed_in(smtp: &str) -> String {
    let mut session = Smtp::connect(smtp);
    for (line, code) in [
        ("EHLO contract.example.net", "250"),
        ("MAIL FROM:<sender@example.net>", "250"),
        ("RCPT TO:<admin@example.test>", "250"),
        ("DATA", "354"),
    ] {
        let reply = session.command(line);
        assert!(reply.starts_with(code), "{line}: {reply}");
    }
    let reply = session.command("Subject: a milter Stalwart cannot read\r\n\r\nHello.\r\n.");
    session.command("QUIT");
    reply
}

/// The recorded events of milters, once one of `kind` is among them.
fn milter_events(path: &Path, kind: &str) -> Vec<EventItem> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        std::thread::sleep(Duration::from_secs(1));
        // The receiver may be writing at this moment.
        if let Ok(Some(db)) = reading(path, Duration::from_secs(2)) {
            let filter = Filter {
                category: "milter".to_owned(),
                ..Filter::default()
            };
            let events = queries::list_events(&db, &filter).unwrap().items;
            if events.iter().any(|event| event.event_type == kind) {
                return events;
            }
            assert!(Instant::now() < deadline, "no {kind} among {events:?}");
        }
    }
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_milter_answer_stalwart_cannot_read_is_recorded_without_its_frame() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let key = random_hex(32);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.sqlite");
    let store = Arc::new(EventStore::open(&path, Limits::new(30, 10_000, 64 << 20)).unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind((callback.as_str(), 0)))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = garrison_ingest::app::router(Arc::clone(&store), key.as_bytes());
    runtime.spawn(async move { axum::serve(listener, app).await });
    create_webhook(&mut lab, &format!("http://{callback}:{port}/webhook"), &key);

    // A header to add that ends before its value, and a second negotiation
    // where a verdict belongs.
    let mut header = vec![0, 0, 0, 0, b'h'];
    header.extend(MARKER.as_bytes());
    header[3] = u8::try_from(header.len() - 4).unwrap();
    let mut negotiation = Vec::new();
    let again = Reply::Negotiate {
        actions: 0,
        protocol: 0,
    };
    protocol::write(&mut negotiation, &again).unwrap();
    let mut seen = 0;
    for (kind, raw) in [
        ("milter.frame-invalid", header),
        ("milter.unexpected-response", negotiation),
    ] {
        let milter = answering(&callback, raw);
        if seen > 0 {
            // The entry of the milter before, made last.
            let (entry, id) = lab.created.pop().unwrap();
            lab.call(&format!("x:{entry}/set"), &json!({"destroy": [id]}));
        }
        lab.create(
            "MtaMilter",
            &json!({"host": callback, "port": milter, "tempFailOnError": true}),
        );
        lab.call(
            "x:Action/set",
            &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
        );
        std::thread::sleep(Duration::from_secs(2));

        let reply = handed_in(&smtp);
        assert!(reply.starts_with("451"), "{kind}: {reply}");
        // That event, and no other of a milter since the one before.
        let events = milter_events(&path, kind);
        let kinds: Vec<&str> = events[..events.len() - seen]
            .iter()
            .map(|event| event.event_type.as_str())
            .collect();
        assert_eq!(kinds, [kind], "{events:?}");
        seen = events.len();
        let event = &events[0];
        let mut fields: Vec<&str> = event.fields.keys().map(String::as_str).collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "elapsed",
                "listenerId",
                "localPort",
                "remoteIp",
                "remotePort",
                "spanId"
            ],
            "{event:?}"
        );
        assert_eq!(event.fields["listenerId"], "smtp", "{event:?}");
    }

    // Nothing of either frame is in the receiver's files.
    drop(runtime);
    drop(store);
    for file in std::fs::read_dir(directory.path()).unwrap() {
        let file = file.unwrap().path();
        let bytes = std::fs::read(&file).unwrap();
        for words in [MARKER, MARKER_SENT, "OPTNEG"] {
            assert!(
                !bytes
                    .windows(words.len())
                    .any(|part| part == words.as_bytes()),
                "{} holds {words}",
                file.display()
            );
        }
    }
}
