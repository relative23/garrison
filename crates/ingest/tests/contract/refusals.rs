//! What a session's rejections on the Sessions page rely on: Stalwart sends
//! an event of its own for each refusal of a session's mail or commands,
//! under the session's span, so the summary of the session names it.

use std::collections::BTreeSet;
use std::fmt::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use garrison_core::sqlite::reading;
use garrison_ingest::app::router;
use garrison_ingest::queries::{self, Filter};
use garrison_ingest::store::{EventStore, Limits};
use garrison_testing::lab::{Lab, random_hex};
use garrison_testing::smtp::Smtp;

use super::{create_webhook, one_at_a_time};

const GREETING: &str = "refusals.example.net";
/// Each refusal the sessions below meet, as the Sessions page names it.
const REFUSED: [&str; 12] = [
    "Too many invalid recipients",
    "From names several domains",
    "Mail loop detected",
    "Too many messages",
    "No EHLO first",
    "No MAIL FROM first",
    "Second MAIL FROM",
    "Invalid command",
    "Invalid sender address",
    "Unsupported parameter",
    "DSN not offered",
    "Authentication not allowed",
];

fn message(subject: &str, headers: &str, from: &str) -> String {
    format!(
        "{headers}From: {from}\r\nTo: <admin@example.test>\r\nSubject: {subject}\r\n\
         Message-ID: <{}@{GREETING}>\r\n\r\nA refusal of the contract test.\r\n.",
        random_hex(8)
    )
}

/// The rejections of every session this test opened, once all of `wanted`
/// arrived.
fn rejections_once(path: &Path, wanted: &[&str]) -> BTreeSet<String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        std::thread::sleep(Duration::from_secs(1));
        // The receiver may be writing at this moment.
        if let Ok(Some(db)) = reading(path, Duration::from_secs(2)) {
            let filter = Filter {
                limit: 100,
                ..Filter::default()
            };
            let page = queries::list_sessions(&db, &filter).unwrap();
            let seen: BTreeSet<String> = page
                .items
                .iter()
                .filter(|item| item.milestones.ehlo.as_deref() == Some(GREETING))
                .flat_map(|item| {
                    item.milestones
                        .rejections
                        .iter()
                        .map(|&reason| reason.to_owned())
                })
                .collect();
            if wanted.iter().all(|reason| seen.contains(*reason)) {
                return seen;
            }
            assert!(Instant::now() < deadline, "{seen:?}");
        }
    }
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn stalwart_names_what_it_refused_in_a_session() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    let key = random_hex(32);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.sqlite");
    let store = Arc::new(EventStore::open(&path, Limits::new(30, 10_000, 64 << 20)).unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind((callback.as_str(), 0)))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = router(Arc::clone(&store), key.as_bytes());
    runtime.spawn(async move { axum::serve(listener, app).await });
    create_webhook(&mut lab, &format!("http://{callback}:{port}/webhook"), &key);
    std::thread::sleep(Duration::from_secs(2));

    // Recipients that do not exist, until Stalwart ends the session; five
    // are far below the number that would ban this address.
    let mut session = Smtp::connect(&smtp);
    session.command(&format!("EHLO {GREETING}"));
    session.command("MAIL FROM:<sender@example.net>");
    for index in 1..=5 {
        let reply = session.command(&format!(
            "RCPT TO:<missing-{index}-{}@example.test>",
            random_hex(3)
        ));
        if reply.starts_with("451") {
            break;
        }
    }
    drop(session);

    // Commands out of order, malformed or for what port 25 does not offer.
    let mut session = Smtp::connect(&smtp);
    for command in [
        "MAIL FROM:<sender@example.net>",
        &format!("EHLO {GREETING}"),
        "RCPT TO:<admin@example.test>",
        "XYZZY",
        "MAIL FROM:<bad",
        "MAIL FROM:<sender@example.net> FOO=BAR",
        "MAIL FROM:<sender@example.net> ENVID=one",
        "AUTH PLAIN",
        "MAIL FROM:<sender@example.net>",
        "MAIL FROM:<sender@example.net>",
        "QUIT",
    ] {
        session.command(command);
    }

    // Messages it refuses, and one more than a session may hand in.
    let mut session = Smtp::connect(&smtp);
    session.command(&format!("EHLO {GREETING}"));
    // One more hop than Stalwart takes (maxReceivedHeaders, 50 by default).
    let mut hops = String::new();
    for hop in 0..51 {
        let _ = write!(
            hops,
            "Received: from hop{hop}.example.net by hop{}.example.net; Tue, 24 Nov 2026 \
             12:00:00 +0000\r\n",
            hop + 1
        );
    }
    for (subject, headers, from) in [
        ("two domains", "", "<a@one.example>, <b@two.example>"),
        ("a loop", hops.as_str(), "<a@one.example>"),
    ] {
        for command in [
            "RSET",
            "MAIL FROM:<sender@example.net>",
            "RCPT TO:<admin@example.test>",
            "DATA",
        ] {
            session.command(command);
        }
        let refused = session.command(&message(subject, headers, from));
        assert!(
            refused.starts_with('4') || refused.starts_with('5'),
            "{subject}: {refused}"
        );
    }
    for index in 1..=11 {
        session.command("MAIL FROM:<sender@example.net>");
        session.command("RCPT TO:<admin@example.test>");
        if !session.command("DATA").starts_with("354") {
            break;
        }
        session.command(&message(&format!("message {index}"), "", "<a@one.example>"));
    }
    session.command("QUIT");

    let seen = rejections_once(&path, &REFUSED);
    assert!(
        REFUSED.iter().all(|reason| seen.contains(*reason)),
        "{seen:?}"
    );
}
