//! Stalwart's webhook delivers what the receiver expects.
//!
//! Configures a signed webhook on the lab instance that points to this
//! receiver, sends mail over SMTP and checks the stored events: signature
//! accepted, span IDs present, SMTP session milestones recorded and private
//! fields dropped. Needs `GARRISON_LAB_SMTP` (the container's address) and
//! `GARRISON_LAB_CALLBACK_HOST` (an address of this machine the container can
//! reach) besides the lab variables, as `cargo xtask lab start` prints
//! them; run with `cargo test --workspace --test contract -- --ignored`.

// Helpers fail the test by panicking, like the test itself.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use garrison_core::sqlite::reading;
use garrison_ingest::answers::SessionSummary;
use garrison_ingest::app::router;
use garrison_ingest::attacks;
use garrison_ingest::policy::event_types;
use garrison_ingest::queries::{self, Filter};
use garrison_ingest::store::{EventStore, Limits};
use garrison_testing::lab::{Lab, random_hex};
use garrison_testing::smtp::Smtp;
use serde_json::{Value, json};

fn create_webhook(lab: &mut Lab, url: &str, key: &str) {
    let events: Value = event_types()
        .into_iter()
        .map(|name| (name.to_owned(), json!(true)))
        .collect();
    lab.create(
        "WebHook",
        &json!({
            "url": url,
            "events": events,
            "eventsPolicy": "include",
            "level": "trace",
            "timeout": 5000,
            "throttle": 500,
            "discardAfter": 60000,
            "lossy": false,
            "signatureKey": {"@type": "Value", "secret": key},
            "httpAuth": {"@type": "Unauthenticated"},
            "httpHeaders": {},
            "allowInvalidCerts": false,
            "enable": true,
        }),
    );
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
}

/// One SMTP session whose only recipient does not exist.
fn send_refused_mail(smtp: &str) {
    let mut session = Smtp::connect(smtp);
    assert!(
        session
            .command("EHLO contract.example.net")
            .starts_with("250")
    );
    assert!(
        session
            .command("MAIL FROM:<sender@example.net>")
            .starts_with("250")
    );
    let refused = session.command("RCPT TO:<missing@example.test>");
    assert!(refused.starts_with('5'), "{refused}");
    session.command("QUIT");
}

/// The first ended session that matches, once the webhook delivered it.
fn wait_for_session(path: &Path) -> SessionSummary {
    let deadline = Instant::now() + Duration::from_secs(30);
    let filter = Filter {
        search: "contract.example".into(),
        ..Filter::default()
    };
    loop {
        assert!(
            Instant::now() < deadline,
            "No complete SMTP session arrived through the webhook"
        );
        std::thread::sleep(Duration::from_secs(1));
        let Some(db) = reading(path, Duration::from_secs(2)).unwrap() else {
            continue;
        };
        let page = queries::list_sessions(&db, &filter).unwrap();
        let complete = page.items.into_iter().find(|item| item.milestones.complete);
        if let Some(item) = complete {
            return item;
        }
    }
}

/// What the summary of sender checks reads: of a check only the name of its
/// outcome is kept, such as `spf.none`.
fn sender_checks_keep_their_outcome(events: &[garrison_ingest::answers::EventItem]) {
    let outcome = events
        .iter()
        .find(|event| event.event_type.starts_with("smtp.spf-"))
        .and_then(|event| event.fields.get("result"))
        .and_then(Value::as_str);
    assert!(
        outcome.is_some_and(|outcome| outcome.starts_with("spf.")),
        "{outcome:?}"
    );
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_signed_webhook_records_a_complete_smtp_session() {
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
    let app = router(store, key.as_bytes());
    runtime.spawn(async move { axum::serve(listener, app).await });
    create_webhook(&mut lab, &format!("http://{callback}:{port}/webhook"), &key);
    std::thread::sleep(Duration::from_secs(2));
    send_refused_mail(&smtp);

    let session = wait_for_session(&path).milestones;
    assert_eq!(session.ehlo.as_deref(), Some("contract.example.net"));
    assert_eq!(session.from.as_deref(), Some("sender@example.net"));
    assert!(session.rejections.contains(&"Mailbox does not exist"));
    assert!(session.complete);

    // A reader holds the file against the receiver while it is open, so it
    // is closed before more mail is sent.
    {
        let db = reading(&path, Duration::from_secs(2)).unwrap().unwrap();
        let events = queries::list_events(
            &db,
            &Filter {
                limit: 100,
                ..Filter::default()
            },
        )
        .unwrap();
        for event in &events.items {
            let span = event.span_id.as_deref().unwrap_or_default();
            assert!(span.bytes().all(|byte| byte.is_ascii_digit()), "{span}");
            if event.category == "smtp" {
                assert!(!event.fields.contains_key("details"), "{event:?}");
            }
        }
        sender_checks_keep_their_outcome(&events.items);
    }

    // What the collector's mail test relies on: an accepted message is named
    // with its queue ID in hex, and the event that files it carries the same
    // ID as a number. (The lab files every stranger's mail as spam; that the
    // filter knows the test text is held in the collector's contract test.)
    let mut session = Smtp::connect(&smtp);
    for command in [
        "EHLO contract.example.net",
        "MAIL FROM:<>",
        "RCPT TO:<admin@example.test>",
    ] {
        let reply = session.command(command);
        assert!(reply.starts_with("250"), "{command}: {reply}");
    }
    assert!(session.command("DATA").starts_with("354"));
    let text = [
        "XJS*C4JDBQADN1.NSBN3*2IDNEN*",
        "GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL",
        "*C.34X",
    ]
    .concat();
    // Stalwart files a message it has seen before as a duplicate, so every
    // run names its own.
    let accepted = session.command(&format!(
        "From: <garrison-test@contract.example.net>\r\nTo: <admin@example.test>\r\n\
         Subject: Garrison mail test\r\nMessage-ID: <{}@contract.example.net>\r\n\r\n\
         {text}\r\n.",
        random_hex(8)
    ));
    session.command("QUIT");
    assert!(
        accepted.starts_with("250") && accepted.contains("with id "),
        "{accepted}"
    );
    let hex = accepted
        .trim()
        .rsplit_once("with id ")
        .unwrap()
        .1
        .trim_end_matches('.');
    let queue = u64::from_str_radix(hex, 16).unwrap().to_string();
    let deadline = Instant::now() + Duration::from_secs(30);
    let filed = loop {
        // The receiver may be writing at this moment.
        let Ok(Some(db)) = reading(&path, Duration::from_secs(2)) else {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        let kinds: Vec<String> = db
            .prepare("SELECT type FROM events WHERE queue_id=?")
            .unwrap()
            .query_map([&queue], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        if kinds.iter().any(|kind| kind.starts_with("message-ingest.")) {
            break kinds;
        }
        assert!(
            Instant::now() < deadline,
            "No filing event arrived for queue {queue}: {kinds:?}"
        );
        std::thread::sleep(Duration::from_secs(1));
    };
    // One of the two verdicts the mail test reads.
    let known = |kind: &String| kind == "message-ingest.spam" || kind == "message-ingest.ham";
    assert!(filed.iter().any(known), "{filed:?}");

    failed_sign_ins_are_recorded(&lab, &path);
}

/// What the attack summary relies on: Stalwart reports a refused sign-in with
/// the address it came from, and names the account only where it found one.
/// Two attempts stay far below the number that would ban this address.
fn failed_sign_ins_are_recorded(lab: &Lab, path: &Path) {
    let account = lab.admin_name().to_owned();
    let stranger = format!("stranger-{}", random_hex(6));
    assert_eq!(
        lab.sign_in_status(&format!("{account}:wrong-{}", random_hex(8))),
        401
    );
    assert_eq!(
        lab.sign_in_status(&format!("{stranger}:wrong-{}", random_hex(8))),
        401
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let summary = loop {
        std::thread::sleep(Duration::from_secs(1));
        // The receiver may be writing at this moment.
        let Ok(Some(db)) = reading(path, Duration::from_secs(2)) else {
            continue;
        };
        let summary = attacks::attacks(&db, 0, i64::MAX).unwrap();
        if summary.totals.failed_sign_ins >= 2 {
            let stored: Vec<String> = db
                .prepare("SELECT fields FROM events WHERE type='auth.failed'")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            // A name that is no account, and every password, stay out of the history.
            assert!(
                stored
                    .iter()
                    .all(|fields| !fields.contains(&stranger) && !fields.contains("wrong-")),
                "{stored:?}"
            );
            assert!(
                stored.iter().any(|fields| fields.contains("\"reason\"")),
                "{stored:?}"
            );
            break summary;
        }
        assert!(
            Instant::now() < deadline,
            "The failed sign-ins did not arrive through the webhook: {summary:?}"
        );
    };
    assert_eq!(summary.totals.unknown_accounts, 1, "{summary:?}");
    let tried: Vec<&str> = summary
        .accounts
        .iter()
        .map(|tried| tried.name.as_str())
        .collect();
    assert_eq!(tried, [account.as_str()]);
    let source = &summary.sources[0];
    assert_eq!(
        (source.failed_sign_ins, source.accounts),
        (2, 1),
        "{source:?}"
    );
    assert!(
        source.address.parse::<std::net::IpAddr>().is_ok(),
        "{source:?}"
    );
    assert_eq!(source.listeners, ["http"]);
}
