//! Where Stalwart did not give the collector's key its accounts, the mail
//! filed by domain is counted under "unknown", and the card by domain says
//! why, each kind of failure in words of its own: Stalwart did not complete
//! the request, and how, refused the key for its rate limit, refused the
//! key, which the setup mends, or answered in a form this release does not
//! read, which names the answer and the supported Stalwart releases.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::thread;

use garrison_testing::http::{answer, json as answer_json, serve};
use serde_json::json;

use super::tests::{event, history, of, rows};
use super::*;
use crate::testing::{Canned, Receiver, Remembered, table};

/// The card by domain over a day of ham and spam for account 1, where
/// Stalwart answers the collector's request for its accounts with `answer`
/// (with none, at a port where nothing listens), as `memory` keeps it.
fn by_domain(answer: Option<String>, memory: &Remembered) -> Observation {
    let events = [
        event("message-ingest.ham", 60, json!({"accountId": 1})),
        event("message-ingest.spam", 90, json!({"accountId": 1})),
    ];
    let directory = tempfile::tempdir().unwrap();
    let mut config = history(directory.path(), &Receiver::default(), &events, 0);
    let stalwart = answer.map(|answer| serve(vec![answer]));
    if let Some(stalwart) = &stalwart {
        config.deployment.stalwart_url.clone_from(&stalwart.url);
    }
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".to_owned()),
        memory,
        ..crate::testing::context(&config, &runner)
    };
    let provider = Flow::new(&table("type = \"mail-flow\"")).unwrap();
    let observations = provider.collect(&context).unwrap().observations;
    if let Some(stalwart) = stalwart {
        stalwart.requests();
    }
    of(&observations, "flow.spam-domains").clone()
}

#[test]
fn the_card_by_domain_says_why_the_domains_of_the_mailboxes_are_not_known() {
    let method = |kind: &str| {
        Some(answer_json(
            &json!({"methodResponses": [["error", {"type": kind}, "0"]]}),
        ))
    };
    let incomplete = |how: &str| {
        format!("Stalwart did not complete the collector's request for its accounts ({how})")
    };
    let limited = "Stalwart refused the collector's key for its rate limit (HTTP 429), so its \
                   accounts could not be read";
    let refused = "Stalwart did not give its accounts to the collector's API key; run `garrison \
                   stalwart setup` again to let it read them";
    let unread = |why: &str| {
        format!(
            "Stalwart answered the collector's request for its accounts in a form this release \
             of Garrison does not read ({why}); see the supported Stalwart releases in the README"
        )
    };
    let cases = [
        ("closed", None, incomplete("Stalwart is unavailable")),
        (
            "503",
            Some(answer(503, "")),
            incomplete("Stalwart answered HTTP 503"),
        ),
        (
            "408",
            Some(answer(408, "")),
            incomplete("Stalwart answered HTTP 408"),
        ),
        (
            "serverFail",
            method("serverFail"),
            incomplete("Stalwart could not complete the request"),
        ),
        ("429", Some(answer(429, "")), limited.to_owned()),
        ("403", Some(answer(403, "")), refused.to_owned()),
        ("forbidden", method("forbidden"), refused.to_owned()),
        (
            "no JSON",
            Some(answer(200, "<html>Welcome</html>")),
            unread("Malformed native API response"),
        ),
        (
            "400",
            Some(answer(400, "")),
            unread("Unexpected native API status 400"),
        ),
        (
            "unknownMethod",
            method("unknownMethod"),
            unread("x:Account/get answered the error unknownMethod"),
        ),
    ];
    let found: Vec<(&str, State, Vec<String>, Vec<String>)> = cases
        .iter()
        .map(|(failure, answer, _)| {
            let card = by_domain(answer.clone(), &Remembered::default());
            (*failure, card.state, card.findings.clone(), rows(&card))
        })
        .collect();
    // The counts stay, under "unknown"; the card is not in order without
    // the domains it is about.
    let expected: Vec<(&str, State, Vec<String>, Vec<String>)> = cases
        .iter()
        .map(|(failure, _, words)| {
            (
                *failure,
                State::Unknown,
                vec![format!(
                    "The domains of the mailboxes are not known: {words}."
                )],
                vec!["unknown | 1 | 1 | 50 %".to_owned()],
            )
        })
        .collect();
    assert_eq!(found, expected);
    // Where Stalwart gives them, the domains are named and the card is in
    // order.
    let accounts = answer_json(&json!({"methodResponses": [["x:Account/get", {"list": [
        {"id": "b", "emailAddress": "anna@example.test"}
    ]}, "0"]]}));
    let named = by_domain(Some(accounts), &Remembered::default());
    assert_eq!(
        (named.state, named.findings.len(), rows(&named)),
        (State::Ok, 0, vec!["example.test | 1 | 1 | 50 %".to_owned()])
    );
}

/// A Stalwart that answers its one request with `answer`, `after` the
/// request came; its address, and its thread.
fn slow(answer: String, after: Duration) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        thread::sleep(after);
        reader.into_inner().write_all(answer.as_bytes()).unwrap();
    });
    (url, handle)
}

/// Stalwart is asked before the history is opened: an answer that takes
/// longer than the reader's two seconds costs no count, and the domains it
/// names are used.
#[test]
fn a_stalwart_slow_to_give_its_accounts_costs_no_count() {
    // Enough mail that SQLite looks at the reader's clock while it counts.
    let events: Vec<_> = (0..6_000)
        .map(|second| event("message-ingest.ham", 60 + second, json!({"accountId": 1})))
        .collect();
    let directory = tempfile::tempdir().unwrap();
    let mut config = history(directory.path(), &Receiver::default(), &events, 0);
    let accounts = answer_json(&json!({"methodResponses": [["x:Account/get", {"list": [
        {"id": "b", "emailAddress": "anna@example.test"}
    ]}, "0"]]}));
    let (url, stalwart) = slow(accounts, Duration::from_millis(2_500));
    config.deployment.stalwart_url = url;
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".to_owned()),
        ..crate::testing::context(&config, &runner)
    };
    let provider = Flow::new(&table("type = \"mail-flow\"")).unwrap();
    let observations = provider.collect(&context).unwrap().observations;
    stalwart.join().unwrap();
    for observation in &observations {
        assert_eq!(
            (observation.state, observation.findings.clone()),
            (State::Ok, Vec::<String>::new()),
            "{}",
            observation.id
        );
    }
    assert_eq!(
        rows(of(&observations, "flow.spam"))[0],
        "2026-10-29 | 6000 | 0 | 0 %"
    );
    assert_eq!(
        rows(of(&observations, "flow.spam-domains")),
        ["example.test | 6000 | 0 | 0 %"]
    );
}

/// The reading is kept for ten minutes, and why the domains are not known
/// with it.
#[test]
fn why_the_domains_are_not_known_is_kept_with_the_reading() {
    let memory = Remembered::default();
    let first = by_domain(Some(answer(429, "")), &memory);
    // Kept: Stalwart is not asked again; asked, the closed port would be
    // an outage.
    let kept = by_domain(None, &memory);
    assert_eq!(
        (kept.state, kept.findings.clone()),
        (first.state, first.findings.clone())
    );
    assert_eq!(kept.state, State::Unknown);
}

/// Without a key for Stalwart, as where its credential file is empty or
/// missing, the accounts are not asked for: the mail is counted under
/// "unknown", and the card by domain says that the domains are not known
/// and what makes a key, Unknown as for any other reason. The cards that
/// need no key are as they were.
#[test]
fn without_a_key_the_card_by_domain_says_what_makes_one() {
    let events = [
        event("message-ingest.ham", 60, json!({"accountId": 1})),
        event("message-ingest.spam", 90, json!({"accountId": 1})),
    ];
    let directory = tempfile::tempdir().unwrap();
    let config = history(directory.path(), &Receiver::default(), &events, 0);
    let runner = Canned(String::new());
    let context = crate::testing::context(&config, &runner);
    assert_eq!(context.native_key, None);
    let provider = Flow::new(&table("type = \"mail-flow\"")).unwrap();
    let observations = provider.collect(&context).unwrap().observations;
    let card = of(&observations, "flow.spam-domains");
    assert_eq!(
        (card.state, card.findings.clone(), rows(card)),
        (
            State::Unknown,
            vec![
                "The domains of the mailboxes are not known: the collector has no API key for \
                 Stalwart; run `garrison stalwart setup`, which makes one."
                    .to_owned()
            ],
            vec!["unknown | 1 | 1 | 50 %".to_owned()]
        )
    );
    for id in ["flow.spam", "flow.authentication", "flow.tls"] {
        let other = of(&observations, id);
        assert_eq!((other.state, other.findings.len()), (State::Ok, 0), "{id}");
    }
}
