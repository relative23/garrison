//! Where Stalwart did not give the collector's key its accounts, the mail
//! filed by domain is counted under "unknown", and the card by domain says
//! why, each kind of failure in words of its own: Stalwart did not complete
//! the request, and how, refused the key for its rate limit, refused the
//! key, which the setup mends, or answered in a form this release does not
//! read, which names the answer and the supported Stalwart releases. The
//! next run asks Stalwart again, and the card follows its answer.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::thread;

use garrison_testing::http::{answer, json as answer_json, serve};
use serde_json::json;

use super::tests::{Event, event, history, of, rows};
use super::*;
use crate::testing::{Canned, Receiver, Remembered, table};

/// A day of ham and spam for account 1.
fn day() -> [Event; 2] {
    [
        event("message-ingest.ham", 60, json!({"accountId": 1})),
        event("message-ingest.spam", 90, json!({"accountId": 1})),
    ]
}

/// The card by domain over `events`, where Stalwart answers the collector's
/// requests for its accounts with `answers` in turn (with none, at a port
/// where nothing listens), as `memory` keeps it; and Stalwart.
fn by_domain_over(
    events: &[Event],
    answers: Vec<String>,
    memory: &Remembered,
) -> (Observation, Option<garrison_testing::http::Server>) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = history(directory.path(), &Receiver::default(), events, 0);
    let stalwart = (!answers.is_empty()).then(|| serve(answers));
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
    (of(&observations, "flow.spam-domains").clone(), stalwart)
}

/// The same over a day, where Stalwart answers its one request with
/// `answer`.
fn by_domain(answer: Option<String>, memory: &Remembered) -> Observation {
    let (card, stalwart) = by_domain_over(&day(), answer.into_iter().collect(), memory);
    if let Some(stalwart) = stalwart {
        stalwart.requests();
    }
    card
}

/// Stalwart's answer that names account 1's address.
fn accounts() -> String {
    answer_json(&json!({"methodResponses": [["x:Account/get", {"list": [
        {"id": "b", "emailAddress": "anna@example.test"}
    ]}, "0"]]}))
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
    let named = by_domain(Some(accounts()), &Remembered::default());
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

/// Where Stalwart did not give the accounts, each run asks it again, alone:
/// setup may change only the key's rights, so nothing but asking shows the
/// change. The reading is made anew once Stalwart answers otherwise, and
/// kept with its counts, for its ten minutes, while it answers the same.
#[test]
fn the_card_by_domain_follows_stalwarts_next_answer() {
    let memory = Remembered::default();
    let (refused, stalwart) = by_domain_over(&day(), vec![answer(403, "")], &memory);
    assert!(
        refused.findings[0].contains("garrison stalwart setup"),
        "{refused:?}"
    );
    stalwart.unwrap().requests();
    // Setup gave the key its rights: the next run names the domains.
    let (named, stalwart) = by_domain_over(&day(), vec![accounts(), accounts()], &memory);
    assert_eq!(
        (named.state, named.findings.clone(), rows(&named)),
        (
            State::Ok,
            Vec::<String>::new(),
            vec!["example.test | 1 | 1 | 50 %".to_owned()]
        )
    );
    stalwart.unwrap().requests();

    let memory = Remembered::default();
    let (limited, stalwart) = by_domain_over(&day(), vec![answer(429, "")], &memory);
    stalwart.unwrap().requests();
    let mut more = day().to_vec();
    more.push(event("message-ingest.ham", 120, json!({"accountId": 1})));
    // The same answer: the reading stays, though the history has more now.
    let (kept, stalwart) = by_domain_over(&more, vec![answer(429, "")], &memory);
    assert_eq!(
        (kept.findings.clone(), rows(&kept)),
        (limited.findings, vec!["unknown | 1 | 1 | 50 %".to_owned()])
    );
    assert_eq!(stalwart.unwrap().requests().len(), 1);
    // Another answer: read anew, with its words.
    let (other, stalwart) = by_domain_over(&more, vec![answer(503, ""), answer(503, "")], &memory);
    assert_eq!(
        (other.findings.clone(), rows(&other)),
        (
            vec![
                "The domains of the mailboxes are not known: Stalwart did not complete the \
                 collector's request for its accounts (Stalwart answered HTTP 503)."
                    .to_owned()
            ],
            vec!["unknown | 2 | 1 | 33 %".to_owned()]
        )
    );
    stalwart.unwrap().requests();
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
