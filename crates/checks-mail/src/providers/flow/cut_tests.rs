//! The lists by domain are read from the newest events of each kind and show
//! the busiest rows. A card whose list left anything out says so, and is
//! Partial where it would be in order for a cut of the events; the counts by
//! day and the numbers of mail with and without TLS count every event of the
//! week, whatever the lists take.

use serde_json::{Value, json};

use super::read::Limits;
use super::tests::{Event, event, history};
use super::*;
use crate::testing::objects::{Objects, objects};
use crate::testing::{Canned, Receiver, table};

/// Two of everything a list reads, each with a domain or host of its own,
/// and mail on port 25 from two sessions with STARTTLS and two without.
fn week() -> Vec<Event> {
    let mut events = Vec::new();
    for (index, domain) in [(1_i64, "a.example"), (2, "b.example")] {
        let ago = 600 + index;
        events.push(event(
            "message-ingest.ham",
            ago,
            json!({"accountId": index}),
        ));
        events.push(event(
            "message-ingest.spam",
            ago,
            json!({"accountId": index}),
        ));
        let from = format!("x@{domain}");
        events.push(event(
            "smtp.spf-from-fail",
            ago,
            json!({"from": from, "result": "spf.fail"}),
        ));
        events.push(event(
            "smtp.dmarc-fail",
            ago,
            json!({"domain": domain, "result": "dmarc.fail"}),
        ));
        let host = format!("mx.{domain}");
        events.push(event(
            "delivery.start-tls-unavailable",
            ago,
            json!({"hostname": host}),
        ));
        let host = format!("mx2.{domain}");
        events.push(event(
            "delivery.start-tls-error",
            ago,
            json!({"hostname": host}),
        ));
    }
    let mail = |span: &'static str, from: &str| -> Event {
        (
            "smtp.mail-from",
            700,
            Some(span),
            json!({"from": from, "localPort": 25}),
        )
    };
    events.extend([
        ("smtp.start-tls", 701, Some("1"), json!({})),
        mail("1", "s@a.example"),
        ("smtp.start-tls", 701, Some("2"), json!({})),
        mail("2", "s@b.example"),
        mail("3", "p@a.example"),
        mail("4", "p@b.example"),
    ]);
    events
}

fn accounts() -> Objects {
    objects(
        "Account",
        vec![
            json!({"id": "b", "emailAddress": "anna@a.example"}),
            json!({"id": "c", "emailAddress": "ben@b.example"}),
        ],
    )
}

/// A card as the test compares it: what it shows, its state and findings.
type Card = (
    String,
    Vec<(String, Value)>,
    Option<Vec<Vec<Value>>>,
    State,
    Vec<String>,
);

fn card(observation: &Observation) -> Card {
    (
        observation.id.clone(),
        observation
            .fields
            .iter()
            .map(|field| (field.label.clone(), field.value.clone()))
            .collect(),
        observation.table.as_ref().map(|table| table.rows.clone()),
        observation.state,
        observation.findings.clone(),
    )
}

#[test]
fn a_list_that_left_events_or_rows_out_says_so_and_no_count_is_cut() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = history(directory.path(), &Receiver::default(), &week(), 0);
    let stalwart = accounts();
    config.deployment.stalwart_url.clone_from(&stalwart.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".to_owned()),
        ..crate::testing::context(&config, &runner)
    };
    let flow = Flow::new(&table("type = \"mail-flow\"")).unwrap();
    let cards = |limits: &Limits| -> Vec<Card> {
        let read = Flow::counted_within(&context, limits);
        let report = flow.cards(&context, &read).unwrap();
        report.observations.iter().map(card).collect()
    };
    let whole = cards(&Limits::WEEK);
    let events = cards(&Limits {
        events: 1,
        ..Limits::WEEK
    });
    let rows = cards(&Limits {
        rows: 1,
        ..Limits::WEEK
    });
    stalwart.requests();
    // In full, every card is in order and says nothing more.
    for (id, _, _, state, findings) in &whole {
        assert_eq!((*state, findings.len()), (State::Ok, 0), "{id}");
    }
    let newest = "The list counts only the newest events of each kind it reads; more were \
                  recorded in these seven days.";
    // Each card that a cut changed says so: a cut of the events makes it
    // Partial, one of the rows lists the busiest and keeps its state; a
    // card the cut did not change is as it was in full.
    let expected = |cut: &[Card], rule: &dyn Fn(&Card) -> (State, bool)| -> Vec<Card> {
        cut.iter()
            .map(|seen| {
                let full = whole.iter().find(|full| full.0 == seen.0).unwrap();
                if (&full.1, &full.2) == (&seen.1, &seen.2) {
                    return full.clone();
                }
                let (state, said) = rule(seen);
                assert!(
                    said,
                    "{} does not say what was left out: {:?}",
                    seen.0, seen.4
                );
                (
                    seen.0.clone(),
                    seen.1.clone(),
                    seen.2.clone(),
                    state,
                    seen.4.clone(),
                )
            })
            .collect()
    };
    assert_eq!(
        events,
        expected(&events, &|seen| (
            State::Partial,
            seen.4.iter().any(|said| said == newest)
        ))
    );
    assert_eq!(
        rows,
        expected(&rows, &|seen| (
            State::Ok,
            seen.4.iter().any(|said| said.contains(" busiest of "))
        ))
    );
    // Some card was changed by each cut, so the rule was tried.
    assert_ne!(events, whole);
    assert_ne!(rows, whole);
    // The numbers of incoming mail are of the whole week either way: two
    // with STARTTLS, two without.
    for cut in [&events, &rows] {
        let tls = cut.iter().find(|card| card.0 == "flow.tls").unwrap();
        let of = |label: &str| {
            tls.1
                .iter()
                .find(|(name, _)| name == label)
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(
            (of("Incoming with TLS"), of("Incoming without TLS")),
            (json!(2), json!(2))
        );
    }
}
