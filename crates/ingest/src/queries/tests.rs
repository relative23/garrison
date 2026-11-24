use garrison_core::time;
use serde_json::json;

use super::*;
use crate::store::tests::{AT, QUEUE, SPAN, event, read, store};

#[test]
fn a_delivery_summary_requires_every_enqueued_recipient() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events
        .arriving(&[
            event(
                1,
                "queue.message-queued",
                AT,
                &json!({"queueId": QUEUE, "to": ["a@example.test", "b@example.org"]}),
            ),
            event(
                2,
                "delivery.dsn-success",
                AT,
                &json!({"queueId": QUEUE, "to": "a@example.test", "code": 250}),
            ),
        ])
        .unwrap();
    let partial = json!(list_deliveries(&read(directory.path()), &Filter::default()).unwrap());
    let partial = &partial["items"][0];
    assert_eq!(partial["recipientEvidenceComplete"], false);
    assert_eq!(partial["status"], "partial");
    events
        .arriving(&[event(
            3,
            "delivery.dsn-perm-fail",
            AT,
            &json!({"queueId": QUEUE, "to": "b@example.org"}),
        )])
        .unwrap();
    let detail = delivery_detail(&read(directory.path()), &QUEUE.to_string()).unwrap();
    let detail = json!(detail.unwrap());
    let summary = &detail["summary"];
    assert_eq!(summary["recipientEvidenceComplete"], true);
    assert_eq!(summary["status"], "partial"); // One delivered, one failed.
    assert_eq!(
        summary["recipientOutcomes"],
        json!({"a@example.test": "delivered", "b@example.org": "failed"})
    );
    assert_eq!(detail["events"].as_array().unwrap().len(), 3);
    assert_eq!(detail["truncated"], false);
    assert_eq!(delivery_detail(&read(directory.path()), "1").unwrap(), None);
}

#[test]
fn a_session_summary_groups_by_span() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events
        .arriving(&[
            event(
                1,
                "smtp.connection-start",
                AT,
                &json!({"spanId": SPAN, "listenerId": "smtp", "remoteIp": "192.0.2.1"}),
            ),
            event(
                2,
                "smtp.ehlo",
                AT,
                &json!({"spanId": SPAN, "domain": "client.example.net"}),
            ),
            event(3, "smtp.spf-from-fail", AT, &json!({"spanId": SPAN})),
            event(
                4,
                "smtp.mailbox-does-not-exist",
                AT,
                &json!({"spanId": SPAN, "to": "nobody@example.test"}),
            ),
            event(5, "smtp.connection-end", AT, &json!({"spanId": SPAN})),
        ])
        .unwrap();
    let filter = Filter {
        search: "client.EXAMPLE".into(),
        ..Filter::default()
    };
    let page = json!(list_sessions(&read(directory.path()), &filter).unwrap());
    let session = &page["items"][0];
    assert_eq!(session["ehlo"], "client.example.net");
    assert_eq!(session["authentication"], json!({"spf-from": "fail"}));
    assert_eq!(session["rejections"], json!(["Mailbox does not exist"]));
    assert_eq!(session["complete"], true);
    assert_eq!(session["listener"], "smtp");
    let none = Filter {
        search: "nothing like it".into(),
        ..Filter::default()
    };
    assert_eq!(
        list_sessions(&read(directory.path()), &none).unwrap().items,
        []
    );
    // A span without SMTP events is no SMTP session, not even by its ID.
    events
        .arriving(&[event(6, "auth.failed", AT, &json!({"spanId": "4242"}))])
        .unwrap();
    assert_eq!(
        session_detail(&read(directory.path()), "4242").unwrap(),
        None
    );
    assert!(
        session_detail(&read(directory.path()), &SPAN.to_string())
            .unwrap()
            .is_some()
    );
}

#[test]
fn pages_continue_with_their_cursor() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let batch: Vec<Value> = (1..=5)
        .map(|index| {
            let at = format!("2026-10-28T10:00:0{index}Z");
            event(
                index,
                "queue.message-queued",
                &at,
                &json!({"queueId": index, "to": ["a@example.test"]}),
            )
        })
        .collect();
    events.arriving(&batch).unwrap();
    let db = read(directory.path());
    let first = list_events(
        &db,
        &Filter {
            limit: 2,
            ..Filter::default()
        },
    )
    .unwrap();
    assert_eq!(first.next.as_deref(), Some("4"));
    let second = list_events(
        &db,
        &Filter {
            limit: 2,
            before: Some("4".into()),
            ..Filter::default()
        },
    )
    .unwrap();
    let ids: Vec<i64> = second.items.iter().map(|item| item.seq).collect();
    assert_eq!(ids, [3, 2]);
    let queues = list_deliveries(
        &db,
        &Filter {
            limit: 2,
            ..Filter::default()
        },
    )
    .unwrap();
    let next = queues.next.unwrap();
    assert!(next.ends_with(":4"), "{next}");
    let rest = list_deliveries(
        &db,
        &Filter {
            limit: 10,
            before: Some(next),
            ..Filter::default()
        },
    )
    .unwrap();
    let queue_ids: Vec<&str> = rest
        .items
        .iter()
        .map(|item| item.queue_id.as_str())
        .collect();
    assert_eq!(queue_ids, ["3", "2", "1"]);
    assert_eq!(rest.next, None);
    for cursor in ["x", "12", "12:", "12:0", ":5", "1:2:3"] {
        let filter = Filter {
            before: Some(cursor.into()),
            ..Filter::default()
        };
        assert!(
            matches!(list_deliveries(&db, &filter), Err(QueryError::Invalid)),
            "{cursor}"
        );
    }
    let filter = Filter {
        before: Some("1:2".into()),
        ..Filter::default()
    };
    assert!(matches!(
        list_events(&db, &filter),
        Err(QueryError::Invalid)
    ));
}

#[test]
fn filters_narrow_the_event_list() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events
        .arriving(&[
            event(
                1,
                "auth.failed",
                "2026-10-28T10:00:00Z",
                &json!({"remoteIp": "192.0.2.9"}),
            ),
            event(
                2,
                "smtp.ehlo",
                "2026-10-28T11:00:00Z",
                &json!({"domain": "100%_match"}),
            ),
        ])
        .unwrap();
    let db = read(directory.path());
    let count = |filter: Filter| list_events(&db, &filter).unwrap().items.len();
    assert_eq!(
        count(Filter {
            category: "auth".into(),
            ..Filter::default()
        }),
        1
    );
    assert_eq!(
        count(Filter {
            event_type: "smtp.ehlo".into(),
            ..Filter::default()
        }),
        1
    );
    let eleven = time::parse("2026-10-28T11:00:00Z").unwrap().as_second();
    assert_eq!(
        count(Filter {
            since: Some(eleven),
            ..Filter::default()
        }),
        1
    );
    assert_eq!(
        count(Filter {
            until: Some(eleven - 1),
            ..Filter::default()
        }),
        1
    );
    // Wildcards and quotes match literally.
    assert_eq!(
        count(Filter {
            search: "100%_".into(),
            ..Filter::default()
        }),
        1
    );
    assert_eq!(
        count(Filter {
            search: "%".into(),
            ..Filter::default()
        }),
        1
    );
    assert_eq!(
        count(Filter {
            search: "'".into(),
            ..Filter::default()
        }),
        0
    );
}

#[test]
fn a_search_reads_what_was_recorded_not_how_it_is_stored() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 100);
    events
        .arriving(&[event(
            1,
            "smtp.ehlo",
            AT,
            &json!({"spanId": SPAN, "domain": "client.example.net", "remoteIp": "192.0.2.7"}),
        )])
        .unwrap();
    drop(events);
    // A value with a quote, a backslash and letters beyond ASCII, as a
    // field may hold them.
    Connection::open(directory.path().join("events.sqlite"))
        .unwrap()
        .execute(
            "INSERT INTO events(event_id,created_at,received_at,type,category,fields) \
             VALUES('odd',1,1,'smtp.ehlo','smtp',?)",
            [
                json!({"domain": "MÜLLER.example", "reason": "said \"no\" twice \\ back"})
                    .to_string(),
            ],
        )
        .unwrap();
    let db = read(directory.path());
    let found = |search: &str| {
        let filter = Filter {
            search: search.into(),
            ..Filter::default()
        };
        list_events(&db, &filter).unwrap().items.len()
    };
    // The names of the fields are how an event is stored, not what it says:
    // "remoteip" is in every event's text and in no event's values.
    assert_eq!(found("remoteip"), 0);
    assert_eq!(found("spanid"), 0);
    assert_eq!(found("192.0.2"), 1);
    // A type is searched by its name as before.
    assert_eq!(found("EHLO"), 2);
    // Quotes and backslashes are found as they were written.
    assert_eq!(found("said \"no\""), 1);
    assert_eq!(found("twice \\ back"), 1);
    assert_eq!(found("\\\""), 0);
    // Letters match in either case, those beyond ASCII too, in the needle
    // and in what is stored alike.
    assert_eq!(found("müller.EXAMPLE"), 1);
    assert_eq!(found("MÜLLER.EXAMPLE"), 1);
    assert_eq!(found("mÜller.example"), 1);
    // Sessions and deliveries are searched the same way.
    let sessions = |search: &str| {
        let filter = Filter {
            search: search.into(),
            ..Filter::default()
        };
        list_sessions(&db, &filter).unwrap().items.len()
    };
    assert_eq!((sessions("remoteip"), sessions("client.EXAMPLE")), (0, 1));
}

#[test]
fn a_search_finds_letters_beyond_ascii_in_either_case() {
    let directory = tempfile::tempdir().unwrap();
    drop(store(directory.path(), 100));
    let db = Connection::open(directory.path().join("events.sqlite")).unwrap();
    for (id, fields) in [
        ("a", json!({"from": "Jörg@Exämple.test"})),
        ("b", json!({"domain": "Straße.example"})),
        ("c", json!({"reason": "ΟΔΟΣ \"closed\""})),
    ] {
        db.execute(
            "INSERT INTO events(event_id,created_at,received_at,type,category,fields) \
             VALUES(?,1,1,'smtp.ehlo','smtp',?)",
            [id.to_owned(), fields.to_string()],
        )
        .unwrap();
    }
    drop(db);
    let db = read(directory.path());
    let found = |search: &str| {
        let filter = Filter {
            search: search.into(),
            ..Filter::default()
        };
        let events: Vec<String> = list_events(&db, &filter)
            .unwrap()
            .items
            .into_iter()
            .map(|item| item.id)
            .collect();
        let sessions = list_sessions(&db, &filter).unwrap().items.len();
        (events.join(","), sessions)
    };
    assert_eq!(found("jörg@exämple"), ("a".to_owned(), 0));
    assert_eq!(found("JÖRG@EXÄMPLE.TEST"), ("a".to_owned(), 0));
    // ß is SS in capitals, so either spelling finds it.
    assert_eq!(found("strasse.EXAMPLE"), ("b".to_owned(), 0));
    assert_eq!(found("STRASSE"), ("b".to_owned(), 0));
    assert_eq!(found("straße"), ("b".to_owned(), 0));
    // A final sigma is a sigma, beside a quote that JSON escapes.
    assert_eq!(found("οδος \"closed"), ("c".to_owned(), 0));
    assert_eq!(found("Οδοσ"), ("c".to_owned(), 0));
    assert_eq!(found("ΟΔΟΣ \"CLOSED\""), ("c".to_owned(), 0));
}

#[test]
fn every_recorded_event_has_a_native_label() {
    let labelled: Vec<&String> = LABELS.keys().collect();
    assert_eq!(labelled, crate::policy::event_types());
    assert!(LABELS.values().all(|labels| !labels.label.is_empty()));
}

fn queued(index: u64, data: &Value) -> Value {
    let at = format!("2026-10-28T10:{:02}:{:02}Z", index / 60, index % 60);
    event(index, "queue.message-queued", &at, data)
}

pub(super) fn limit(limit: usize) -> Filter {
    Filter {
        limit,
        ..Filter::default()
    }
}

#[test]
fn an_exactly_full_page_has_no_next_page() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let batch: Vec<Value> = (1..=5)
        .map(|index| queued(index, &json!({"queueId": index, "to": ["a@example.test"]})))
        .collect();
    events.arriving(&batch).unwrap();
    let db = read(directory.path());
    assert_eq!(list_events(&db, &limit(5)).unwrap().next, None);
    assert_eq!(list_deliveries(&db, &limit(5)).unwrap().next, None);
}

#[test]
fn a_page_stays_within_its_byte_budget() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    // 40 events with 100 long addresses each: about 1 MB of JSON.
    let to: Vec<String> = (0..100)
        .map(|index| format!("{}{index:03}@example.test", "x".repeat(230)))
        .collect();
    let batch: Vec<Value> = (1..=40)
        .map(|index| queued(index, &json!({"to": to})))
        .collect();
    events.arriving(&batch).unwrap();
    let page = list_events(&read(directory.path()), &limit(100)).unwrap();
    let items = &page.items;
    assert!((1..40).contains(&items.len()), "{}", items.len());
    assert!(json!(items).to_string().len() <= MAX_RESPONSE_BYTES);
    // One more item would pass the budget, so the budget is the JSON's size.
    let one = json!(items[0]).to_string().len();
    assert!(json!(items).to_string().len() + one > MAX_RESPONSE_BYTES);
    assert_eq!(page.next, Some(items.last().unwrap().seq.to_string()));
}

#[test]
fn a_detail_shows_its_first_256_events() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let batch: Vec<Value> = (1..=256)
        .map(|index| queued(index, &json!({"queueId": "77", "to": ["a@example.test"]})))
        .collect();
    events.arriving(&batch).unwrap();
    let detail = delivery_detail(&read(directory.path()), "77")
        .unwrap()
        .unwrap();
    assert_eq!((detail.truncated, detail.events.len()), (false, 256));
    events
        .arriving(&[queued(
            257,
            &json!({"queueId": "77", "to": ["a@example.test"]}),
        )])
        .unwrap();
    let detail = delivery_detail(&read(directory.path()), "77")
        .unwrap()
        .unwrap();
    assert_eq!((detail.truncated, detail.events.len()), (true, 256));
    assert_eq!(detail.summary.event_count, 257);
}
