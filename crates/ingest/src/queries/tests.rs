use garrison_core::time;
use serde_json::json;

use super::*;
use crate::store::tests::{AT, QUEUE, SPAN, event, read, store};

#[test]
fn a_delivery_summary_requires_every_enqueued_recipient() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events
        .ingest(
            &[
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
            ],
            1,
        )
        .unwrap();
    let partial = json!(list_deliveries(&read(directory.path()), &Filter::default()).unwrap());
    let partial = &partial["items"][0];
    assert_eq!(partial["recipientEvidenceComplete"], false);
    assert_eq!(partial["status"], "partial");
    events
        .ingest(
            &[event(
                3,
                "delivery.dsn-perm-fail",
                AT,
                &json!({"queueId": QUEUE, "to": "b@example.org"}),
            )],
            2,
        )
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
        .ingest(
            &[
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
            ],
            1,
        )
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
        .ingest(
            &[event(6, "auth.failed", AT, &json!({"spanId": "4242"}))],
            1,
        )
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
    events.ingest(&batch, 1).unwrap();
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
        .ingest(
            &[
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
            ],
            1,
        )
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
fn every_recorded_event_has_a_native_label() {
    let labelled: Vec<&String> = LABELS.keys().collect();
    assert_eq!(labelled, crate::policy::event_types());
    assert!(LABELS.values().all(|labels| !labels.label.is_empty()));
}

fn queued(index: u64, data: &Value) -> Value {
    let at = format!("2026-10-28T10:{:02}:{:02}Z", index / 60, index % 60);
    event(index, "queue.message-queued", &at, data)
}

fn limit(limit: usize) -> Filter {
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
    events.ingest(&batch, 1).unwrap();
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
    events.ingest(&batch, 1).unwrap();
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
    events.ingest(&batch, 1).unwrap();
    let detail = delivery_detail(&read(directory.path()), "77")
        .unwrap()
        .unwrap();
    assert_eq!((detail.truncated, detail.events.len()), (false, 256));
    events
        .ingest(
            &[queued(
                257,
                &json!({"queueId": "77", "to": ["a@example.test"]}),
            )],
            1,
        )
        .unwrap();
    let detail = delivery_detail(&read(directory.path()), "77")
        .unwrap()
        .unwrap();
    assert_eq!((detail.truncated, detail.events.len()), (true, 256));
    assert_eq!(detail.summary.event_count, 257);
}

#[test]
fn only_an_interrupted_query_counts_as_interrupted() {
    let interrupt = rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT);
    assert!(QueryError::Sqlite(rusqlite::Error::SqliteFailure(interrupt, None)).is_interrupted());
    let busy = rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY);
    assert!(!QueryError::Sqlite(rusqlite::Error::SqliteFailure(busy, None)).is_interrupted());
    assert!(!QueryError::Invalid.is_interrupted());
}
