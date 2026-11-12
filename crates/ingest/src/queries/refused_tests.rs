//! A message that a milter or an MTA hook refuses has a queue ID and never
//! reaches the queue: its session names the refusal, and it is no delivery.

use serde_json::json;

use super::*;
use crate::store::tests::{AT, QUEUE, SPAN, event, read, store};

#[test]
fn a_message_a_milter_refuses_is_part_of_its_session_and_no_delivery() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let refused = QUEUE + 1;
    events
        .ingest(
            &[
                event(
                    1,
                    "smtp.connection-start",
                    AT,
                    &json!({"spanId": SPAN, "remoteIp": "192.0.2.1"}),
                ),
                event(
                    2,
                    "mta-hook.action-accept",
                    AT,
                    &json!({"spanId": SPAN, "queueId": refused}),
                ),
                event(
                    3,
                    "milter.action-reply-code",
                    AT,
                    &json!({"spanId": SPAN, "queueId": refused}),
                ),
                event(4, "smtp.connection-end", AT, &json!({"spanId": SPAN})),
                // Another message is queued and delivered.
                event(
                    5,
                    "queue.message-queued",
                    AT,
                    &json!({"queueId": QUEUE, "from": "a@example.net", "to": ["b@example.test"]}),
                ),
                event(
                    6,
                    "delivery.delivered",
                    AT,
                    &json!({"queueId": QUEUE, "to": ["b@example.test"]}),
                ),
            ],
            1,
        )
        .unwrap();
    let db = read(directory.path());
    let sessions = json!(list_sessions(&db, &Filter::default()).unwrap());
    assert_eq!(
        sessions["items"][0]["rejections"],
        json!(["Refused by a milter"])
    );
    let deliveries = list_deliveries(&db, &Filter::default()).unwrap();
    let listed: Vec<&str> = deliveries
        .items
        .iter()
        .map(|item| item.queue_id.as_str())
        .collect();
    assert_eq!(listed, [QUEUE.to_string()]);
    assert_eq!(delivery_detail(&db, &refused.to_string()).unwrap(), None);
    assert!(delivery_detail(&db, &QUEUE.to_string()).unwrap().is_some());
    // The refused message's events are still in the history.
    let filter = Filter {
        category: "milter".into(),
        ..Filter::default()
    };
    assert_eq!(list_events(&db, &filter).unwrap().items.len(), 1);
}

#[test]
fn what_a_milter_or_a_hook_did_to_a_message_is_named() {
    for (kind, named) in [
        ("milter.action-reject", "Refused by a milter"),
        ("milter.action-reply-code", "Refused by a milter"),
        ("milter.action-temp-fail", "Deferred by a milter"),
        ("milter.action-discard", "Discarded by a milter"),
        ("mta-hook.action-reject", "Refused by an MTA hook"),
        ("mta-hook.action-discard", "Discarded by an MTA hook"),
        ("mta-hook.action-quarantine", "Quarantined by an MTA hook"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let events = store(directory.path(), 1000);
        events
            .ingest(
                &[
                    event(1, "smtp.ehlo", AT, &json!({"spanId": SPAN})),
                    event(2, kind, AT, &json!({"spanId": SPAN, "queueId": QUEUE})),
                ],
                1,
            )
            .unwrap();
        let sessions = json!(list_sessions(&read(directory.path()), &Filter::default()).unwrap());
        assert_eq!(sessions["items"][0]["rejections"], json!([named]), "{kind}");
    }
    // A milter or a hook that lets the message pass refuses nothing.
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events
        .ingest(
            &[
                event(1, "smtp.ehlo", AT, &json!({"spanId": SPAN})),
                event(2, "milter.action-accept", AT, &json!({"spanId": SPAN})),
                event(3, "mta-hook.action-accept", AT, &json!({"spanId": SPAN})),
            ],
            1,
        )
        .unwrap();
    let sessions = json!(list_sessions(&read(directory.path()), &Filter::default()).unwrap());
    assert_eq!(sessions["items"][0]["rejections"], json!([]));
}
