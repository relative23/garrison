//! What the history holds and cannot be read is the history's fault, not
//! the request's: such a query says which event it could not read.

use serde_json::json;

use super::*;
use crate::store::tests::{AT, QUEUE, SPAN, event, read, store};

#[test]
fn an_event_whose_fields_cannot_be_read_is_the_historys_fault() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events
        .arriving(&[
            event(
                1,
                "smtp.connection-start",
                AT,
                &json!({"spanId": SPAN, "remoteIp": "192.0.2.1"}),
            ),
            event(
                2,
                "queue.message-queued",
                AT,
                &json!({"spanId": SPAN, "queueId": QUEUE, "from": "a@example.net", "to": ["b@example.test"]}),
            ),
        ])
        .unwrap();
    // Fields that are JSON, but no object.
    Connection::open(directory.path().join("events.sqlite"))
        .unwrap()
        .execute("UPDATE events SET fields = '[1]' WHERE seq = 2", [])
        .unwrap();
    let db = read(directory.path());
    let reason = "Event 2 of the event history has fields that are not a JSON object";
    let said = |error: QueryError| match error {
        QueryError::Unreadable(said) => said,
        other => format!("not unreadable: {other:?}"),
    };
    let filter = Filter::default();
    assert_eq!(said(list_events(&db, &filter).unwrap_err()), reason);
    assert_eq!(said(list_deliveries(&db, &filter).unwrap_err()), reason);
    assert_eq!(said(list_sessions(&db, &filter).unwrap_err()), reason);
    let queue = QUEUE.to_string();
    assert_eq!(said(delivery_detail(&db, &queue).unwrap_err()), reason);
    assert_eq!(
        said(session_detail(&db, &SPAN.to_string()).unwrap_err()),
        reason
    );
}
