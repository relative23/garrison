use serde_json::json;

use super::*;

fn event(kind: &str, fields: &Value) -> Event {
    (kind.to_owned(), fields.as_object().unwrap().clone())
}

#[test]
fn outcomes_follow_the_answer_class() {
    let code = |value: i64| json!({"code": value}).as_object().unwrap().clone();
    assert_eq!(
        outcome(EventType::DeliveryDelivered, &Map::new()),
        Some("delivered")
    );
    assert_eq!(
        outcome(EventType::DeliveryDsnSuccess, &code(250)),
        Some("delivered")
    );
    assert_eq!(outcome(EventType::DeliveryDsnSuccess, &Map::new()), None);
    assert_eq!(
        outcome(EventType::DeliveryRcptToRejected, &code(451)),
        Some("deferred")
    );
    assert_eq!(
        outcome(EventType::DeliveryMessageRejected, &code(550)),
        Some("failed")
    );
    assert_eq!(outcome(EventType::DeliveryRcptToRejected, &code(250)), None);
    assert_eq!(
        outcome(EventType::DeliveryDsnPermFail, &Map::new()),
        Some("failed")
    );
    assert_eq!(
        outcome(EventType::DeliveryDsnTempFail, &Map::new()),
        Some("deferred")
    );
    assert_eq!(outcome(EventType::QueueRescheduled, &Map::new()), None);
}

#[test]
fn a_queue_without_its_enqueue_event_is_never_complete() {
    let events = [event(
        "delivery.delivered",
        &json!({"to": ["a@example.test"], "from": "s@x"}),
    )];
    let summary = json!(summarize_queue(&events, 1));
    assert_eq!(summary["status"], "partial");
    assert_eq!(summary["recipientEvidenceComplete"], false);
    assert_eq!(summary["from"], "s@x");
}

#[test]
fn a_complete_queue_takes_its_recipients_common_outcome() {
    let events = [
        event("queue.message-queued", &json!({"to": ["a@x", "b@x"]})),
        event("delivery.attempt-start", &json!({})),
        event("delivery.delivered", &json!({"to": ["a@x", "b@x"]})),
        event("delivery.completed", &json!({})),
    ];
    let summary = json!(summarize_queue(&events, 4));
    assert_eq!(summary["status"], "delivered");
    assert_eq!(summary["recipientEvidenceComplete"], true);
    // Events beyond those inspected make the summary unknown.
    let truncated = json!(summarize_queue(&events, 5));
    assert_eq!(truncated["status"], "unknown");
    assert_eq!(truncated["recipientEvidenceComplete"], false);
}

#[test]
fn only_an_enqueue_event_names_the_expected_recipients() {
    let events = [
        event("queue.rescheduled", &json!({"to": ["a@x"]})),
        event("delivery.delivered", &json!({"to": ["a@x"]})),
    ];
    let summary = json!(summarize_queue(&events, events.len()));
    assert_eq!(summary["recipientEvidenceComplete"], false);
    assert_eq!(summary["status"], "deferred");
}

#[test]
fn a_delivery_without_outcomes_keeps_its_lifecycle_status() {
    let events = [
        event("queue.message-queued", &json!({"to": ["a@x"]})),
        event("delivery.attempt-start", &json!({})),
    ];
    assert_eq!(
        json!(summarize_queue(&events, events.len()))["status"],
        "in-progress"
    );
}

#[test]
fn the_status_follows_the_last_lifecycle_event() {
    let events = [
        event("queue.message-queued", &json!({"to": ["a@x"]})),
        event("queue.rescheduled", &json!({})),
    ];
    assert_eq!(json!(summarize_queue(&events, 2))["status"], "deferred");
    // A summary reads 256 events at most: a delivery after them is not seen.
    let mut many = vec![event("queue.message-queued", &json!({"to": ["a@x"]}))];
    many.extend((0..254).map(|_| event("queue.locked", &json!({}))));
    many.push(event("delivery.delivered", &json!({"to": ["a@x"]})));
    assert_eq!(json!(summarize_queue(&many, 256))["status"], "delivered");
    many.insert(1, event("queue.locked", &json!({})));
    assert_eq!(json!(summarize_queue(&many, 257))["status"], "unknown");
}

#[test]
fn a_session_keeps_its_first_listener_and_queue_ids() {
    let events = [
        event(
            "smtp.connection-start",
            &json!({"listenerId": "", "remoteIp": "192.0.2.1"}),
        ),
        event("smtp.ehlo", &json!({"listenerId": "smtp", "domain": "a"})),
        event("smtp.rcpt-to", &json!({"to": ["x@y", "x@y", "z@y"]})),
        event("smtp.relay-not-allowed", &json!({})),
        event("smtp.relay-not-allowed", &json!({})),
        event("queue.message-queued", &json!({"queueId": "9"})),
        event("smtp.dkim-pass", &json!({})),
        event("smtp.dkim-fail", &json!({})),
    ];
    let summary = json!(summarize_session(&events, 8));
    assert_eq!(summary["listener"], "smtp");
    assert_eq!(summary["remoteIp"], "192.0.2.1");
    assert_eq!(summary["to"], json!(["x@y", "z@y"]));
    assert_eq!(summary["rejections"], json!(["Relay not allowed"]));
    assert_eq!(summary["queueIds"], json!(["9"]));
    assert_eq!(summary["authentication"], json!({"dkim": "fail"}));
    assert_eq!(summary["complete"], false);
    let keys: Vec<&String> = summary.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "listener",
            "remoteIp",
            "ehlo",
            "from",
            "to",
            "authentication",
            "rejections",
            "queueIds",
            "complete"
        ]
    );
}

#[test]
fn every_rejected_smtp_command_has_a_reason() {
    for (event_type, reason) in [
        ("smtp.mailbox-does-not-exist", "Mailbox does not exist"),
        ("smtp.relay-not-allowed", "Relay not allowed"),
        ("smtp.rcpt-to-greylisted", "Recipient greylisted"),
        ("smtp.too-many-recipients", "Too many recipients"),
        ("smtp.message-too-large", "Message too large"),
        ("smtp.rate-limit-exceeded", "Rate limit exceeded"),
        (
            "smtp.concurrency-limit-exceeded",
            "Concurrency limit exceeded",
        ),
        ("smtp.time-limit-exceeded", "Time limit exceeded"),
        ("smtp.mail-from-unauthenticated", "Sender not authenticated"),
        ("smtp.mail-from-unauthorized", "Sender not authorized"),
        ("smtp.mail-from-not-allowed", "Sender not allowed"),
        ("smtp.invalid-ehlo", "Invalid EHLO"),
    ] {
        let kind = EventType::parse(event_type).expect(event_type);
        assert_eq!(rejection(kind), Some(reason), "{event_type}");
    }
    assert_eq!(rejection(EventType::SmtpRcptTo), None);
}

#[test]
fn the_lifecycle_moves_through_attempts_to_completion() {
    assert_eq!(
        status(EventType::DeliveryAttemptStart, "queued"),
        "in-progress"
    );
    assert_eq!(
        status(EventType::DeliveryCompleted, "in-progress"),
        "completed"
    );
    assert_eq!(
        status(EventType::DeliveryConnect, "in-progress"),
        "in-progress"
    );
}

#[test]
fn the_first_sender_counts_and_recipients_are_capped() {
    let to: Vec<String> = (0..=MAX_RECIPIENTS)
        .map(|index| format!("r{index}@example.test"))
        .collect();
    let events = [
        event(
            "queue.message-queued",
            &json!({"from": "first@example.test", "to": to}),
        ),
        event(
            "delivery.attempt-start",
            &json!({"from": "later@example.test"}),
        ),
    ];
    let summary = json!(summarize_queue(&events, events.len()));
    assert_eq!(summary["from"], "first@example.test");
    assert_eq!(summary["to"].as_array().unwrap().len(), MAX_RECIPIENTS);
    // The cap holds across events as well.
    let first: Vec<String> = (0..MAX_RECIPIENTS)
        .map(|index| format!("r{index}@example.test"))
        .collect();
    let events = [
        event("queue.message-queued", &json!({"to": first})),
        event("delivery.delivered", &json!({"to": ["late@example.test"]})),
    ];
    let summary = json!(summarize_queue(&events, events.len()));
    assert_eq!(summary["to"].as_array().unwrap().len(), MAX_RECIPIENTS);
}

#[test]
fn a_truncated_queue_is_never_complete() {
    let events = [
        event("queue.message-queued", &json!({"to": ["a@example.test"]})),
        event("delivery.delivered", &json!({"to": ["a@example.test"]})),
    ];
    let whole = json!(summarize_queue(&events, events.len()));
    assert_eq!(
        (
            whole["status"].clone(),
            whole["recipientEvidenceComplete"].clone()
        ),
        (json!("delivered"), json!(true))
    );
    let truncated = json!(summarize_queue(&events, events.len() + 1));
    assert_eq!(
        (
            truncated["status"].clone(),
            truncated["recipientEvidenceComplete"].clone()
        ),
        (json!("unknown"), json!(false))
    );
}

#[test]
fn a_session_value_that_is_no_text_counts_as_absent() {
    let events = [
        event(
            "smtp.connection-start",
            &json!({"listenerId": 25, "remoteIp": true}),
        ),
        event("smtp.ehlo", &json!({"domain": 7})),
        event("smtp.mail-from", &json!({"from": ["a@x", "b@x"]})),
        event("queue.message-queued", &json!({"queueId": 9})),
        event("queue.message-queued", &json!({"queueId": ""})),
        event(
            "smtp.rcpt-to",
            &json!({"listenerId": "smtp", "remoteIp": "192.0.2.1"}),
        ),
    ];
    let summary = summarize_session(&events, events.len());
    // The first event that names them as text counts.
    assert_eq!(summary.listener.as_deref(), Some("smtp"));
    assert_eq!(summary.remote_ip.as_deref(), Some("192.0.2.1"));
    assert_eq!((summary.ehlo, summary.from), (None, None));
    assert_eq!(summary.queue_ids, Vec::<String>::new());
}

#[test]
fn a_summary_goes_out_under_the_names_the_api_uses() {
    let queue = summarize_queue(
        &[event(
            "queue.message-queued",
            &json!({"from": "s@x", "to": ["a@x"]}),
        )],
        1,
    );
    assert_eq!(
        json!(queue),
        json!({
            "from": "s@x", "to": ["a@x"], "status": "queued",
            "recipientOutcomes": {}, "recipientEvidenceComplete": false,
        })
    );
    let session = summarize_session(&[event("smtp.connection-end", &json!({}))], 1);
    assert_eq!(
        json!(session),
        json!({
            "listener": null, "remoteIp": null, "ehlo": null, "from": null, "to": [],
            "authentication": {}, "rejections": [], "queueIds": [], "complete": false,
        })
    );
}
