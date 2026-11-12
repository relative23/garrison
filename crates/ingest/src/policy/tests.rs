use serde_json::json;

use super::*;
use crate::event_type::Group;

#[test]
fn identifiers_are_positive_integers_kept_as_text() {
    assert_eq!(identifier(&json!(u64::MAX)), Some(u64::MAX.to_string()));
    assert_eq!(identifier(&json!("007")), Some("007".into()));
    assert_eq!(
        identifier(&json!("99999999999999999999")),
        Some("99999999999999999999".into())
    );
    for value in [
        json!(0),
        json!(-1),
        json!(1.5),
        json!("0"),
        json!("00"),
        json!(""),
        json!("1a"),
        json!("123456789012345678901"),
        json!(true),
        json!(null),
        json!("²"),
    ] {
        assert_eq!(identifier(&value), None, "{value}");
    }
}

#[test]
fn only_listed_fields_survive_and_text_is_bounded() {
    let data = json!({
        "spanId": 7,
        "queueId": 0,
        "to": ["a@example.test", 5, "x".repeat(300)],
        "from": "s@example.net",
        "remoteIp": "192.0.2.1",
        "size": 9_007_199_254_740_993_u64,
        "elapsed": -9_007_199_254_740_992_i64,
        "code": 250,
        "total": 1.5,
        "protocol": null,
        "causedBy": false,
        "hostname": {"nested": true},
        "details": "kept for delivery",
        "contents": "DATA",
        "password": "secret",
    });
    let fields = select_fields(EventType::DeliveryConnect, &data);
    assert_eq!(
        Value::Object(fields),
        json!({
            "spanId": "7",
            "to": ["a@example.test", "x".repeat(254)],
            "from": "s@example.net",
            "remoteIp": "192.0.2.1",
            "size": "9007199254740993",
            "elapsed": "-9007199254740992",
            "code": 250,
            "total": 1.5,
            "causedBy": false,
            "details": "kept for delivery",
        })
    );
    // SMTP clients choose their own texts; those are not kept.
    assert!(select_fields(EventType::SmtpEhlo, &json!({"details": "x"})).is_empty());
    assert!(select_fields(EventType::SmtpEhlo, &json!("not an object")).is_empty());
    assert_eq!(
        Value::Object(select_fields(
            EventType::SmtpRcptTo,
            &json!({"to": "single@example.test"})
        )),
        json!({"to": "single@example.test"})
    );
    assert!(select_fields(EventType::SmtpRcptTo, &json!({"to": [1, 2]})).is_empty());
    let many: Vec<String> = (0..150)
        .map(|index| format!("r{index}@example.test"))
        .collect();
    let fields = select_fields(EventType::SmtpRcptTo, &json!({"to": many}));
    assert_eq!(fields["to"].as_array().unwrap().len(), 100);
}

#[test]
fn the_event_lists_are_disjoint_and_never_forbidden() {
    let all = event_types();
    let mut unique = all.clone();
    unique.dedup();
    assert_eq!(unique.len(), all.len());
    assert_eq!(all.len(), 111);
    assert!(FORBIDDEN_EVENTS.iter().all(|event| !is_recorded(event)));
    assert!(is_recorded("smtp.ehlo") && !is_recorded("smtp.raw-input"));
    // A name is recorded as a whole: no part of one, nothing longer.
    for near in [
        "",
        "smtp.ehl",
        "smtp.ehlo ",
        "smtp.ehlo-",
        "mtp.ehlo",
        "SMTP.EHLO",
    ] {
        assert!(!is_recorded(near), "{near:?}");
    }
    assert!(event_types().into_iter().all(is_recorded));
    // Every type has one name, and a name spells one type.
    for kind in EventType::ALL {
        assert_eq!(EventType::parse(kind.as_str()), Some(*kind));
        assert!(kind.as_str().starts_with(kind.category()));
    }
    let names: std::collections::BTreeSet<&str> = event_types().into_iter().collect();
    assert_eq!((names.len(), EventType::ALL.len()), (111, 111));
    assert_eq!(EventType::QueueRescheduled.as_str(), "queue.rescheduled");
    assert_eq!(EventType::MtaHookActionReject.category(), "mta-hook");
    // The summaries of sessions and deliveries read the events of their group.
    let of = |group: Group| {
        EventType::ALL
            .iter()
            .filter(|kind| kind.group() == group)
            .count()
    };
    assert_eq!(
        (of(Group::Session), of(Group::Delivery), of(Group::Other)),
        (30, 49, 32)
    );
    assert!(
        EventType::ALL
            .iter()
            .all(|kind| { (kind.group() == Group::Session) == (kind.category() == "smtp") })
    );
    assert_eq!(category("message-ingest.spam"), "message-ingest");
    assert_eq!(category("plain"), "plain");
}

#[test]
fn a_sign_in_keeps_its_verdict_and_the_name_of_an_existing_account_only() {
    let known = json!({
        "accountName": "anna@example.test", "accountId": 7, "remoteIp": "192.0.2.1",
        "listenerId": "http", "reason": "Authentication failed", "details": "more",
    });
    assert_eq!(
        Value::Object(select_fields(EventType::AuthFailed, &known)),
        json!({"accountName": "anna@example.test", "accountId": 7, "remoteIp": "192.0.2.1",
               "listenerId": "http", "reason": "Authentication failed"})
    );
    // Without an account of that name, what was typed may be a password.
    let unknown =
        json!({"accountName": "hunter2", "remoteIp": "192.0.2.1", "reason": "Account not found"});
    assert_eq!(
        Value::Object(select_fields(EventType::AuthFailed, &unknown)),
        json!({"remoteIp": "192.0.2.1", "reason": "Account not found"})
    );
    // A ban names the address; the name it came with has no account beside it.
    let ban = json!({"accountName": "hunter2", "remoteIp": "192.0.2.1"});
    assert_eq!(
        Value::Object(select_fields(EventType::SecurityAuthenticationBan, &ban)),
        json!({"remoteIp": "192.0.2.1"})
    );
    // Elsewhere an account's name is not kept at all.
    let session = json!({"accountName": "anna@example.test", "accountId": 7});
    assert_eq!(
        Value::Object(select_fields(EventType::MessageIngestHam, &session)),
        json!({"accountId": 7})
    );
    let handshake =
        json!({"remoteIp": "192.0.2.1", "reason": "received corrupt message", "details": "x"});
    assert_eq!(
        Value::Object(select_fields(EventType::TlsHandshakeError, &handshake)),
        json!({"remoteIp": "192.0.2.1", "reason": "received corrupt message"})
    );
}

#[test]
fn of_a_check_of_the_sender_the_outcome_is_kept_and_not_what_it_looked_at() {
    let dmarc = json!({
        "spanId": 9, "domain": "sender.example", "policy": "reject", "strict": false,
        "result": {"type": "dmarc.fail", "data": {"causedBy": {"details": "v=DMARC1; p=reject; rua=mailto:x@sender.example"}}},
    });
    assert_eq!(
        Value::Object(select_fields(EventType::SmtpDmarcFail, &dmarc)),
        json!({"spanId": "9", "domain": "sender.example", "policy": "reject", "result": "dmarc.fail"})
    );
    // A message without a signature, and one with several.
    let dkim = |result: Value| {
        Value::Object(select_fields(
            EventType::SmtpDkimFail,
            &json!({"result": result}),
        ))
    };
    assert_eq!(dkim(json!([])), json!({"result": "none"}));
    assert_eq!(
        dkim(json!([{"type": "dkim.pass", "data": {}}, {"type": "dkim.fail", "data": {"x": 1}}])),
        json!({"result": "dkim.pass, dkim.fail"})
    );
    assert_eq!(dkim(json!("free text")), json!({}));
    // Elsewhere a result is not a check's outcome and is not kept.
    let other = json!({"result": {"type": "x", "data": "secret"}});
    assert_eq!(
        Value::Object(select_fields(EventType::DeliveryConnect, &other)),
        json!({})
    );
}
