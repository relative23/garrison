use serde_json::json;

use super::*;

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
    assert_eq!(all.len(), 131);
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
    assert_eq!((names.len(), EventType::ALL.len()), (131, 131));
    assert_eq!(EventType::QueueRescheduled.as_str(), "queue.rescheduled");
    assert_eq!(EventType::MtaHookActionReject.category(), "mta-hook");
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

/// A milter's answer that is larger than Stalwart reads, as Stalwart 1.2.1
/// sends it (measured): the size the answer announced is kept, which
/// `details` holds as a number, and the milter's entry in Stalwart's own
/// words is not.
#[test]
fn a_milter_answer_that_is_too_large_keeps_the_size_it_announced() {
    let sent = json!({
        "spanId": 342_984_699_454_438_912_u64, "name": "MtaMilter with id jqugym9llgaa",
        "details": 67_108_864, "elapsed": 0, "listenerId": "smtp", "localPort": 25,
        "remoteIp": "172.17.0.3", "remotePort": 43540,
    });
    assert_eq!(
        Value::Object(select_fields(EventType::MilterFrameTooLarge, &sent)),
        json!({
            "spanId": "342984699454438912", "details": 67_108_864, "elapsed": 0,
            "listenerId": "smtp", "localPort": 25, "remoteIp": "172.17.0.3",
            "remotePort": 43540,
        })
    );
}

/// A milter's answer that Stalwart cannot read, as Stalwart 1.2.1 sends it
/// (measured): that it happened is kept, with the session it happened in.
/// `details` holds the milter's frame, which may quote the message, in
/// base64 or in Stalwart's words, and is never kept; a number there would be
/// no frame, and goes too.
#[test]
fn a_milter_answer_that_stalwart_cannot_read_keeps_nothing_of_the_frame() {
    let kept = json!({
        "spanId": "342986075850939904", "elapsed": 0, "listenerId": "smtp", "localPort": 25,
        "remoteIp": "172.17.0.3", "remotePort": 51682,
    });
    for (kind, details) in [
        (EventType::MilterFrameInvalid, json!("eTQ1MQ==")),
        (EventType::MilterFrameInvalid, json!("")),
        (EventType::MilterFrameInvalid, json!(451)),
        (
            EventType::MilterUnexpectedResponse,
            json!("OPTNEG (version: 6, actions: [], options: [])"),
        ),
    ] {
        let sent = json!({
            "spanId": 342_986_075_850_939_904_u64, "name": "MtaMilter with id jquiae1rleqa",
            "details": details, "reason": details, "elapsed": 0, "listenerId": "smtp",
            "localPort": 25, "remoteIp": "172.17.0.3", "remotePort": 51682,
        });
        assert_eq!(Value::Object(select_fields(kind, &sent)), kept, "{kind:?}");
    }
}

/// A connection that a full listener refused, as Stalwart 1.2.1 sends it
/// (measured): the listener and the address are kept, the limit, which is a
/// setting of Stalwart's, is not.
#[test]
fn a_connection_refused_by_a_full_listener_keeps_its_listener_and_address() {
    let sent = json!({
        "listenerId": "smtp", "localPort": 25, "remoteIp": "172.17.0.3", "remotePort": 43766,
        "limit": 2,
    });
    assert_eq!(
        Value::Object(select_fields(EventType::LimitConcurrentConnection, &sent)),
        json!({"listenerId": "smtp", "localPort": 25, "remoteIp": "172.17.0.3", "remotePort": 43766})
    );
}
