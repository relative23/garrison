use garrison_core::observations::State;
use garrison_testing::http::{answer, serve};
use serde_json::{Value, json};

use super::*;
use crate::context::Provider;
use crate::testing::{Canned, config, context, table};

/// The accounts of an answer of Stalwart, as the provider reads them.
fn listed(answer: &Value) -> Vec<stalwart::answers::MailboxAccount> {
    stalwart::answers::rows(answer.as_object().cloned()).unwrap()
}

fn account(address: &str, used: Option<u64>, quota: Option<u64>) -> Value {
    let mut row = json!({"@type": "User", "emailAddress": address, "usedDiskQuota": used});
    if let Some(quota) = quota {
        row["quotas"] = json!({"maxDiskQuota": quota});
    }
    row
}

#[test]
fn mailboxes_put_the_fullest_first_and_warn_at_ninety_percent() {
    const GIB: u64 = 1 << 30;
    let answer = json!({"list": [
        account("small@example.test", Some(GIB), Some(10 * GIB)),
        account("unlimited@example.test", Some(5 * GIB), None),
        account("full@example.test", Some(19 * GIB), Some(20 * GIB)),
        {"@type": "Group", "emailAddress": "team@example.test"},
    ]});
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = context(&config, &runner);
    let observation = mailboxes::mailboxes(&context, Some(&listed(&answer)), 10).unwrap();
    assert_eq!(observation.state, State::Warning);
    let rows = &observation.table.as_ref().unwrap().rows;
    let names: Vec<&str> = rows.iter().map(|row| row[0].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "full@example.test",
            "small@example.test",
            "unlimited@example.test"
        ]
    );
    assert_eq!(
        (rows[0][3].clone(), rows[2][3].clone()),
        (json!(95.0), Value::Null)
    );
    assert_eq!(
        observation.findings,
        ["full@example.test uses 90 % or more of its quota."]
    );

    let three = json!({"list": (0..3).map(|n| account(&format!("user{n}@example.test"), Some(n), Some(100))).collect::<Vec<_>>()});
    let partial = mailboxes::mailboxes(&context, Some(&listed(&three)), 2).unwrap();
    assert_eq!(partial.state, State::Partial);
    assert_eq!(partial.table.unwrap().rows.len(), 2);
    // Exactly as many accounts as listed are not cut.
    assert_eq!(
        mailboxes::mailboxes(&context, Some(&listed(&three)), 3)
            .unwrap()
            .state,
        State::Ok
    );
    // A mailbox with a quota, however empty, comes before one without.
    let tiny = json!({"list": [account("open@example.test", Some(5), None), account("tiny@example.test", Some(1), Some(1000))]});
    let rows = mailboxes::mailboxes(&context, Some(&listed(&tiny)), 10)
        .unwrap()
        .table
        .unwrap()
        .rows;
    assert_eq!(rows[0][0], "tiny@example.test");
    // Without quotas, the largest mailbox comes first.
    let open = json!({"list": [account("a@example.test", Some(1), None), account("b@example.test", Some(9), None)]});
    let rows = mailboxes::mailboxes(&context, Some(&listed(&open)), 10)
        .unwrap()
        .table
        .unwrap()
        .rows;
    assert_eq!(
        (rows[0][0].as_str(), rows[1][0].as_str()),
        (Some("b@example.test"), Some("a@example.test"))
    );
    assert_eq!(
        mailboxes::mailboxes(&context, None, 2).unwrap().state,
        State::Unknown
    );
    // An account is shown with whatever is known of it.
    let odd = json!({"list": [
        {"@type": "User", "emailAddress": null, "usedDiskQuota": "much", "quotas": 5},
        {"@type": "User", "usedDiskQuota": 7, "quotas": {"maxDiskQuota": 0}},
        {"@type": "user", "emailAddress": "lower@example.test"},
        "no account",
    ]});
    let observation = mailboxes::mailboxes(&context, Some(&listed(&odd)), 10).unwrap();
    assert_eq!(
        observation.table.unwrap().rows,
        [
            vec![json!(""), json!(7), json!(0), Value::Null],
            vec![json!("null"), Value::Null, Value::Null, Value::Null],
        ]
    );
}

#[test]
fn the_exporter_is_read_with_its_credential() {
    let metrics = "stalwart_queue_message_queued_total 7\nstalwart_server_memory_bytes 2097152\n\
                   stalwart_smtp_active_connections 3\n";
    let server = serve(vec![answer(200, metrics), answer(401, "")]);
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), &server.url);
    let runner = Canned(String::new());
    let mut context = context(&config, &runner);
    context.metrics_credential = Some(("user".into(), "secret".into()));
    let provider = Prometheus::new(&table("type = \"prometheus\"")).unwrap();
    let report = provider.collect(&context).unwrap();
    assert_eq!(
        report.counters,
        [("queue_message_queued".to_owned(), 7.0)].into()
    );
    assert_eq!(
        report.gauges,
        [
            ("server_memory_mib".to_owned(), 2.0),
            ("smtp_connections".to_owned(), 3.0)
        ]
        .into()
    );
    let refused = provider.collect(&context).unwrap();
    assert_eq!(
        refused.observations[0].findings,
        ["The exporter answered HTTP 401."]
    );
    let request = server.requests().remove(0);
    assert!(request.starts_with("GET /metrics/prometheus HTTP/1.1"));
    assert!(request.contains("authorization: Basic dXNlcjpzZWNyZXQ=\r\n"));
    context.metrics_credential = None;
    let missing = provider.collect(&context).unwrap();
    assert_eq!(
        missing.observations[0].findings,
        ["No scrape credential is configured."]
    );
}

#[test]
fn a_scrape_without_every_gauge_is_a_warning() {
    let every_gauge = "stalwart_server_memory_bytes 2097152\nstalwart_smtp_active_connections 0\n\
                       stalwart_imap_active_connections 0\nstalwart_http_active_connections 0\n";
    let server = serve(vec![
        answer(200, every_gauge),
        answer(200, "stalwart_server_memory_bytes 2097152\n"),
    ]);
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), &server.url);
    let runner = Canned(String::new());
    let mut context = context(&config, &runner);
    context.metrics_credential = Some(("user".into(), "secret".into()));
    let provider = Prometheus::new(&table("type = \"prometheus\"")).unwrap();
    let complete = provider.collect(&context).unwrap();
    assert_eq!(complete.observations[0].state, State::Ok);
    assert_eq!(complete.counters.len(), 12, "every counter is zero");
    let partial = provider.collect(&context).unwrap();
    assert_eq!(partial.observations[0].state, State::Warning);
    assert!(partial.counters.is_empty());
    assert_eq!(partial.observations[0].findings.len(), 1);
}
