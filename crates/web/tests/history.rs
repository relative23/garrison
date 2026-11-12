//! The event history's answers through the API: every field of a delivery
//! and of a session, in the details and in the lists.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

mod support;

use garrison_core::config::Database;
use garrison_core::time;
use garrison_ingest::store::{EventStore, Limits};
use serde_json::json;
use support::setup;

fn api(path: &str) -> String {
    format!("/api/{path}")
}

/// One SMTP session (span 9) that queues a message (queue 7), and the
/// message's delivery, all in the second `at`.
fn a_session_and_its_delivery(at: &str) -> Vec<serde_json::Value> {
    let event = |id: u32, kind: &str, data: serde_json::Value| json!({"id": id.to_string(), "createdAt": at, "type": kind, "data": data});
    vec![
        event(
            2_000_001,
            "smtp.connection-start",
            json!({"spanId": 9, "listenerId": "smtp", "remoteIp": "192.0.2.1"}),
        ),
        event(
            2_000_002,
            "smtp.ehlo",
            json!({"spanId": 9, "domain": "client.example.net"}),
        ),
        event(
            2_000_003,
            "smtp.mail-from",
            json!({"spanId": 9, "from": "a@example.test"}),
        ),
        event(
            2_000_004,
            "smtp.rcpt-to",
            json!({"spanId": 9, "to": ["b@example.test"]}),
        ),
        event(2_000_005, "smtp.dkim-pass", json!({"spanId": 9})),
        event(2_000_006, "smtp.relay-not-allowed", json!({"spanId": 9})),
        event(
            2_000_007,
            "queue.message-queued",
            json!({"spanId": 9, "queueId": 7, "from": "a@example.test", "to": ["b@example.test"]}),
        ),
        event(2_000_008, "smtp.connection-end", json!({"spanId": 9})),
        event(
            2_000_009,
            "delivery.delivered",
            json!({"queueId": 7, "to": ["b@example.test"]}),
        ),
    ]
}

/// The event store of `setup` with that session and delivery recorded now;
/// the second they are recorded in.
fn record_a_session_and_its_delivery(setup: &support::Setup) -> i64 {
    let store = EventStore::open(
        &setup.config.database(Database::Events),
        Limits::new(30, 1000, 64 << 20),
    )
    .unwrap();
    let second = time::now().as_second();
    let at = time::isoformat(time::Timestamp::from_second(second).unwrap());
    store
        .ingest(&a_session_and_its_delivery(&at), second)
        .unwrap();
    second
}

#[tokio::test]
async fn summaries_state_every_field_in_details_and_lists() {
    let mut setup = setup();
    let second = record_a_session_and_its_delivery(&setup);
    setup.client.sign_in("code-admin").await;
    let delivery = setup.client.get(&api("deliveries/7")).await.json();
    assert_eq!(
        delivery["summary"],
        json!({
            "queueId": "7", "firstSeen": second, "lastSeen": second, "eventCount": 2,
            "from": "a@example.test", "to": ["b@example.test"], "status": "delivered",
            "recipientOutcomes": {"b@example.test": "delivered"},
            "recipientEvidenceComplete": true,
        })
    );
    assert_eq!(delivery["truncated"], false);
    let events = delivery["events"].as_array().unwrap();
    let types: Vec<&str> = events
        .iter()
        .map(|event| event["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["queue.message-queued", "delivery.delivered"]);
    assert_eq!(
        events[0],
        json!({
            "seq": 7, "id": "2000007", "createdAt": second, "type": "queue.message-queued",
            "label": "Queued message for delivery", "category": "queue", "spanId": "9",
            "queueId": "7",
            "fields": {"spanId": "9", "queueId": "7", "from": "a@example.test",
                       "to": ["b@example.test"]},
        })
    );
    let session = setup.client.get(&api("sessions/9")).await.json();
    assert_eq!(
        session["summary"],
        json!({
            "spanId": "9", "firstSeen": second, "lastSeen": second, "eventCount": 8,
            "listener": "smtp", "remoteIp": "192.0.2.1", "ehlo": "client.example.net",
            "from": "a@example.test", "to": ["b@example.test"],
            "authentication": {"dkim": "pass"}, "rejections": ["Relay not allowed"],
            "queueIds": ["7"], "complete": true,
        })
    );
    assert_eq!(session["events"].as_array().unwrap().len(), 8);
    // The lists show the same summaries.
    let deliveries = setup.client.get(&api("deliveries")).await.json();
    assert_eq!(
        deliveries,
        json!({"items": [delivery["summary"]], "next": null})
    );
    let sessions = setup.client.get(&api("sessions")).await.json();
    assert_eq!(
        sessions,
        json!({"items": [session["summary"]], "next": null})
    );
}

#[tokio::test]
async fn coverage_states_where_the_history_begins_and_what_is_missing_inside() {
    let mut setup = setup();
    let store = EventStore::open(
        &setup.config.database(Database::Events),
        Limits::new(30, 1000, 64 << 20),
    )
    .unwrap();
    let now = time::now().as_second();
    let began = now - 3 * 3600;
    store.start(began).unwrap();
    // One event a second from two hours ago on, a hundred more than the limit keeps.
    let first = now - 7200;
    let events: Vec<serde_json::Value> = (0..1100)
        .map(|index| {
            let at = time::isoformat(time::Timestamp::from_second(first + index).unwrap());
            json!({"id": (3_000_000 + index).to_string(), "createdAt": at, "type": "auth.failed", "data": {}})
        })
        .collect();
    store.ingest(&events, now - 5000).unwrap();
    // The receiver comes back after more than the hour Stalwart keeps events for it.
    store.start(now).unwrap();
    setup.client.sign_in("code-admin").await;
    assert_eq!(
        setup.client.get(&api("coverage")).await.json(),
        json!({
            "available": true, "receiver": "running", "heartbeatAt": now,
            "recordingSince": began, "lastBatchAt": now - 5000, "retentionDays": 30,
            "eventCount": 1000,
            // The limit removed the hundred oldest: the history begins after them.
            "trimmed": {"until": first + 99, "limit": "events"},
            "gapCount": 1,
            "gaps": [{"start": now - 5000, "end": now - 3600, "reason": "receiver-offline"}],
            "limitations": garrison_ingest::coverage::LIMITATIONS,
        })
    );
}

#[tokio::test]
async fn the_attack_summary_covers_the_period_asked_for() {
    let mut setup = setup();
    let store = EventStore::open(
        &setup.config.database(Database::Events),
        Limits::new(30, 1000, 64 << 20),
    )
    .unwrap();
    let now = time::now().as_second();
    store.start(now).unwrap();
    let event = |id: u32, ago: i64, kind: &str, data: serde_json::Value| {
        let at = time::isoformat(time::Timestamp::from_second(now - ago).unwrap());
        json!({"id": id.to_string(), "createdAt": at, "type": kind, "data": data})
    };
    let failed = |id: u32, ago: i64| {
        event(
            id,
            ago,
            "auth.failed",
            json!({"remoteIp": "192.0.2.1", "listenerId": "submission", "accountId": 3,
                   "accountName": "anna@example.test", "reason": "Authentication failed"}),
        )
    };
    store
        .ingest(
            &[
                failed(4_000_001, 60),
                failed(4_000_002, 2 * 86_400),
                event(
                    4_000_003,
                    30,
                    "security.authentication-ban",
                    json!({"remoteIp": "192.0.2.1", "accountName": "anna@example.test"}),
                ),
            ],
            now,
        )
        .unwrap();
    setup.client.sign_in("code-admin").await;
    let day = setup.client.get(&api("attacks")).await.json();
    assert_eq!(
        day["totals"],
        json!({"failedSignIns": 1, "unknownAccounts": 0, "tlsErrors": 0, "bans": 1, "sources": 1})
    );
    assert_eq!(
        day["sources"],
        json!([{
            "address": "192.0.2.1", "network": "192.0.2.0/24", "failedSignIns": 1, "accounts": 1,
            "tlsErrors": 0, "bans": 1, "firstSeen": now - 60, "lastSeen": now - 30,
            "listeners": ["submission"],
        }])
    );
    assert_eq!(
        day["accounts"],
        json!([{"name": "anna@example.test", "failedSignIns": 1, "sources": 1, "lastSeen": now - 60}])
    );
    assert_eq!(
        day["bans"],
        json!([{"at": now - 30, "address": "192.0.2.1", "reason": "authentication"}])
    );
    assert_eq!(day["networks"], json!([]));
    assert_eq!(day["truncated"], false);
    // The week also holds the attempt of two days ago.
    let week = setup.client.get(&api("attacks?period=7d")).await.json();
    assert_eq!(week["totals"]["failedSignIns"], 2);
    assert!(week["since"].as_i64().unwrap() <= now - 7 * 86_400 + 5);
}

/// Outgoing mail as the event history has it at `now`: a message that was
/// delayed an hour ago and still waits, a bounce half an hour ago, a
/// delivery, and a bounce three days ago, which is in the week only.
fn deliveries_with_problems(now: i64) -> Vec<serde_json::Value> {
    let event = |id: u32, ago: i64, kind: &str, data: serde_json::Value| {
        let at = time::isoformat(time::Timestamp::from_second(now - ago).unwrap());
        json!({"id": id.to_string(), "createdAt": at, "type": kind, "data": data})
    };
    let outcome = |id: u32, ago: i64, kind: &str, queue: u32, to: &str, details: &str| {
        let host = format!("mx.{}", to.rsplit('@').next().unwrap());
        event(
            id,
            ago,
            &format!("delivery.dsn-{kind}"),
            json!({"queueId": queue, "queueName": "remote", "to": to, "hostname": host, "details": details}),
        )
    };
    let refused = "550 5.7.1 Sender rejected";
    vec![
        event(
            5_000_001,
            7200,
            "queue.message-queued",
            json!({"queueId": 11, "from": "anna@example.test", "to": ["a@slow.example"]}),
        ),
        outcome(
            5_000_002,
            3600,
            "temp-fail",
            11,
            "a@slow.example",
            "Connection timed out",
        ),
        outcome(
            5_000_003,
            1800,
            "perm-fail",
            12,
            "c@strict.example",
            refused,
        ),
        outcome(5_000_004, 900, "success", 13, "f@fine.example", "OK"),
        outcome(
            5_000_005,
            3 * 86_400,
            "perm-fail",
            14,
            "g@strict.example",
            refused,
        ),
        // Stalwart is done with these three; the first still waits.
        event(
            5_000_006,
            1800,
            "delivery.completed",
            json!({"queueId": 12}),
        ),
        event(5_000_007, 900, "delivery.completed", json!({"queueId": 13})),
        event(
            5_000_008,
            3 * 86_400,
            "delivery.completed",
            json!({"queueId": 14}),
        ),
    ]
}

#[tokio::test]
async fn delivery_problems_name_destinations_causes_and_what_waits() {
    let mut setup = setup();
    let store = EventStore::open(
        &setup.config.database(Database::Events),
        Limits::new(30, 1000, 64 << 20),
    )
    .unwrap();
    let now = time::now().as_second();
    store.start(now).unwrap();
    store.ingest(&deliveries_with_problems(now), now).unwrap();
    setup.client.sign_in("code-admin").await;
    let day = setup.client.get(&api("destinations")).await.json();
    assert_eq!(
        day["totals"],
        json!({"delivered": 1, "delays": 1, "bounces": 1, "destinations": 2, "waiting": 1})
    );
    // Every field of a destination, a cause and a waiting message; the
    // newest problem first.
    assert_eq!(
        day["destinations"],
        json!([
            {"domain": "strict.example", "delivered": 0, "delays": 0, "bounces": 1,
             "lastProblem": now - 1800, "cause": "550 5.7.1 Sender rejected",
             "hosts": ["mx.strict.example"]},
            {"domain": "slow.example", "delivered": 0, "delays": 1, "bounces": 0,
             "lastProblem": now - 3600, "cause": "Connection timed out",
             "hosts": ["mx.slow.example"]},
        ])
    );
    assert_eq!(
        day["causes"],
        json!([
            {"cause": "550 5.7.1 Sender rejected", "delays": 0, "bounces": 1, "domains": 1,
             "lastSeen": now - 1800},
            {"cause": "Connection timed out", "delays": 1, "bounces": 0, "domains": 1,
             "lastSeen": now - 3600},
        ])
    );
    assert_eq!(
        day["waiting"],
        json!([{"queueId": "11", "queuedAt": now - 7200, "lastEvent": now - 3600}])
    );
    assert_eq!(day["truncated"], false);
    let week = setup
        .client
        .get(&api("destinations?period=7d"))
        .await
        .json();
    assert_eq!(week["totals"]["bounces"], 2);
    assert_eq!(week["destinations"][0]["bounces"], 2);
    assert!(week["since"].as_i64().unwrap() <= now - 7 * 86_400 + 5);
}
