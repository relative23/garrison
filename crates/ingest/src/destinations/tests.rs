use serde_json::{Value, json};

use super::*;
use crate::store::tests::{event, read, store};

const DAY: &str = "2026-10-28T";
/// 2026-10-28T00:00:00Z.
const MIDNIGHT: i64 = 1_793_145_600;

fn at(seq: u64, kind: &str, time: &str, data: &Value) -> Value {
    event(seq, kind, &format!("{DAY}{time}Z"), data)
}

/// An outcome of the remote queue for one recipient.
fn outcome(seq: u64, kind: &str, time: &str, queue: u64, to: &str, details: &str) -> Value {
    let host = format!("mx.{}", to.rsplit('@').next().unwrap());
    at(
        seq,
        kind,
        time,
        &json!({"queueId": queue, "queueName": "remote", "to": to, "hostname": host, "details": details}),
    )
}

fn summary(events: &[Value], since: i64, until: i64) -> Destinations {
    let directory = tempfile::tempdir().unwrap();
    store(directory.path(), 10_000).ingest(events, 1).unwrap();
    destinations(&read(directory.path()), since, until).unwrap()
}

#[test]
fn delays_and_bounces_are_summed_by_domain_and_cause() {
    let refused = "550 5.7.1 <anna@example.test>: Sender rejected, id 8839201177";
    let events = [
        outcome(
            1,
            "delivery.dsn-temp-fail",
            "09:00:00",
            11,
            "a@slow.example",
            "Connection timed out",
        ),
        outcome(
            2,
            "delivery.dsn-temp-fail",
            "09:30:00",
            11,
            "a@slow.example",
            "Connection timed out.",
        ),
        outcome(
            3,
            "delivery.dsn-temp-fail",
            "09:40:00",
            12,
            "b@Slow.Example",
            "451 4.7.1 Try again later",
        ),
        outcome(
            4,
            "delivery.dsn-perm-fail",
            "10:00:00",
            13,
            "c@strict.example",
            refused,
        ),
        outcome(
            5,
            "delivery.dsn-perm-fail",
            "10:00:01",
            14,
            "d@other.example",
            "550 5.7.1 <ben@example.test>: Sender rejected, id 8839201178",
        ),
        outcome(
            6,
            "delivery.dsn-success",
            "10:05:00",
            15,
            "e@strict.example",
            "OK",
        ),
        outcome(
            7,
            "delivery.dsn-success",
            "10:06:00",
            16,
            "f@fine.example",
            "OK",
        ),
        // Into a mailbox of this server: no destination.
        at(
            8,
            "delivery.dsn-success",
            "10:07:00",
            &json!({"queueId": 17, "queueName": "local", "to": "anna@example.test", "hostname": "localhost"}),
        ),
    ];
    let summary = summary(&events, MIDNIGHT, MIDNIGHT + 86_399);
    assert!(!summary.truncated);
    // These events tell no message's end, so each of the seven still waits.
    assert_eq!(
        json!(summary.totals),
        json!({"delivered": 2, "delays": 3, "bounces": 2, "destinations": 3, "waiting": 7})
    );
    // The domain with most problems first; one that only took mail is no row.
    assert_eq!(
        json!(summary.destinations),
        json!([
            {"domain": "slow.example", "delivered": 0, "delays": 3, "bounces": 0,
             "lastProblem": MIDNIGHT + 34_800, "cause": "Connection timed out",
             "hosts": ["mx.Slow.Example", "mx.slow.example"]},
            {"domain": "other.example", "delivered": 0, "delays": 0, "bounces": 1,
             "lastProblem": MIDNIGHT + 36_001, "cause": "550 5.7.1 Sender rejected, id",
             "hosts": ["mx.other.example"]},
            {"domain": "strict.example", "delivered": 1, "delays": 0, "bounces": 1,
             "lastProblem": MIDNIGHT + 36_000, "cause": "550 5.7.1 Sender rejected, id",
             "hosts": ["mx.strict.example"]},
        ])
    );
    // One cause is one row, whatever address or number it came with.
    assert_eq!(
        json!(summary.causes),
        json!([
            {"cause": "550 5.7.1 Sender rejected, id", "delays": 0, "bounces": 2, "domains": 2, "lastSeen": MIDNIGHT + 36_001},
            {"cause": "Connection timed out", "delays": 2, "bounces": 0, "domains": 1, "lastSeen": MIDNIGHT + 34_200},
            {"cause": "451 4.7.1 Try again later", "delays": 1, "bounces": 0, "domains": 1, "lastSeen": MIDNIGHT + 34_800},
        ])
    );
}

#[test]
fn a_message_without_a_recorded_end_waits() {
    let queued = |seq: u64, time: &str, queue: u64| {
        at(
            seq,
            "queue.message-queued",
            time,
            &json!({"queueId": queue, "to": ["a@slow.example"]}),
        )
    };
    let events = [
        queued(1, "08:00:00", 21),
        outcome(
            2,
            "delivery.dsn-temp-fail",
            "08:00:05",
            21,
            "a@slow.example",
            "Connection timed out",
        ),
        queued(3, "09:00:00", 22),
        at(4, "delivery.completed", "09:00:02", &json!({"queueId": 22})),
        queued(5, "09:30:00", 23),
        at(6, "delivery.failed", "09:30:02", &json!({"queueId": 23})),
        queued(7, "10:00:00", 24),
    ];
    let summary = summary(&events, MIDNIGHT, MIDNIGHT + 86_399);
    assert_eq!(summary.totals.waiting, 2);
    assert_eq!(
        json!(summary.waiting),
        json!([
            {"queueId": "21", "queuedAt": MIDNIGHT + 28_800, "lastEvent": MIDNIGHT + 28_805},
            {"queueId": "24", "queuedAt": MIDNIGHT + 36_000, "lastEvent": MIDNIGHT + 36_000},
        ])
    );
    // A week later Stalwart has long given up on them: they wait no more.
    let later = MIDNIGHT + 8 * 86_400;
    let directory = tempfile::tempdir().unwrap();
    store(directory.path(), 100).ingest(&events, 1).unwrap();
    let old = destinations(&read(directory.path()), later - 86_400, later).unwrap();
    assert_eq!((old.totals.waiting, old.waiting.len()), (0, 0));
}

#[test]
fn causes_lose_what_differs_from_message_to_message() {
    assert_eq!(
        cause("DNS lookup failed: no MX record found."),
        "DNS lookup failed: no MX record found"
    );
    assert_eq!(
        cause("550 5.1.1 <user@example.org>: Recipient address rejected: User unknown"),
        "550 5.1.1 Recipient address rejected: User unknown"
    );
    assert_eq!(
        cause("421 4.3.2 queue id 1A2B3C4D5E667788 try later"),
        "421 4.3.2 queue id try later"
    );
    assert_eq!(cause(""), "No cause recorded");
    assert_eq!(cause(&"x".repeat(500)).chars().count(), 120);
    assert_eq!(
        domain("<Anna@Example.ORG.>").as_deref(),
        Some("example.org")
    );
    assert_eq!(domain("no-address"), None);
}
