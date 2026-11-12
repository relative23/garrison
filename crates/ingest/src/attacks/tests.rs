use serde_json::{Value, json};

use super::*;
use crate::store::tests::{event, read, store};

const DAY: &str = "2026-10-28T";
/// 2026-10-28T00:00:00Z.
const MIDNIGHT: i64 = 1_793_145_600;

/// A failed sign-in at `time` of the day; with `account` Stalwart found one
/// of that name.
fn failed(seq: u64, time: &str, address: &str, account: Option<&str>) -> Value {
    let mut data =
        json!({"remoteIp": address, "listenerId": "submission", "reason": "Authentication failed"});
    if let Some(account) = account {
        data["accountName"] = json!(account);
        data["accountId"] = json!(7);
    } else {
        data["accountName"] = json!("hunter2");
        data["reason"] = json!("Account not found");
    }
    event(seq, "auth.failed", &format!("{DAY}{time}Z"), &data)
}

fn other(seq: u64, kind: &str, time: &str, address: &str) -> Value {
    event(
        seq,
        kind,
        &format!("{DAY}{time}Z"),
        &json!({"remoteIp": address, "listenerId": "imaps", "reason": "received corrupt message"}),
    )
}

fn summary(events: &[Value], since: i64, until: i64) -> Attacks {
    let directory = tempfile::tempdir().unwrap();
    store(directory.path(), 10_000).ingest(events, 1).unwrap();
    attacks(&read(directory.path()), since, until).unwrap()
}

#[test]
fn the_day_is_what_the_tests_take_it_for() {
    let directory = tempfile::tempdir().unwrap();
    store(directory.path(), 10)
        .ingest(&[failed(1, "00:00:00", "192.0.2.1", None)], 1)
        .unwrap();
    let at: i64 = read(directory.path())
        .query_row("SELECT created_at FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(at, MIDNIGHT);
}

#[test]
fn sign_ins_bans_and_handshakes_are_summed_by_address_network_and_account() {
    let events = [
        failed(1, "10:00:00", "192.0.2.10", Some("anna@example.test")),
        failed(2, "10:00:05", "192.0.2.10", Some("anna@example.test")),
        failed(3, "10:00:09", "192.0.2.10", Some("ben@example.test")),
        failed(4, "10:01:00", "192.0.2.10", None),
        other(5, "security.authentication-ban", "10:01:01", "192.0.2.10"),
        // The same network, each address under any limit.
        failed(6, "11:00:00", "192.0.2.77", Some("anna@example.test")),
        other(7, "tls.handshake-error", "11:30:00", "192.0.2.77"),
        // Somewhere else.
        other(8, "tls.handshake-error", "12:00:00", "2001:db8:1:2:aaaa::1"),
        other(9, "security.scan-ban", "12:00:01", "2001:db8:1:2:aaaa::1"),
    ];
    let summary = summary(&events, MIDNIGHT, MIDNIGHT + 86_399);
    assert!(!summary.truncated);
    assert_eq!(
        json!(summary.totals),
        json!({"failedSignIns": 5, "unknownAccounts": 1, "tlsErrors": 2, "bans": 2, "sources": 3})
    );
    assert_eq!(
        json!(summary.sources[0]),
        json!({
            "address": "192.0.2.10", "network": "192.0.2.0/24", "failedSignIns": 4,
            "accounts": 2, "tlsErrors": 0, "bans": 1,
            "firstSeen": MIDNIGHT + 36_000, "lastSeen": MIDNIGHT + 36_061,
            "listeners": ["imaps", "submission"],
        })
    );
    let order: Vec<&str> = summary
        .sources
        .iter()
        .map(|source| source.address.as_str())
        .collect();
    assert_eq!(order, ["192.0.2.10", "2001:db8:1:2:aaaa::1", "192.0.2.77"]);
    // Only the network with more than one address is a row of its own.
    assert_eq!(
        json!(summary.networks),
        json!([{"network": "192.0.2.0/24", "sources": 2, "failedSignIns": 5, "tlsErrors": 1,
                "bans": 1, "lastSeen": MIDNIGHT + 41_400}])
    );
    assert_eq!(
        json!(summary.accounts),
        json!([
            {"name": "anna@example.test", "failedSignIns": 3, "sources": 2, "lastSeen": MIDNIGHT + 39_600},
            {"name": "ben@example.test", "failedSignIns": 1, "sources": 1, "lastSeen": MIDNIGHT + 36_009},
        ])
    );
    assert_eq!(
        json!(summary.bans),
        json!([
            {"at": MIDNIGHT + 43_201, "address": "2001:db8:1:2:aaaa::1", "reason": "scan"},
            {"at": MIDNIGHT + 36_061, "address": "192.0.2.10", "reason": "authentication"},
        ])
    );
}

#[test]
fn a_name_that_is_no_account_is_never_stored_or_shown() {
    let directory = tempfile::tempdir().unwrap();
    store(directory.path(), 10)
        .ingest(&[failed(1, "10:00:00", "192.0.2.10", None)], 1)
        .unwrap();
    let stored: String = read(directory.path())
        .query_row("SELECT fields FROM events", [], |row| row.get(0))
        .unwrap();
    assert!(!stored.contains("hunter2"), "{stored}");
    assert!(stored.contains("Account not found"), "{stored}");
    let summary = attacks(&read(directory.path()), 0, i64::MAX).unwrap();
    assert_eq!(summary.accounts, Vec::new());
    assert_eq!(summary.totals.unknown_accounts, 1);
}

#[test]
fn only_the_stretch_asked_for_counts() {
    let events = [
        failed(1, "09:59:59", "192.0.2.10", None),
        failed(2, "10:00:00", "192.0.2.10", None),
        failed(3, "11:00:00", "192.0.2.10", None),
        failed(4, "11:00:01", "192.0.2.10", None),
    ];
    let summary = summary(&events, MIDNIGHT + 36_000, MIDNIGHT + 39_600);
    assert_eq!(summary.totals.failed_sign_ins, 2);
    assert_eq!(summary.sources[0].first_seen, MIDNIGHT + 36_000);
    let empty = tempfile::tempdir().unwrap();
    store(empty.path(), 10);
    let nothing = attacks(&read(empty.path()), 0, i64::MAX).unwrap();
    assert_eq!(
        nothing,
        Attacks {
            until: i64::MAX,
            ..Attacks::default()
        }
    );
}

#[test]
fn lists_keep_their_rows_and_the_totals_count_everything() {
    let events: Vec<Value> = (0..u64::try_from(MAX_ROWS + 5).unwrap())
        .map(|index| failed(index + 1, "10:00:00", &format!("198.51.{index}.1"), None))
        .collect();
    let summary = summary(&events, 0, i64::MAX);
    assert_eq!(summary.sources.len(), MAX_ROWS);
    assert_eq!(summary.totals.sources, MAX_ROWS as u64 + 5);
    // Equal counts come in the order of their names, the same on every request.
    assert_eq!(summary.sources[0].address, "198.51.0.1");
}

#[test]
fn addresses_count_to_their_network() {
    assert_eq!(network("203.0.113.200"), "203.0.113.0/24");
    assert_eq!(network("2001:db8:aa:bb:1:2:3:4"), "2001:db8:aa:bb::/64");
    // An IPv4 address a dual-stack listener reports in IPv6 form.
    assert_eq!(network("::ffff:203.0.113.200"), "203.0.113.0/24");
    assert_eq!(network("unknown"), "unknown");
}
