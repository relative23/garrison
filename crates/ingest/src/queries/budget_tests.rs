//! The response-size budget of the pages of deliveries and sessions and of
//! their details. An event holds up to a hundred addresses, and a session
//! or a delivery up to 256 events that count.

use serde::Serialize;
use serde_json::json;

use super::tests::limit;
use super::*;
use crate::store::tests::{event, read, store};

const GROUPS: u64 = 40;

/// A hundred addresses as long as an address may be: about 26 kB of JSON.
fn long_addresses() -> Vec<String> {
    (0..100)
        .map(|index| format!("{}{index:03}@example.test", "x".repeat(230)))
        .collect()
}

/// Forty sessions and forty deliveries, each naming those addresses: every
/// summary is about 26 kB, a page of all of them about 1 MB.
fn large_groups() -> Vec<Value> {
    let to = long_addresses();
    (1..=GROUPS)
        .flat_map(|index| {
            let at = format!("2026-10-28T10:{:02}:{:02}Z", index / 60, index % 60);
            [
                event(
                    index * 2,
                    "smtp.rcpt-to",
                    &at,
                    &json!({"spanId": index, "to": to}),
                ),
                event(
                    index * 2 + 1,
                    "queue.message-queued",
                    &at,
                    &json!({"queueId": 1000 + index, "to": to}),
                ),
            ]
        })
        .collect()
}

/// Every page from the first to the last, each within the budget.
fn pages<S: Serialize>(read: impl Fn(&Filter) -> Page<S>) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut filter = limit(100);
    loop {
        let page = read(&filter);
        let size = json!(page.items).to_string().len();
        assert!(size <= MAX_RESPONSE_BYTES, "a page of {size} bytes");
        assert_ne!(page.items.len(), 0, "a page that holds nothing");
        sizes.push(page.items.len());
        match page.next {
            Some(next) => filter.before = Some(next),
            None => return sizes,
        }
        assert!(sizes.len() < 100, "the pages do not end");
    }
}

#[test]
fn a_page_of_sessions_or_deliveries_stays_within_its_byte_budget() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    events.arriving(&large_groups()).unwrap();
    let db = read(directory.path());
    for sizes in [
        pages(|filter| list_sessions(&db, filter).unwrap()),
        pages(|filter| list_deliveries(&db, filter).unwrap()),
    ] {
        // More than one page, and every group on exactly one of them.
        assert!(sizes.len() > 1, "{sizes:?}");
        assert_eq!(sizes.iter().sum::<usize>(), 40, "{sizes:?}");
    }
}

#[test]
fn a_detail_stays_within_its_byte_budget() {
    let directory = tempfile::tempdir().unwrap();
    let events = store(directory.path(), 1000);
    let to = long_addresses();
    // Forty events of one delivery and of one session: about 1 MB each.
    let batch: Vec<Value> = (1..=GROUPS)
        .flat_map(|index| {
            let at = format!("2026-10-28T10:00:{index:02}Z");
            [
                event(
                    index * 2,
                    "smtp.rcpt-to",
                    &at,
                    &json!({"spanId": 7, "to": to}),
                ),
                event(
                    index * 2 + 1,
                    "delivery.delivered",
                    &at,
                    &json!({"queueId": 8, "to": to}),
                ),
            ]
        })
        .collect();
    events.arriving(&batch).unwrap();
    let db = read(directory.path());
    let session = session_detail(&db, "7").unwrap().unwrap();
    let delivery = delivery_detail(&db, "8").unwrap().unwrap();
    for (shown, truncated, size) in [
        (
            session.events.len(),
            session.truncated,
            json!(session).to_string().len(),
        ),
        (
            delivery.events.len(),
            delivery.truncated,
            json!(delivery).to_string().len(),
        ),
    ] {
        // The first events are shown, and that there are more is said.
        assert!((1..40).contains(&shown), "{shown}");
        assert!(truncated);
        // The summary, some 30 kB at most, comes on top of the events.
        assert!(size <= MAX_RESPONSE_BYTES + 64 * 1024, "{size}");
    }
    // The summary itself still counts every event.
    assert_eq!(session.summary.event_count, 40);
}
