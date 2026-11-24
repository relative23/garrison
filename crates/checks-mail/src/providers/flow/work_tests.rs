//! How much work the reading of the week is, counted in steps of SQLite's
//! virtual machine and not in time, so that the answer is the same on every
//! machine, over the event history as the receiver keeps it, with its
//! indexes. The counts and the numbers of mail with and without TLS look at
//! every event of the week by design: they grow with the week, but only in
//! proportion. A query that comes to look through the week for each event,
//! as the count of mail with TLS would without the receiver's index of
//! sessions, fails here long before the reader's two seconds run out.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use garrison_ingest::store::{EventStore, Limits as Kept};
use rusqlite::Connection;
use serde_json::json;

use super::read::{self, DAY, DAYS, Limits};
use crate::testing::now;

const SMALL: i64 = 1_000;
const LARGE: i64 = 10_000;

/// A week of `sessions` sessions as the receiver keeps them: each hands in
/// mail on port 25, every other said STARTTLS first, and each message was
/// filed, passed by a milter and deferred by another, as while a scanner
/// cannot scan: then the look for a deferral in each message's session
/// runs over every message since yesterday.
fn week(directory: &Path, sessions: i64) -> Connection {
    let path = directory.join("events.sqlite");
    EventStore::open(&path, Kept::new(30, 10_000_000, 4 << 30)).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch("BEGIN").unwrap();
    let mut insert = db
        .prepare(
            "INSERT INTO events(event_id,created_at,received_at,type,category,span_id,fields) \
             VALUES(?1,?2,?2,?3,?4,?5,?6)",
        )
        .unwrap();
    let since = now().as_second() - DAYS * DAY;
    for session in 0..sessions {
        let at = since + session * DAYS * DAY / sessions;
        let filed = if session % 3 == 0 {
            "message-ingest.spam"
        } else {
            "message-ingest.ham"
        };
        let events = [
            (session % 2 == 0, "smtp.start-tls", json!({})),
            (
                true,
                "smtp.mail-from",
                json!({"from": format!("s@d{}.example", session % 50), "localPort": 25}),
            ),
            (true, filed, json!({"accountId": session % 7})),
            (true, "milter.action-accept", json!({})),
            (true, "milter.action-temp-fail", json!({})),
            (true, "smtp.dkim-pass", json!({})),
        ];
        for (index, (happened, kind, fields)) in events.into_iter().enumerate() {
            if happened {
                let category = kind.split('.').next().unwrap();
                let id = format!("{session}.{index}");
                insert
                    .execute((
                        id,
                        at,
                        kind,
                        category,
                        session.to_string(),
                        fields.to_string(),
                    ))
                    .unwrap();
            }
        }
    }
    drop(insert);
    db.execute_batch("COMMIT").unwrap();
    db
}

/// The steps SQLite takes to read the week from `db`.
fn steps(db: &mut Connection) -> u64 {
    let taken = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&taken);
    db.progress_handler(
        1,
        Some(move || {
            counter.fetch_add(1, Ordering::Relaxed);
            false
        }),
    )
    .unwrap();
    read::week(db, now().as_second(), &HashMap::new(), &Limits::WEEK).unwrap();
    db.progress_handler(0, None::<fn() -> bool>).unwrap();
    taken.load(Ordering::Relaxed)
}

#[test]
fn the_week_costs_in_proportion_to_its_events() {
    let (small, large) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let small = steps(&mut week(small.path(), SMALL));
    let large = steps(&mut week(large.path(), LARGE));
    assert!(large > small, "{small} steps, then {large}");
    assert!(
        large <= small * 12,
        "{small} steps for {SMALL} sessions, {large} for {LARGE}"
    );
}
