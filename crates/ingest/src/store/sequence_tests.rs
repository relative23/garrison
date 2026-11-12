//! The store under long random sequences of what happens to it in production:
//! batches (some events sent twice, some late, some not recordable), cleanups,
//! heartbeats and restarts with and without lost time. After every step the
//! rules the history promises must hold. The limit tests check single
//! boundaries; these check that nothing drifts over time. The sequences are
//! the same on every run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use garrison_testing::noise::Noise;
use serde_json::json;

use super::tests::{event, read};
use super::*;
use crate::coverage;
use crate::queries::{self, Filter};

const BEGINNING: i64 = 1_793_000_000;
const DAY: i64 = 86400;
/// As `Limits::new` sets it: what Stalwart keeps for a receiver that is away.
const BUFFERED: i64 = 3600;
/// As the store's `CLEANUP_AFTER`.
const CLEANUP_AFTER: u64 = 1000;
const KINDS: [&str; 3] = ["auth.failed", "smtp.ehlo", "queue.message-queued"];

/// The store and what a correct store must hold after everything done to it.
struct Run {
    /// The directory goes with the run.
    _home: tempfile::TempDir,
    directory: PathBuf,
    limits: Limits,
    events: Option<EventStore>,
    noise: Noise,
    clock: i64,
    next: u64,
    /// Every event the store took, by its ID: when it was created and its type.
    taken: BTreeMap<String, (i64, &'static str)>,
    heartbeat: Option<i64>,
    began: Option<i64>,
    /// The windows in which the receiver was away for longer than Stalwart buffers.
    away: Vec<(i64, i64)>,
    /// Events created before this were removed for their age at the last cleanup.
    cutoff: i64,
    since_cleanup: u64,
    /// The reasons of every window the store ever kept.
    seen: BTreeSet<String>,
}

impl Run {
    fn new(limits: Limits, seed: u64) -> Run {
        let home = tempfile::tempdir().unwrap();
        let mut run = Run {
            directory: home.path().to_owned(),
            _home: home,
            limits,
            events: None,
            noise: Noise::new(seed),
            clock: BEGINNING,
            next: 0,
            taken: BTreeMap::new(),
            heartbeat: None,
            began: None,
            away: Vec::new(),
            cutoff: i64::MIN,
            since_cleanup: 0,
            seen: BTreeSet::new(),
        };
        run.start();
        run
    }

    fn store(&self) -> &EventStore {
        self.events.as_ref().unwrap()
    }

    /// The service starts: a new process opens the history.
    fn start(&mut self) {
        self.events = None;
        let store = EventStore::open(&self.directory.join("events.sqlite"), self.limits).unwrap();
        store.start(self.clock).unwrap();
        if let Some(last) = self.heartbeat
            && self.clock - BUFFERED > last
        {
            self.away.push((last, self.clock - BUFFERED));
        }
        self.began.get_or_insert(self.clock);
        self.heartbeat = Some(self.clock);
        self.since_cleanup = 0;
        self.events = Some(store);
    }

    fn cleaned(&mut self) {
        self.cutoff = self.clock - i64::from(self.limits.retention_days) * DAY;
        let cutoff = self.cutoff;
        self.away.retain(|(_, end)| *end >= cutoff);
        self.since_cleanup = 0;
    }

    /// One event of a batch and, if the store must take it, its ID.
    fn one(&mut self) -> (Value, Option<String>) {
        let at = |second: i64| time::isoformat(time::Timestamp::from_second(second).unwrap());
        let choice = self.noise.below(100);
        self.next += 1;
        let number = self.next;
        if choice < 4 {
            // A type the policy never records.
            return (
                event(number, "smtp.raw-input", &at(self.clock), &json!({})),
                None,
            );
        }
        if choice < 6 {
            return (event(number, "auth.failed", "yesterday", &json!({})), None);
        }
        if choice < 16 && !self.taken.is_empty() {
            // Stalwart sends a batch again when it saw no answer.
            let index = self.noise.below(self.taken.len());
            let (id, (created, kind)) = self.taken.iter().nth(index).unwrap();
            let again = json!({"id": id, "createdAt": at(*created), "type": kind, "data": {}});
            return (again, Some(id.clone()));
        }
        // Most events are of this minute; a few arrive up to three days late.
        let age = if self.noise.below(20) == 0 {
            self.noise.below(3 * 86400)
        } else {
            self.noise.below(120)
        };
        let created = self.clock - i64::try_from(age).unwrap();
        let kind = KINDS[self.noise.below(KINDS.len())];
        // Sessions and deliveries come and go: a few are open at a time, and
        // an old one gets no further event.
        let group = number / 8 + u64::try_from(self.noise.below(4)).unwrap();
        let data = match kind {
            "smtp.ehlo" => json!({"spanId": group}),
            "queue.message-queued" => json!({"queueId": group}),
            _ => json!({}),
        };
        let sent = event(number, kind, &at(created), &data);
        let id = sent["id"].as_str().unwrap().to_owned();
        self.taken.insert(id.clone(), (created, kind));
        (sent, Some(id))
    }

    fn ingest(&mut self) {
        let held = stored(&self.directory);
        let count = 1 + self.noise.below(120);
        let mut batch = Vec::new();
        let mut fresh = BTreeSet::new();
        for _ in 0..count {
            let (sent, id) = self.one();
            if let Some(id) = id.filter(|id| !held.contains_key(id)) {
                fresh.insert(id);
            }
            batch.push(sent);
        }
        let outcome = self.store().ingest(&batch, self.clock).unwrap();
        let expected = u64::try_from(fresh.len()).unwrap();
        assert_eq!(
            (outcome.stored, outcome.skipped),
            (expected, u64::try_from(count).unwrap() - expected),
            "what a batch stores and skips"
        );
        self.heartbeat = Some(self.clock);
        self.since_cleanup += outcome.stored;
        if self.since_cleanup >= CLEANUP_AFTER {
            self.cleaned();
        }
    }

    /// One thing that happens to the receiver, then every rule.
    fn step(&mut self) {
        self.clock += i64::try_from(self.noise.below(900)).unwrap();
        match self.noise.below(100) {
            0..62 => self.ingest(),
            62..74 => {
                self.store().enforce_limits(self.clock).unwrap();
                self.cleaned();
                let kept = i64::try_from(stored(&self.directory).len()).unwrap();
                assert!(
                    kept <= i64::from(self.limits.max_events),
                    "{kept} events after a cleanup"
                );
            }
            74..82 => {
                self.store().heartbeat(self.clock).unwrap();
                self.heartbeat = Some(self.clock);
            }
            82..92 => self.start(),
            _ => {
                // Down for longer than Stalwart keeps events for the receiver.
                self.clock += BUFFERED + 1 + i64::try_from(self.noise.below(7200)).unwrap();
                self.start();
            }
        }
        self.check();
    }

    fn check(&mut self) {
        let db = read(&self.directory);
        let held = stored(&self.directory);
        for id in held.keys() {
            assert!(
                self.taken.contains_key(id),
                "the history holds {id}, which was never sent"
            );
        }
        let mut statement = db
            .prepare("SELECT start_at, end_at, reason FROM gaps ORDER BY start_at, end_at")
            .unwrap();
        let windows: Vec<(i64, i64, String)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(windows.iter().all(|(start, end, _)| start <= end));
        let mut trimmed: Option<(i64, &str)> = None;
        for limit in [EVENT_LIMIT, STORAGE_BUDGET] {
            let of_limit: Vec<_> = windows.iter().filter(|window| window.2 == limit).collect();
            assert!(
                of_limit.len() <= 1,
                "{} windows for {limit}",
                of_limit.len()
            );
            if let Some((_, end, _)) = of_limit.first()
                && trimmed.is_none_or(|(until, _)| *end > until)
            {
                trimmed = Some((*end, limit));
            }
        }
        self.seen
            .extend(windows.iter().map(|window| window.2.clone()));
        // Nothing is lost silently: what the store took is there, or went for
        // a size limit that says until when, or for its age.
        for (id, (created, _)) in &self.taken {
            assert!(
                held.contains_key(id)
                    || trimmed.is_some_and(|(until, _)| *created <= until)
                    || *created < self.cutoff,
                "event {id} of {created} is gone without a reason (cutoff {}, trimmed {trimmed:?})",
                self.cutoff
            );
        }
        let away: Vec<(i64, i64)> = windows
            .iter()
            .filter(|window| window.2 == OFFLINE)
            .map(|window| (window.0, window.1))
            .collect();
        assert_eq!(away, self.away, "the windows the receiver was away for");
        let since: String = db
            .query_row(
                "SELECT value FROM metadata WHERE key='recordingSince'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(Some(since.parse::<i64>().unwrap()), self.began);

        let covered = coverage::read(Some(&db), self.clock).unwrap();
        assert_eq!(covered.event_count, i64::try_from(held.len()).unwrap());
        assert_eq!(covered.gap_count, i64::try_from(self.away.len()).unwrap());
        assert_eq!(
            covered.trimmed.map(|trimmed| trimmed.until),
            trimmed.map(|(until, _)| until)
        );
        assert_eq!(covered.recording_since, self.began);

        // A delivery or a session is listed only while it has an event, and
        // every event's delivery and session are there. Between two cleanups
        // a size limit has not run, so nothing is without events then either.
        for (table, key) in [("queues", "queue_id"), ("spans", "span_id")] {
            let count = |sql: String| -> i64 { db.query_row(&sql, [], |row| row.get(0)).unwrap() };
            assert_eq!(
                count(format!(
                    "SELECT count(*) FROM {table} WHERE NOT EXISTS \
                     (SELECT 1 FROM events WHERE events.{key} = {table}.{key})"
                )),
                0,
                "{table} without an event"
            );
            assert_eq!(
                count(format!(
                    "SELECT count(*) FROM events WHERE {key} IS NOT NULL AND NOT EXISTS \
                     (SELECT 1 FROM {table} WHERE {table}.{key} = events.{key})"
                )),
                0,
                "events whose {table} row is missing"
            );
        }

        // Page by page the list shows every event once, newest first.
        let mut before = None;
        let mut listed = Vec::new();
        loop {
            let filter = Filter {
                limit: 200,
                before,
                ..Filter::default()
            };
            let page = queries::list_events(&db, &filter).unwrap();
            listed.extend(page.items.iter().map(|item| item.seq));
            before = page.next;
            if before.is_none() {
                break;
            }
        }
        assert_eq!(listed.len(), held.len(), "the pages list every event");
        assert!(listed.windows(2).all(|pair| pair[0] > pair[1]));
    }
}

/// The events in the history: when each was created, by ID.
fn stored(directory: &Path) -> BTreeMap<String, i64> {
    let db = read(directory);
    let mut statement = db
        .prepare("SELECT event_id, created_at FROM events")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn run(limits: Limits, seed: u64) -> Run {
    let mut run = Run::new(limits, seed);
    for _ in 0..250 {
        run.step();
    }
    run.events = None;
    run
}

#[test]
fn the_event_limit_never_loses_an_event_silently() {
    for seed in [11, 12, 13, 14] {
        let run = run(Limits::new(30, 1500, 64 << 20), seed);
        assert!(
            run.seen.contains(EVENT_LIMIT),
            "seed {seed} met the event limit"
        );
        assert!(!run.seen.contains(STORAGE_BUDGET));
    }
}

#[test]
fn the_storage_budget_never_loses_an_event_silently() {
    for seed in [21, 22, 23] {
        let run = run(Limits::new(30, 100_000, 1 << 20), seed);
        assert!(
            run.seen.contains(STORAGE_BUDGET),
            "seed {seed} met the storage budget"
        );
        assert!(!run.seen.contains(EVENT_LIMIT));
    }
}

#[test]
fn retention_removes_by_age_alone() {
    for seed in [31, 32, 33] {
        let run = run(Limits::new(1, 100_000, 64 << 20), seed);
        assert!(!run.seen.contains(EVENT_LIMIT) && !run.seen.contains(STORAGE_BUDGET));
        let kept = stored(&run.directory).len();
        assert!(
            kept < run.taken.len(),
            "seed {seed}: events older than a day went ({kept} of {})",
            run.taken.len()
        );
    }
}
