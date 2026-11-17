//! A reader of another service's database and that service's writer: a
//! snapshot that holds the writer's commit back, the reader's own time, a
//! request that went away, and a writer that holds its lock longer than a
//! reader waits, which the journal names.

use std::sync::{Mutex, Once, PoisonError, mpsc};
use std::thread;
use std::time::Duration;

use super::tests::MIGRATIONS;
use super::*;

/// The lines this test binary writes to its journal.
struct Journal(Mutex<Vec<String>>);

impl log::Log for Journal {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        let line = format!("{} {}", record.level(), record.args());
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    }

    fn flush(&self) {}
}

static JOURNAL: Journal = Journal(Mutex::new(Vec::new()));
static KEPT: Once = Once::new();

/// The kept lines that hold `words`; the first call starts keeping them.
fn kept(words: &str) -> Vec<String> {
    KEPT.call_once(|| {
        log::set_logger(&JOURNAL).unwrap();
        log::set_max_level(log::LevelFilter::Info);
    });
    JOURNAL
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|line| line.contains(words))
        .cloned()
        .collect()
}

/// With the rollback journal, which a database another service reads uses,
/// a reader's snapshot holds the writer's commit back: the writer waits for
/// it to end, the snapshot stays as it was meanwhile, and a reader that comes
/// while the writer waits gets the write once it is committed.
#[test]
fn a_writer_waits_for_a_snapshot_of_the_rollback_journal_and_new_readers_for_the_writer() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("items.sqlite");
    let writer = open_writer(&path, MIGRATIONS, Sharing::WithReaders, 0o600).unwrap();
    writer
        .execute("INSERT INTO item (name) VALUES ('a')", [])
        .unwrap();
    let count = |db: &Connection| -> i64 {
        db.query_row("SELECT count(*) FROM item", [], |row| row.get(0))
            .unwrap()
    };
    let reader = reading(&path, Duration::from_secs(2)).unwrap().unwrap();
    assert_eq!(count(&reader), 1);
    let (wrote, written) = mpsc::channel();
    let writing = thread::spawn(move || {
        let result = writer.execute("INSERT INTO item (name) VALUES ('b')", []);
        wrote
            .send(result.map_err(|error| error.to_string()))
            .unwrap();
    });
    let patience = Duration::from_millis(300);
    assert_eq!(
        written.recv_timeout(patience),
        Err(mpsc::RecvTimeoutError::Timeout),
        "the writer waits while the snapshot is open"
    );
    assert_eq!(count(&reader), 1);
    let later = path.clone();
    let (read, seen) = mpsc::channel();
    let reading_later = thread::spawn(move || {
        let db = reading(&later, Duration::from_secs(2)).unwrap().unwrap();
        read.send(count(&db)).unwrap();
    });
    assert_eq!(
        seen.recv_timeout(patience),
        Err(mpsc::RecvTimeoutError::Timeout),
        "a new reader waits for the write that waits"
    );
    drop(reader);
    // Well within the writer's five seconds and the new reader's two.
    assert_eq!(written.recv_timeout(Duration::from_secs(4)), Ok(Ok(1)));
    assert_eq!(seen.recv_timeout(Duration::from_secs(2)), Ok(2));
    writing.join().unwrap();
    reading_later.join().unwrap();
}

#[test]
fn reader_queries_stop_at_the_time_budget() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("items.sqlite");
    drop(open_writer(&path, MIGRATIONS, Sharing::WithReaders, 0o600).unwrap());
    let reader = reading(&path, Duration::from_millis(50)).unwrap().unwrap();
    let endless =
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n) SELECT count(*) FROM n";
    // On a thread of its own, a query that is never interrupted fails the
    // test instead of hanging it.
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let stopped = reader.query_row(endless, [], |row| row.get::<_, i64>(0));
        let missing = reader.query_row("SELECT 1 FROM nowhere", [], |row| row.get::<_, i64>(0));
        sender.send((
            stopped.is_err_and(|error| out_of_time(&error)),
            missing.is_err_and(|error| out_of_time(&error)),
        ))
    });
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(5)),
        Ok((true, false)),
        "the query must be interrupted, and only that counts as out of time"
    );
    // Within its budget, a long query runs to the end.
    let patient = reading(&path, Duration::from_secs(60)).unwrap().unwrap();
    let bounded = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100000) \
                   SELECT count(*) FROM n";
    let count = patient.query_row(bounded, [], |row| row.get::<_, i64>(0));
    assert_eq!(count.unwrap(), 100_000);
}

#[test]
fn reader_queries_stop_once_their_request_is_gone() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("items.sqlite");
    drop(open_writer(&path, MIGRATIONS, Sharing::WithReaders, 0o600).unwrap());
    let gone = Arc::new(AtomicBool::new(false));
    // A budget the test never waits for: only the flag can stop the query.
    let reader = reading_until(&path, Duration::from_secs(3600), Arc::clone(&gone))
        .unwrap()
        .unwrap();
    let endless =
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n) SELECT count(*) FROM n";
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let stopped = reader.query_row(endless, [], |row| row.get::<_, i64>(0));
        sender.send(stopped.is_err_and(|error| out_of_time(&error)))
    });
    // The query runs until the flag is set, and then stops.
    assert_eq!(
        receiver.recv_timeout(Duration::from_millis(200)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    gone.store(true, Ordering::Relaxed);
    assert_eq!(receiver.recv_timeout(Duration::from_secs(5)), Ok(true));
}

/// While the writer holds its lock, a new reader waits for it, up to two
/// seconds. Once the request it reads for has gone, it waits no more.
#[test]
fn a_reader_that_waits_for_the_writer_stops_once_its_request_is_gone() {
    kept("");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("items.sqlite");
    let writer = open_writer(&path, MIGRATIONS, Sharing::WithReaders, 0o600).unwrap();
    writer
        .execute("INSERT INTO item (name) VALUES ('a')", [])
        .unwrap();
    // A writer in the middle of its commit: no reader may begin.
    writer.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let read_while_locked = |gone: Arc<AtomicBool>| {
        let path = path.clone();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let count =
                reading_until(&path, Duration::from_secs(3600), gone).and_then(|reader| {
                    let reader = reader.unwrap();
                    Ok(reader
                        .query_row("SELECT count(*) FROM item", [], |row| row.get::<_, i64>(0))?)
                });
            sender
                .send(count.map_err(|error| error.to_string()))
                .unwrap();
        });
        receiver
    };
    let gone = Arc::new(AtomicBool::new(false));
    let waiting = read_while_locked(Arc::clone(&gone));
    assert_eq!(
        waiting.recv_timeout(Duration::from_millis(300)),
        Err(mpsc::RecvTimeoutError::Timeout),
        "the reader waits for the lock"
    );
    gone.store(true, Ordering::Relaxed);
    let gave_up = waiting
        .recv_timeout(Duration::from_millis(500))
        .expect("the reader stops waiting once its request is gone");
    assert!(gave_up.is_err(), "{gave_up:?}");
    // One whose request stays waits on and reads once the writer is done.
    let staying = read_while_locked(Arc::new(AtomicBool::new(false)));
    thread::sleep(Duration::from_millis(300));
    writer.execute_batch("COMMIT").unwrap();
    assert_eq!(staying.recv_timeout(Duration::from_secs(5)), Ok(Ok(1)));
    // Neither waited the writer out, so neither leaves a line.
    let lines = kept(&format!("A reader of {}", path.display()));
    assert!(lines.is_empty(), "{lines:?}");
}

/// A reader that waits out the writer's lock is told so by its error, and
/// by no other: neither a query out of its time nor a broken file reads as
/// the writer's moment.
#[test]
fn a_reader_that_waits_out_the_writer_is_told_so() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("items.sqlite");
    let writer = open_writer(&path, MIGRATIONS, Sharing::WithReaders, 0o600).unwrap();
    writer.execute_batch("BEGIN EXCLUSIVE").unwrap();
    kept("");
    let started = Instant::now();
    let error = reading(&path, Duration::from_secs(60)).unwrap_err();
    assert!(
        started.elapsed() >= FOR_THE_WRITER,
        "{:?}",
        started.elapsed()
    );
    let SqliteError::Sqlite(cause) = error else {
        panic!("{error}")
    };
    assert!(
        held_by_the_writer(&cause) && !out_of_time(&cause),
        "{cause}"
    );
    // The journal names the database, where an operator finds a writer
    // that does not let go.
    let lines = kept(&format!("A reader of {} waited", path.display()));
    assert_eq!(
        lines,
        [format!(
            "WARN A reader of {} waited 2 s for its writer and gave up: the writer held the \
             database longer than a reader waits",
            path.display()
        )]
    );
    writer.execute_batch("COMMIT").unwrap();
    let failure = |code| rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
    for other in [
        rusqlite::ffi::SQLITE_INTERRUPT,
        rusqlite::ffi::SQLITE_CORRUPT,
    ] {
        assert!(!held_by_the_writer(&failure(other)), "{other}");
    }
}

/// One line at once for each database, and then at most one a minute, with
/// how many readers waited out its writer since.
#[test]
fn readers_that_wait_out_a_writer_are_said_once_a_minute_for_each_database() {
    let mut said = BTreeMap::new();
    let events = Path::new("/var/lib/garrison/ingest/events.sqlite");
    let status = Path::new("/var/lib/garrison/collector/status.sqlite");
    let start = Instant::now();
    assert_eq!(
        waited_line(&mut said, events, start).unwrap(),
        "A reader of /var/lib/garrison/ingest/events.sqlite waited 2 s for its writer and gave \
         up: the writer held the database longer than a reader waits"
    );
    for second in [1, 30, 59] {
        let at = start + Duration::from_secs(second);
        assert_eq!(waited_line(&mut said, events, at), None);
    }
    assert!(waited_line(&mut said, status, start + Duration::from_secs(59)).is_some());
    let later = waited_line(&mut said, events, start + QUIET).unwrap();
    assert!(
        later.ends_with("; 3 more since the last such line"),
        "{later}"
    );
    let quiet = waited_line(&mut said, events, start + QUIET * 3).unwrap();
    assert!(!quiet.contains("more since"), "{quiet}");
}
