//! No reader waits for good at a name SQLite opens that the user who writes
//! a database may replace: the database itself, its journal, and a
//! write-ahead log with its shared memory. SQLite opens each by its name
//! and without `O_NONBLOCK`, so a named pipe there, which nobody writes to,
//! holds the open, and with it the reader: in the collector the whole run,
//! in the web service one of the two turns of the history queries.

use std::collections::BTreeMap;
use std::fs::{self, Permissions};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use rustix::fs::{CWD, FileType, Mode, OFlags, RenameFlags};

use super::reading;

/// Longer than a reader waits for SQLite to open a database.
const PATIENCE: Duration = Duration::from_secs(8);

/// A named pipe at `path` that nobody writes to, with `mode`.
fn pipe(path: &Path, mode: u32) {
    rustix::fs::mknodat(CWD, path, FileType::Fifo, Mode::from_raw_mode(mode), 0).unwrap();
}

/// Lets go a reader that waits in SQLite's open of the pipe at `path`, as a
/// writer of the pipe would: opens it for writing without waiting, which
/// succeeds only while someone waits to read it, and closes it again.
fn release(path: &Path) {
    if fs::set_permissions(path, Permissions::from_mode(0o644)).is_err() {
        return;
    }
    let flags = OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
    for _ in 0..50 {
        if let Ok(writer) = rustix::fs::open(path, flags, Mode::empty()) {
            thread::sleep(Duration::from_millis(20));
            drop(writer);
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// A database at `path` with one row in `t`, in write-ahead mode where
/// `wal`: its log and shared memory are gone once it is closed.
fn database(path: &Path, wal: bool) {
    let db = Connection::open(path).unwrap();
    if wal {
        let mode: String = db
            .pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
    }
    db.execute_batch("CREATE TABLE t(a); INSERT INTO t VALUES(1);")
        .unwrap();
}

/// How a reader of `path` and its first query end, on a thread of their
/// own, with `then` run between the two: the query's count, or the error.
fn read(path: &Path, then: impl FnOnce() + Send + 'static) -> mpsc::Receiver<Result<i64, String>> {
    let (sender, receiver) = mpsc::channel();
    let path = path.to_owned();
    thread::spawn(move || {
        let counted = reading(&path, Duration::from_secs(2))
            .map_err(|error| error.to_string())
            .and_then(|reader| {
                let reader = reader.ok_or_else(|| "absent".to_owned())?;
                then();
                reader
                    .query_row("SELECT count(*) FROM t", [], |row| row.get::<_, i64>(0))
                    .map_err(|error| error.to_string())
            });
        let _ = sender.send(counted);
    });
    receiver
}

/// The name of `path` with `suffix` after it, as SQLite names a journal.
fn beside(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", path.display()))
}

#[test]
fn no_reader_waits_for_good_at_a_pipe_in_place_of_a_file_sqlite_opens() {
    // Each name SQLite opens besides the database, with the journal mode in
    // which it does; the pipe is there before the reader opens, or, for the
    // journal, comes between its open and its first query. A pipe that only
    // the writer may write makes SQLite try it for reading, as a reader of
    // another user's database does. Every database is made first: an open
    // of SQLite's while a reader waits is what the last check asks of.
    let directory = tempfile::tempdir().unwrap();
    let cases = [
        ("-journal", false, false),
        ("-journal", false, true),
        ("-wal", true, false),
        ("-shm", true, false),
    ];
    let mut made = Vec::new();
    for (suffix, wal, after_the_open) in cases {
        let when = if after_the_open { "after" } else { "before" };
        let path = directory.path().join(format!("{when}{suffix}.sqlite"));
        database(&path, wal);
        let name = beside(&path, suffix);
        if !after_the_open {
            pipe(&name, 0o444);
        }
        made.push((
            format!("{when} the open: {suffix}"),
            path,
            name,
            after_the_open,
        ));
    }
    let elsewhere = directory.path().join("elsewhere.sqlite");
    database(&elsewhere, false);
    let started = Instant::now();
    let readers: Vec<_> = made
        .iter()
        .map(|(case, path, name, after_the_open)| {
            let receiver = if *after_the_open {
                let name = name.clone();
                read(path, move || pipe(&name, 0o444))
            } else {
                read(path, || {})
            };
            (case.clone(), receiver)
        })
        .collect();
    // Another database of this process, opened while they wait.
    thread::sleep(Duration::from_millis(200));
    let other = read(&elsewhere, || {});
    let until = started + PATIENCE;
    let left = || until.saturating_duration_since(Instant::now());
    let ended: Vec<(String, Option<Result<i64, String>>)> = readers
        .iter()
        .map(|(case, receiver)| (case.clone(), receiver.recv_timeout(left()).ok()))
        .collect();
    let other = other.recv_timeout(left()).ok();
    for (_, _, name, _) in &made {
        release(name);
    }
    assert_eq!(
        other,
        Some(Ok(1)),
        "another database of the process; {ended:?}"
    );
    let held: Vec<&String> = ended
        .iter()
        .filter(|(_, end)| end.is_none())
        .map(|(case, _)| case)
        .collect();
    assert_eq!(held, Vec::<&String>::new(), "{ended:?}");
    // A reader that opened before the pipe came reads its snapshot.
    assert_eq!(ended[1].1, Some(Ok(1)), "{ended:?}");
}

#[test]
fn no_reader_waits_for_good_at_a_pipe_swapped_in_after_its_look() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("swapped.sqlite");
    let other = directory.path().join("other");
    database(&path, false);
    pipe(&other, 0o644);
    let (stop, pause) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let swaps = Arc::new(AtomicU64::new(0));
    // The writer of the folder swaps the database and a pipe, as fast as it can.
    let swapper = {
        let (stop, pause, swaps) = (Arc::clone(&stop), Arc::clone(&pause), Arc::clone(&swaps));
        let (a, b) = (path.clone(), other.clone());
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                if pause.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                rustix::fs::renameat_with(CWD, &a, CWD, &b, RenameFlags::EXCHANGE).unwrap();
                swaps.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    let mut answers: BTreeMap<String, u64> = BTreeMap::new();
    let mut slowest = Duration::ZERO;
    let began = Instant::now();
    let mut held = false;
    while began.elapsed() < Duration::from_secs(10) && !held {
        let asked = Instant::now();
        match read(&path, || {}).recv_timeout(PATIENCE) {
            Ok(answer) => {
                slowest = slowest.max(asked.elapsed());
                let said = answer.map_or_else(|error| error, |_| "read".to_owned());
                *answers.entry(said.chars().take(60).collect()).or_default() += 1;
            }
            Err(_) => held = true,
        }
    }
    // Lets go a reader held in SQLite's open of the pipe, wherever it is now.
    pause.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(20));
    for name in [&path, &other] {
        if fs::symlink_metadata(name).is_ok_and(|found| found.file_type().is_fifo()) {
            release(name);
        }
    }
    stop.store(true, Ordering::SeqCst);
    swapper.join().unwrap();
    let exchanges = swaps.load(Ordering::Relaxed);
    assert!(
        !held,
        "a reader waited past {PATIENCE:?} beside {exchanges} swaps; {answers:?}"
    );
    assert!(exchanges > 1000, "{exchanges}");
    assert!(slowest < PATIENCE, "{slowest:?}; {answers:?}");
}

#[test]
fn a_reader_left_waiting_in_an_open_holds_no_other() {
    // A pipe at the journal's name of one database: its reader is left
    // waiting in SQLite's open.
    let directory = tempfile::tempdir().unwrap();
    let (held, other) = (
        directory.path().join("held.sqlite"),
        directory.path().join("other.sqlite"),
    );
    database(&held, false);
    database(&other, false);
    let journal = beside(&held, "-journal");
    pipe(&journal, 0o444);
    let asked = Instant::now();
    let first = read(&held, || {}).recv_timeout(PATIENCE);
    assert!(asked.elapsed() < PATIENCE, "{first:?}");
    assert!(
        matches!(&first, Ok(Err(why)) if why.contains("did not open") && why.contains("held.sqlite")),
        "{first:?}"
    );
    // While that open waits, a reader of the same database is refused at
    // once, and one of another database reads.
    let asked = Instant::now();
    let second = read(&held, || {}).recv_timeout(PATIENCE);
    assert!(asked.elapsed() < Duration::from_secs(1), "{second:?}");
    assert!(
        matches!(&second, Ok(Err(why)) if why.contains("still waits")),
        "{second:?}"
    );
    assert_eq!(read(&other, || {}).recv_timeout(PATIENCE), Ok(Ok(1)));
    // Once the waiting open has ended, the database is read again.
    release(&journal);
    fs::remove_file(&journal).unwrap();
    let until = Instant::now() + PATIENCE;
    loop {
        let third = read(&held, || {}).recv_timeout(PATIENCE);
        if third == Ok(Ok(1)) {
            break;
        }
        assert!(Instant::now() < until, "{third:?}");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_database_in_write_ahead_mode_is_not_read_and_its_log_not_opened() {
    // The log and the shared memory beside it are files the writing user
    // may replace, and SQLite opens the shared memory holding a lock of the
    // whole process; a database another service reads keeps the rollback
    // journal.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("logged.sqlite");
    database(&path, true);
    let asked = Instant::now();
    let refused = read(&path, || {}).recv_timeout(PATIENCE);
    assert!(matches!(refused, Ok(Err(_))), "{refused:?}");
    assert!(
        asked.elapsed() < Duration::from_secs(1),
        "{:?}",
        asked.elapsed()
    );
    for suffix in ["-wal", "-shm"] {
        assert!(
            fs::symlink_metadata(beside(&path, suffix)).is_err(),
            "{suffix}"
        );
    }
}
