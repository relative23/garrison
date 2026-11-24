//! SQLite connections and ordered schema migrations.
//!
//! Each database has exactly one writing component. Databases that another
//! service user reads use the rollback journal instead of WAL: a read-only WAL
//! reader would need write access to the shared-memory file, which would weaken
//! the boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions, Permissions};
use std::io;
use std::ops::Deref;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags};

use crate::config::Database;

/// One schema version: statements applied together in one transaction.
pub type Migration = &'static [&'static str];

#[derive(Debug, thiserror::Error)]
pub enum SqliteError {
    #[error(
        "The database was created by a newer release; restore the matching release or its \
         backup instead of downgrading in place."
    )]
    NewerSchema,
    #[error("SQLite kept journal mode {0}")]
    JournalMode(String),
    #[error("The database holds objects Garrison never creates; it is not read")]
    ForeignSchema,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// How the writer shares its database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sharing {
    /// Read by another service user: rollback journal.
    WithReaders,
    /// Read only by the writing service: write-ahead log.
    Private,
}

/// Open the single writer connection and apply pending migrations in order.
///
/// A new file is created with `mode` before SQLite writes to it, so it is never
/// readable with a wider mode. Callers serialize access to the connection.
pub fn open_writer(
    path: &Path,
    migrations: &[Migration],
    sharing: Sharing,
    mode: u32,
) -> Result<Connection, SqliteError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)?;
        fs::set_permissions(path, Permissions::from_mode(mode))?;
    }
    let db = Connection::open(path)?;
    db.busy_timeout(Duration::from_secs(5))?;
    db.pragma_update(None, "foreign_keys", "ON")?;
    let wanted = match sharing {
        Sharing::WithReaders => "delete",
        Sharing::Private => "wal",
    };
    let mode: String =
        db.pragma_update_and_check(None, "journal_mode", wanted, |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case(wanted) {
        return Err(SqliteError::JournalMode(mode));
    }
    db.pragma_update(None, "synchronous", "FULL")?;
    migrate(&db, migrations)?;
    Ok(db)
}

/// Open the writer of one service's database with the file mode and journal
/// its readers need.
pub fn open_database(
    path: &Path,
    migrations: &[Migration],
    database: Database,
) -> Result<Connection, SqliteError> {
    let sharing = if database.has_readers() {
        Sharing::WithReaders
    } else {
        Sharing::Private
    };
    open_writer(path, migrations, sharing, database.mode())
}

/// Apply the migrations after the stored `user_version`, each in its own
/// transaction; a database from a newer release is refused, not downgraded.
pub fn migrate(db: &Connection, migrations: &[Migration]) -> Result<(), SqliteError> {
    let stored: i64 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let current = usize::try_from(stored).map_err(|_| SqliteError::NewerSchema)?;
    if current > migrations.len() {
        return Err(SqliteError::NewerSchema);
    }
    for (version, statements) in (1_i64..).zip(migrations).skip(current) {
        db.execute_batch("BEGIN IMMEDIATE")?;
        let applied = statements
            .iter()
            .try_for_each(|statement| db.execute_batch(statement))
            .and_then(|()| db.pragma_update(None, "user_version", version))
            .and_then(|()| db.execute_batch("COMMIT"));
        if let Err(error) = applied {
            // The failed statement is the useful error, not a failing rollback.
            db.execute_batch("ROLLBACK").ok();
            return Err(error.into());
        }
    }
    Ok(())
}

/// A read-only snapshot that is released when dropped.
///
/// With the rollback journal an open read transaction blocks the writer's
/// commit, so readers must never keep one beyond a single request.
#[derive(Debug)]
pub struct Reader {
    db: Connection,
}

impl Deref for Reader {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.db
    }
}

/// How long a reader waits for the writer's lock each time it meets it.
const FOR_THE_WRITER: Duration = Duration::from_secs(2);
/// How long a reader whose request may go away sleeps between two tries
/// for the writer's lock, and so how soon it sees that it has gone.
const RETRY: Duration = Duration::from_millis(10);
/// At most one line in this long for the readers of one database that
/// waited out its writer.
const QUIET: Duration = Duration::from_secs(60);

/// When the journal last said that a reader waited out the writer of each
/// database, and how many more did since.
static WAITED: Mutex<BTreeMap<PathBuf, (Instant, u64)>> = Mutex::new(BTreeMap::new());
/// How long a reader waits for SQLite to open a database and begin its
/// snapshot: the writer's lock twice, as SQLite meets it reading the schema
/// and again beginning the snapshot, and a second for the disk.
const OPEN_WAIT: Duration = Duration::from_secs(5);
/// The databases, by their resolved path, of which a reader was left
/// waiting in SQLite's open: one such thread at the most for each, as a
/// further reader of one is refused at once until that open has ended.
static LEFT_WAITING: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

/// The line for a reader of `path` that waited out its writer at `now`,
/// where one is due: at once, and then at most once a minute for that
/// database, with how many more there were.
fn waited_line(
    said: &mut BTreeMap<PathBuf, (Instant, u64)>,
    path: &Path,
    now: Instant,
) -> Option<String> {
    let since = match said.get_mut(path) {
        Some((at, more)) if now.saturating_duration_since(*at) < QUIET => {
            *more += 1;
            return None;
        }
        Some((_, more)) => *more,
        None => 0,
    };
    said.insert(path.to_owned(), (now, 0));
    let more = if since == 0 {
        String::new()
    } else {
        format!("; {since} more since the last such line")
    };
    Some(format!(
        "A reader of {} waited {} s for its writer and gave up: the writer held the database \
         longer than a reader waits{more}",
        path.display(),
        FOR_THE_WRITER.as_secs()
    ))
}

/// Say that a reader of `path` waited out its writer: a writer that keeps
/// its database for good looks to each reader as one that commits slowly,
/// and the journal is where an operator finds it.
fn waited_out(path: &Path) {
    let line = waited_line(
        &mut WAITED.lock().unwrap_or_else(PoisonError::into_inner),
        path,
        Instant::now(),
    );
    if let Some(line) = line {
        log::warn!("{line}");
    }
}

/// Open a read-only snapshot whose queries stop after `budget`, or `None` when
/// the database does not exist yet.
///
/// The budget bounds expensive searches even when an authorized user sends a
/// pathological filter.
pub fn reading(path: &Path, budget: Duration) -> Result<Option<Reader>, SqliteError> {
    reading_until(path, budget, Arc::new(AtomicBool::new(false)))
}

/// [`reading`], whose queries also stop as soon as `gone` is set: a query
/// whose request has gone away need not run out its budget, nor wait for
/// the writer's commit. The file is opened as [`open_untrusted`] opens it.
pub fn reading_until(
    path: &Path,
    budget: Duration,
    gone: Arc<AtomicBool>,
) -> Result<Option<Reader>, SqliteError> {
    if fs::symlink_metadata(path).is_err() {
        return Ok(None);
    }
    let database = path.to_owned();
    bounded(path, move || begin_reading(&database, budget, gone)).map(Some)
}

/// The reader of [`reading_until`], its snapshot begun.
fn begin_reading(
    path: &Path,
    budget: Duration,
    gone: Arc<AtomicBool>,
) -> Result<Reader, SqliteError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mut db = connect_untrusted(path, flags)?;
    // While the writer commits, the reader waits for its lock as any other
    // does, tried again every few milliseconds, but not once its request
    // has gone: a wait for the lock checks no progress handler.
    let waiting = Arc::clone(&gone);
    let mut since = Instant::now();
    let database = path.to_owned();
    db.busy_handler(Some(move |tries: i32| {
        if tries == 0 {
            since = Instant::now();
        }
        if waiting.load(Ordering::Relaxed) {
            return false;
        }
        if since.elapsed() >= FOR_THE_WRITER {
            waited_out(&database);
            return false;
        }
        thread::sleep(RETRY);
        true
    }))?;
    // In exclusive locking mode SQLite reads a database in write-ahead mode
    // only under a lock that a read-only reader cannot take, so it never
    // opens a write-ahead log or its shared memory, which it opens holding a
    // lock of the whole process: a pipe there would hold every open of the
    // process. The reader keeps its shared lock until it is dropped, as its
    // snapshot does anyway. The snapshot begins with the read of the schema,
    // at which SQLite opens a journal there is by its name: within the
    // open's wait, and no later query of the reader opens anything.
    db.pragma_update_and_check(None, "locking_mode", "EXCLUSIVE", |_| Ok(()))?;
    db.execute_batch("BEGIN")?;
    harden(&db)?;
    db.pragma_update(None, "query_only", "ON")?;
    let deadline = Instant::now() + budget;
    db.progress_handler(
        10_000,
        Some(move || Instant::now() > deadline || gone.load(Ordering::Relaxed)),
    )?;
    Ok(Reader { db })
}

/// `open`, which opens the database at `path` that another user writes, on
/// a thread of its own, waited for no longer than [`OPEN_WAIT`]. SQLite
/// opens the database, its journal, and a write-ahead log and its shared
/// memory by their names and without `O_NONBLOCK`, so a named pipe that the
/// user who writes the folder puts in place of one of them, at any moment,
/// holds the open for good. Such an open is left to wait on its thread, and
/// the reader gets an error.
fn bounded<T: Send + 'static>(
    path: &Path,
    open: impl FnOnce() -> Result<T, SqliteError> + Send + 'static,
) -> Result<T, SqliteError> {
    let database = with_resolved_directory(path)?;
    let left = || LEFT_WAITING.lock().unwrap_or_else(PoisonError::into_inner);
    if left().contains(&database) {
        return Err(io::Error::other(format!(
            "an earlier reader of {} still waits for SQLite to open it, as where a named pipe \
             stands in its place or its journal's: take away what is no regular file there; it is \
             read again once that reader ends or the service starts again",
            database.display()
        ))
        .into());
    }
    let (sender, receiver) = mpsc::channel();
    let opening = database.clone();
    thread::Builder::new()
        .name("sqlite-open".to_owned())
        .spawn(move || {
            let opened = open();
            // The answer goes while the lock is held: a reader that gave up
            // on it marked the database first and listens no more.
            let mut waiting = left();
            if sender.send(opened).is_err() {
                waiting.remove(&opening);
            }
        })?;
    match receiver.recv_timeout(OPEN_WAIT) {
        Ok(opened) => opened,
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("SQLite's open ended without an answer").into())
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let mut waiting = left();
            if let Ok(opened) = receiver.try_recv() {
                return opened;
            }
            waiting.insert(database.clone());
            drop(receiver);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "SQLite did not open {} within {} s, as where a named pipe stands in its place \
                     or its journal's: take away what is no regular file there",
                    database.display(),
                    OPEN_WAIT.as_secs()
                ),
            )
            .into())
        }
    }
}

/// Whether a query failed because its reader's time budget ran out, or its
/// request went away. That is the size of the request, not a fault of the
/// database.
#[must_use]
pub fn out_of_time(error: &rusqlite::Error) -> bool {
    error.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted)
}

/// Whether a reader gave up waiting for the writer's lock: the writer held
/// its database for longer than a reader waits for it (SQLite's busy), as
/// while a large clean-up commits or on a slow disk, or the reader's
/// request went away meanwhile. That is the writer's moment, which passes,
/// not a fault of the database or of the request.
#[must_use]
pub fn held_by_the_writer(error: &rusqlite::Error) -> bool {
    error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy)
}

/// Open a database that another user writes: a service reading a file of
/// another service, or a root-run command reading any service's file.
///
/// The user who writes such a file can replace it. The file must not be a
/// symbolic link, triggers and views are switched off, and a file whose schema
/// holds anything but tables and indexes is refused before any table is read:
/// Garrison creates nothing else, and a virtual table would run SQLite's
/// C modules (full-text search, R-tree) on data that user chose. Loading the
/// schema parses it but runs no module.
///
/// SQLite's `NOFOLLOW` refuses a link anywhere in the path, so the directory is
/// resolved first: it is the operator's (a state directory may live on another
/// disk), while only the file itself is the writing user's to replace.
pub fn open_untrusted(path: &Path, flags: OpenFlags) -> Result<Connection, SqliteError> {
    let database = path.to_owned();
    bounded(path, move || {
        let db = connect_untrusted(&database, flags)?;
        db.busy_timeout(FOR_THE_WRITER)?;
        harden(&db)?;
        Ok(db)
    })
}

/// The connection [`open_untrusted`] begins with, before it waits for a
/// writer or reads anything.
fn connect_untrusted(path: &Path, flags: OpenFlags) -> Result<Connection, SqliteError> {
    let path = with_resolved_directory(path)?;
    regular(&path)?;
    Ok(Connection::open_with_flags(
        path,
        flags | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

/// Refuses a named pipe or other file that is no regular file at `path`,
/// whose open by SQLite, without `O_NONBLOCK`, could wait for ever. It looks
/// without opening: closing a descriptor of the file would drop every lock
/// this process holds on it, another reader's among them. A link, or what
/// cannot be looked at, is left to SQLite's own open to refuse or name. A
/// pipe swapped in after this look holds SQLite's open; [`bounded`] bounds
/// how long a reader waits for it.
fn regular(path: &Path) -> Result<(), SqliteError> {
    match fs::symlink_metadata(path) {
        Ok(found) if !found.is_file() && !found.file_type().is_symlink() => {
            Err(SqliteError::Io(io::Error::other("not a regular file")))
        }
        _ => Ok(()),
    }
}

/// `path` with its directory resolved to the real one; the file name is kept.
fn with_resolved_directory(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("a database path names a file"))?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok(fs::canonicalize(directory)?.join(name))
}

/// The settings and schema check of [`open_untrusted`], for a connection that
/// is already open, such as a copy of an untrusted database.
pub fn harden(db: &Connection) -> Result<(), SqliteError> {
    for (setting, on) in [
        (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
    ] {
        db.set_db_config(setting, on)?;
    }
    db.pragma_update(None, "cell_size_check", true)?;
    let mut statement = db.prepare("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")?;
    for sql in statement.query_map([], |row| row.get::<_, String>(0))? {
        if !matches!(
            created(&sql?).as_deref(),
            Some("TABLE" | "INDEX" | "UNIQUE")
        ) {
            return Err(SqliteError::ForeignSchema);
        }
    }
    Ok(())
}

/// The word after CREATE in a schema statement, read as SQLite's tokenizer
/// reads it: white space and comments may stand between the two.
fn created(sql: &str) -> Option<String> {
    let text = blanks_skipped(sql);
    let end = text
        .find(|character: char| !character.is_ascii_alphabetic())
        .unwrap_or(text.len());
    let (first, rest) = text.split_at(end);
    if !first.eq_ignore_ascii_case("CREATE") {
        return None;
    }
    let word: String = blanks_skipped(rest)
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect();
    Some(word.to_ascii_uppercase())
}

/// `text` after SQLite's white space (space, tab, LF, VT, FF, CR) and its
/// `--` and `/* */` comments.
fn blanks_skipped(mut text: &str) -> &str {
    loop {
        text = text.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
        if let Some(rest) = text.strip_prefix("--") {
            text = rest.split_once('\n').map_or("", |(_, after)| after);
        } else if let Some(rest) = text.strip_prefix("/*") {
            text = rest.split_once("*/").map_or("", |(_, after)| after);
        } else {
            return text;
        }
    }
}

#[cfg(test)]
mod reader_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wait_tests;
