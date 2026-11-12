//! SQLite connections and ordered schema migrations.
//!
//! Each database has exactly one writing component. Databases that another
//! service user reads use the rollback journal instead of WAL: a read-only WAL
//! reader would need write access to the shared-memory file, which would weaken
//! the boundary.

use std::fs::{self, OpenOptions, Permissions};
use std::ops::Deref;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
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
    Io(#[from] std::io::Error),
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

/// Open a read-only snapshot whose queries stop after `budget`, or `None` when
/// the database does not exist yet.
///
/// The budget bounds expensive searches even when an authorized user sends a
/// pathological filter.
pub fn reading(path: &Path, budget: Duration) -> Result<Option<Reader>, SqliteError> {
    if fs::symlink_metadata(path).is_err() {
        return Ok(None);
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mut db = open_untrusted(path, flags)?;
    db.pragma_update(None, "query_only", "ON")?;
    let deadline = Instant::now() + budget;
    db.progress_handler(10_000, Some(move || Instant::now() > deadline))?;
    db.execute_batch("BEGIN")?;
    Ok(Some(Reader { db }))
}

/// Whether a query failed because its reader's time budget ran out. That is
/// the size of the request, not a fault of the database.
#[must_use]
pub fn out_of_time(error: &rusqlite::Error) -> bool {
    error.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted)
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
    let path = with_resolved_directory(path)?;
    let db = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)?;
    db.busy_timeout(Duration::from_secs(2))?;
    harden(&db)?;
    Ok(db)
}

/// `path` with its directory resolved to the real one; the file name is kept.
fn with_resolved_directory(path: &Path) -> std::io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("a database path names a file"))?;
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
mod tests;
