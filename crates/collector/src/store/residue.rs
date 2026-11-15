//! What earlier releases kept of a key of Spamhaus' Data Query Service. A
//! zone of the service holds the subscriber's key in its name, and releases
//! before this one kept it there: in the reputation check's reading, in the
//! notifications' memory of a listing and in the snapshots. SQLite does not
//! overwrite what it frees, so a key that no row holds any more may stay in
//! a free page or in a page's free space until that is reused, and the
//! group garrison may read the status database.
//!
//! So the store rebuilds the file without it: once, in the first run of this
//! release, where the file names the service at all, and in any run that
//! finds a key in a row, as after a return to an earlier release and back.
//! The rows are masked in place under `secure_delete`, a short write; then
//! VACUUM INTO writes a copy beside the database, which leaves no free space
//! and holds only a reader's lock on it, so the web service reads on, and
//! the copy takes the database's place (replace.rs). A VACUUM in place held
//! every reader off for as long as it wrote: some 20 seconds for 90 days of
//! history on a disk that writes 2 MB a second, where a reader gives up
//! after two. The status database uses the rollback journal, which SQLite
//! deletes at the end of each commit: no write-ahead log holds a copy.
//!
//! A rebuild is a run's last step, once its snapshot is stored, and may take
//! until eight minutes after the run began (run.rs), asking systemd for more
//! time while it runs (store.rs). One that does not finish by then, or that
//! is ended, is tried again a day later, since on a disk too slow for its
//! history it would write the disk in every run. One that fails, as on a
//! full disk, is tried again in the next run.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use garrison_core::sqlite::{self, SqliteError};
use rusqlite::{Connection, OptionalExtension, params};

use super::replace;

/// Where the store notes that this release looked at the file.
const LOOKED: &str = "store.dqs-keys-looked";
/// When a rebuild began that has not finished, a Unix second.
const BEGAN: &str = "store.dqs-keys-rebuild-began";
/// How long after such a rebuild the next one waits.
const AGAIN_AFTER: i64 = 86_400;
/// How every name of the service ends.
const SERVICE: &str = ".dq.spamhaus.net";

/// Why a rebuild did not finish: the time it had was up, or it failed.
#[derive(Debug, thiserror::Error)]
pub(super) enum Unfinished {
    #[error("the time the run left was up")]
    Late,
    #[error("{0}")]
    Failed(#[from] SqliteError),
}

impl From<rusqlite::Error> for Unfinished {
    fn from(error: rusqlite::Error) -> Self {
        Unfinished::Failed(error.into())
    }
}

impl From<std::io::Error> for Unfinished {
    fn from(error: std::io::Error) -> Self {
        Unfinished::Failed(error.into())
    }
}

/// `text` with the key of every name of the service left out, as the cards
/// name a zone with its key: `….zen.dq.spamhaus.net`, also where an error
/// repeated a question, `5.113.0.203.….zen.dq.spamhaus.net`.
pub(super) fn masked(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(SERVICE) {
        let (before, after) = rest.split_at(at);
        out.push_str(&without_key(before));
        out.push_str(SERVICE);
        rest = &after[SERVICE.len()..];
    }
    out.push_str(rest);
    out
}

/// `before`, which a name of the service goes on from, with the label before
/// the list's own left out: that is the key. Labels are ASCII, so the byte
/// after the last one that is no label's always begins a character.
fn without_key(before: &str) -> String {
    let label = |byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'-';
    let bytes = before.as_bytes();
    let list = bytes
        .iter()
        .rposition(|byte| !label(byte))
        .map_or(0, |at| at + 1);
    let Some(dot) = list.checked_sub(1).filter(|dot| bytes[*dot] == b'.') else {
        return before.to_owned();
    };
    let key = bytes[..dot]
        .iter()
        .rposition(|byte| !label(byte))
        .map_or(0, |at| at + 1);
    if key == dot {
        return before.to_owned();
    }
    format!("{}…{}", &before[..key], &before[dot..])
}

/// Whether the file at `path` names the service anywhere: in a row, a free
/// page or a page's free space.
fn named_in_file(path: &Path) -> std::io::Result<bool> {
    let wanted = SERVICE.as_bytes();
    let mut file = File::open(path)?;
    let mut chunk = vec![0; 1 << 20];
    // The end of the chunk before, where a name may begin.
    let mut held: Vec<u8> = Vec::new();
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            return Ok(false);
        }
        held.extend_from_slice(&chunk[..read]);
        if held
            .windows(wanted.len())
            .any(|window| window[0] == b'.' && window == wanted)
        {
            return Ok(true);
        }
        let start = held.len().saturating_sub(wanted.len() - 1);
        held.drain(..start);
    }
}

/// The rows of `table` whose `text` holds a key, each with its masked text.
fn keyed(
    db: &Connection,
    table: &str,
    id: &str,
    text: &str,
) -> rusqlite::Result<Vec<(String, String)>> {
    let mut statement = db.prepare(&format!(
        "SELECT CAST({id} AS TEXT), {text} FROM {table} WHERE {text} LIKE ?1"
    ))?;
    let rows = statement.query_map([format!("%{SERVICE}%")], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut found = Vec::new();
    for row in rows {
        let (id, text) = row?;
        let masked = masked(&text);
        if masked != text {
            found.push((id, masked));
        }
    }
    Ok(found)
}

/// Whether the database `db` holds open, at `path`, may hold a key of the
/// service, and is to be rebuilt now: not within a day of a rebuild that did
/// not finish. `now` is the run's time.
pub(super) fn due(db: &Connection, path: &Path, now: i64) -> Result<bool, SqliteError> {
    let recalled = |key: &str| {
        db.query_row("SELECT value FROM memory WHERE key = ?1", [key], |row| {
            row.get::<_, String>(0)
        })
        .optional()
    };
    let looked = recalled(LOOKED)?.is_some();
    // A rebuild dated ahead of the clock, as after the clock went back, is
    // no reason to wait.
    let waiting = recalled(BEGAN)?
        .and_then(|began| began.parse::<i64>().ok())
        .is_some_and(|began| (0..AGAIN_AFTER).contains(&now.saturating_sub(began)));
    let keyed = !keyed(db, "memory", "key", "value")?.is_empty()
        || !keyed(db, "snapshots", "id", "document")?.is_empty();
    if !keyed && (looked || !named_in_file(path)?) {
        if !looked {
            note(db, LOOKED, "1")?;
        }
        return Ok(false);
    }
    Ok(!waiting)
}

/// Rebuild the database `db` holds open, at `path`, without any copy of a
/// key of the service, by `until`; how many rows held one. `now` is the
/// run's time. The file at `path` is then another one than `db`'s.
pub(super) fn clear(
    db: &mut Connection,
    path: &Path,
    now: i64,
    until: Instant,
) -> Result<usize, Unfinished> {
    note(db, BEGAN, &now.to_string())?;
    let copy = replace::copy_of(path);
    let rebuilt = rebuilt(db, path, &copy, until);
    if rebuilt.is_err() {
        // No copy of the key stays behind, whatever ended the rebuild.
        replace::remove(&copy);
    }
    if let Err(Unfinished::Failed(_)) = rebuilt {
        // A failure, as on a full disk, is tried again in the next run.
        let _ = db.execute("DELETE FROM memory WHERE key = ?1", [BEGAN]);
    }
    rebuilt
}

/// The copy at `copy` of the database `db` holds open, without a key in a
/// row or in free space, in its place at `path`; how many rows held one.
fn rebuilt(
    db: &mut Connection,
    path: &Path,
    copy: &Path,
    until: Instant,
) -> Result<usize, Unfinished> {
    let rows = masked_rows(db)?;
    // What a run that was ended left.
    replace::remove(copy);
    replace::made_like(path, copy)?;
    // A configured path is text, as garrison.toml is.
    let name = copy
        .to_str()
        .ok_or_else(|| std::io::Error::other("the status database's path is no text"))?;
    db.progress_handler(1000, Some(move || Instant::now() >= until))?;
    let vacuumed = db.execute("VACUUM INTO ?1", [name]);
    db.progress_handler(0, None::<fn() -> bool>)?;
    match vacuumed {
        Err(error) if sqlite::out_of_time(&error) => return Err(Unfinished::Late),
        vacuumed => vacuumed?,
    };
    // Only the copy says that the rebuild is done: until it is in place, the
    // database is one to rebuild.
    let copied = Connection::open(copy)?;
    copied.execute("DELETE FROM memory WHERE key = ?1", [BEGAN])?;
    note(&copied, LOOKED, "1")?;
    drop(copied);
    replace::put_in_place(copy, path)?;
    Ok(rows)
}

/// Mask the key in every row of the database `db` holds open that holds one,
/// as the copy is to have them; how many did. VACUUM INTO writes the copy
/// without zeroing what it moves, so the rows it copies must hold no key:
/// masked afterwards, the copy's own pages would keep it. The masking holds
/// readers off only while it writes these rows.
fn masked_rows(db: &mut Connection) -> Result<usize, Unfinished> {
    let memory = keyed(db, "memory", "key", "value")?;
    let snapshots = keyed(db, "snapshots", "id", "document")?;
    // What the masking frees is overwritten with zeros.
    db.pragma_update(None, "secure_delete", true)?;
    let transaction = db.transaction()?;
    for (key, value) in &memory {
        transaction.execute(
            "UPDATE memory SET value = ?1 WHERE key = ?2",
            params![value, key],
        )?;
    }
    for (id, document) in &snapshots {
        transaction.execute(
            "UPDATE snapshots SET document = ?1 WHERE id = CAST(?2 AS INTEGER)",
            params![document, id],
        )?;
    }
    transaction.commit()?;
    db.pragma_update(None, "secure_delete", false)?;
    Ok(memory.len() + snapshots.len())
}

/// Note `value` under `key` in the store's memory: that this release looked,
/// so that a later run does not read the whole file again, or when a rebuild
/// began.
fn note(db: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    db.execute(
        "INSERT OR REPLACE INTO memory(key, value) VALUES(?1, ?2)",
        params![key, value],
    )
    .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_key_of_a_name_of_the_service_is_left_out() {
        for (text, expected) in [
            ("abcdef.zen.dq.spamhaus.net", "….zen.dq.spamhaus.net"),
            (
                "listed on abcdef.sbl-xbl.dq.spamhaus.net (127.0.0.2).",
                "listed on ….sbl-xbl.dq.spamhaus.net (127.0.0.2).",
            ),
            (
                "5.113.0.203.abcdef.zen.dq.spamhaus.net is no DNS name",
                "5.113.0.203.….zen.dq.spamhaus.net is no DNS name",
            ),
            (
                "[\"k1.zen.dq.spamhaus.net\", \"k2.dbl.dq.spamhaus.net\"]",
                "[\"….zen.dq.spamhaus.net\", \"….dbl.dq.spamhaus.net\"]",
            ),
            // Masked already, or without a key: as it is.
            ("….zen.dq.spamhaus.net", "….zen.dq.spamhaus.net"),
            ("\"zen.dq.spamhaus.net\"", "\"zen.dq.spamhaus.net\""),
            ("zen.dq.spamhaus.net", "zen.dq.spamhaus.net"),
            ("zen.spamhaus.org", "zen.spamhaus.org"),
            ("é.zen.dq.spamhaus.net", "é.zen.dq.spamhaus.net"),
        ] {
            assert_eq!(masked(text), expected, "{text}");
        }
    }

    /// A database that never named the service is looked at once and left
    /// as it is; one that holds a key in a row again, as after a return to
    /// an earlier release, is cleared again.
    #[test]
    fn the_file_is_read_once_and_a_key_in_a_row_is_cleared_in_any_run() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status.sqlite");
        let mut db = Connection::open(&path).unwrap();
        db.execute_batch(
            "CREATE TABLE memory(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE snapshots(id INTEGER PRIMARY KEY, collected_at INTEGER, document TEXT)",
        )
        .unwrap();
        assert!(!due(&db, &path, 0).unwrap());
        let looked: String = db
            .query_row("SELECT value FROM memory WHERE key = ?1", [LOOKED], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(looked, "1");
        assert!(!due(&db, &path, 0).unwrap());
        db.execute(
            "INSERT INTO snapshots(collected_at, document) VALUES(1, ?1)",
            ["{\"zone\": \"abcdef.zen.dq.spamhaus.net\"}"],
        )
        .unwrap();
        assert!(due(&db, &path, 0).unwrap());
        let until = Instant::now() + std::time::Duration::from_secs(60);
        assert_eq!(clear(&mut db, &path, 0, until).unwrap(), 1);
        // The file at the path is the copy now.
        let db = Connection::open(&path).unwrap();
        let document: String = db
            .query_row("SELECT document FROM snapshots", [], |row| row.get(0))
            .unwrap();
        assert_eq!(document, "{\"zone\": \"….zen.dq.spamhaus.net\"}");
        assert!(!due(&db, &path, 0).unwrap());
    }
}
