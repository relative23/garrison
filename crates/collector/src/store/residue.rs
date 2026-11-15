//! What earlier releases kept of a key of Spamhaus' Data Query Service. A
//! zone of the service holds the subscriber's key in its name, and releases
//! before this one kept it there: in the reputation check's reading, in the
//! notifications' memory of a listing and in the snapshots. SQLite does not
//! overwrite what it frees, so a key that no row holds any more may stay in
//! a free page or in a page's free space until that is reused, and the
//! group garrison may read the status database.
//!
//! So the store masks the key in every row that holds one, under
//! `secure_delete`, and rebuilds the file with VACUUM, which leaves no free
//! space: once, in the first run of this release, where the file names the
//! service at all, and in any run that finds a key in a row, as after a
//! return to an earlier release and back. VACUUM writes the file in place,
//! so it keeps its inode, and with it its owner, mode and SELinux label.
//! The status database uses the rollback journal, which SQLite deletes at
//! the end of each commit: no write-ahead log holds a copy.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use garrison_core::sqlite::SqliteError;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

/// Where the store notes that this release looked at the file.
const LOOKED: &str = "store.dqs-keys-looked";
/// How every name of the service ends.
const SERVICE: &str = ".dq.spamhaus.net";

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

/// Clear the database of every copy of a key of the service, where it may
/// hold one; how many rows held one, where it cleared.
pub(super) fn clear(db: &mut Connection, path: &Path) -> Result<Option<usize>, SqliteError> {
    let looked = db
        .query_row("SELECT 1 FROM memory WHERE key = ?1", [LOOKED], |_| Ok(()))
        .optional()?
        .is_some();
    let memory = keyed(db, "memory", "key", "value")?;
    let snapshots = keyed(db, "snapshots", "id", "document")?;
    let rows = memory.len() + snapshots.len();
    if rows == 0 && (looked || !named_in_file(path)?) {
        if !looked {
            note(db)?;
        }
        return Ok(None);
    }
    // What the masking frees is overwritten with zeros; VACUUM then leaves
    // no free page at all.
    db.pragma_update(None, "secure_delete", true)?;
    let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
    db.execute_batch("VACUUM")?;
    db.pragma_update(None, "secure_delete", false)?;
    note(db)?;
    Ok(Some(rows))
}

/// Note that this release looked, so that a later run does not read the
/// whole file again.
fn note(db: &Connection) -> rusqlite::Result<()> {
    db.execute(
        "INSERT OR REPLACE INTO memory(key, value) VALUES(?1, '1')",
        [LOOKED],
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
        assert_eq!(clear(&mut db, &path).unwrap(), None);
        let looked: String = db
            .query_row("SELECT value FROM memory WHERE key = ?1", [LOOKED], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(looked, "1");
        assert_eq!(clear(&mut db, &path).unwrap(), None);
        db.execute(
            "INSERT INTO snapshots(collected_at, document) VALUES(1, ?1)",
            ["{\"zone\": \"abcdef.zen.dq.spamhaus.net\"}"],
        )
        .unwrap();
        assert_eq!(clear(&mut db, &path).unwrap(), Some(1));
        let document: String = db
            .query_row("SELECT document FROM snapshots", [], |row| row.get(0))
            .unwrap();
        assert_eq!(document, "{\"zone\": \"….zen.dq.spamhaus.net\"}");
    }
}
