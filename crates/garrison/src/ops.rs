//! `garrison backup` and `self-check`: consistent copies and verification.
//!
//! `backup` uses SQLite's online backup API, so services keep running and every
//! copy is a consistent snapshot. Run it as root right before the host backup
//! job takes its snapshot. Credentials are never copied: they are recreated with
//! `stalwart setup` or restored from the host's protected secret backup, and
//! active sessions (which contain access tokens) are removed from the copy.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use garrison_core::config::{Config, Database};
use garrison_core::files::atomic_write;
use garrison_core::sqlite::{self, SqliteError};
use garrison_core::time;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Map, Value, json};

use crate::say;

/// The access policy's name inside a backup, whatever its configured name.
pub(crate) const POLICY_COPY: &str = "access-policy.json";

/// The schema version this release writes for `database`.
pub(crate) fn schema_version(database: Database) -> usize {
    match database {
        Database::Web => garrison_web::store::SCHEMA_VERSION,
        Database::Events => garrison_ingest::store::SCHEMA_VERSION,
        Database::Status => garrison_collector::store::SCHEMA_VERSION,
        Database::Jobs => garrison_broker::store::SCHEMA_VERSION,
    }
}

fn private_directory(path: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| error.to_string())
}

fn copy(database: Database, source: &Path, destination: &Path) -> Result<(), String> {
    let failed = |error: &dyn std::fmt::Display| format!("{}: {error}", database.writer());
    let partial = destination.with_extension("partial");
    let _ = fs::remove_file(&partial);
    // Root reads a file that a service user writes and may have replaced.
    let reader = sqlite::open_untrusted(source, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| failed(&error))?;
    let mut writer = Connection::open(&partial).map_err(|error| failed(&error))?;
    rusqlite::backup::Backup::new(&reader, &mut writer)
        .map_err(|error| failed(&error))?
        .run_to_completion(256, Duration::from_millis(10), None)
        .map_err(|error| failed(&error))?;
    if database == Database::Web {
        // Sessions hold access tokens; a backup must not contain them. The copy
        // has the source's schema, so it gets the same settings first.
        sqlite::harden(&writer).map_err(|error| failed(&error))?;
        writer
            .execute_batch("DELETE FROM sessions; VACUUM;")
            .map_err(|error| failed(&error))?;
    }
    drop(writer);
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    fs::rename(&partial, destination).map_err(|error| error.to_string())
}

pub(crate) fn backup(config: &Config, target: &Path) -> u8 {
    match write_backup(config, target) {
        Ok(()) => 0,
        Err(error) => {
            crate::complain(&error);
            1
        }
    }
}

fn write_backup(config: &Config, target: &Path) -> Result<(), String> {
    private_directory(target)?;
    let mut databases = Map::new();
    for database in Database::ALL {
        let (name, source) = (database.writer(), config.database(database));
        // A link here is not absent: `copy` refuses it.
        if fs::symlink_metadata(&source).is_err() {
            databases.insert(name.into(), json!("absent"));
            continue;
        }
        let folder = target.join(name);
        private_directory(&folder)?;
        copy(database, &source, &folder.join(database.file_name()))?;
        databases.insert(name.into(), json!("copied"));
    }
    let policy = &config.broker.policy;
    if policy.is_file() {
        let copied = target.join(POLICY_COPY);
        fs::copy(policy, &copied).map_err(|error| error.to_string())?;
        fs::set_permissions(&copied, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    let report = json!({"createdAt": time::now_isoformat(), "databases": databases});
    let text = serde_json::to_string_pretty(&report).unwrap_or_default();
    atomic_write(&target.join("backup.json"), text.as_bytes(), 0o600)
        .map_err(|error| error.to_string())?;
    for (name, state) in &databases {
        say(&format!("- {name}: {}", state.as_str().unwrap_or_default()));
    }
    say(&format!("Backup written to {}", target.display()));
    Ok(())
}

/// The schema version stored in the database at `path`; `None` when no
/// database can be read there.
pub(crate) fn stored_version(path: &Path) -> Option<i64> {
    // Root reads a file that a service user wrote.
    let db = sqlite::open_untrusted(path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    db.query_row("PRAGMA user_version", [], |row| row.get(0))
        .ok()
}

/// Integrity, schema version and row counts; damage is a result, not a crash.
fn check_database(path: &Path, known: usize) -> Value {
    let inspect = || -> Result<(String, i64, Map<String, Value>), SqliteError> {
        // Every table is counted below, so a file with anything but tables and
        // indexes must be refused before: root runs this on service users' files.
        let db = sqlite::open_untrusted(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let integrity: String = db.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let mut statement = db.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
        let tables: Vec<String> = statement
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut counts = Map::new();
        for table in tables {
            let quoted = table.replace('"', "\"\"");
            let count: i64 =
                db.query_row(&format!("SELECT count(*) FROM \"{quoted}\""), [], |row| {
                    row.get(0)
                })?;
            counts.insert(table, json!(count));
        }
        Ok((integrity, version, counts))
    };
    match inspect() {
        Ok((integrity, version, rows)) => {
            let readable =
                usize::try_from(version).is_ok_and(|version| (1..=known).contains(&version));
            json!({
                "ok": integrity == "ok" && readable,
                "integrity": integrity,
                "schemaVersion": version,
                "rows": rows,
            })
        }
        Err(error) => json!({
            "ok": false,
            "integrity": format!("unreadable ({error})"),
            "schemaVersion": null,
            "rows": {},
        }),
    }
}

/// Check live state, or a restored copy written by `backup` (`--state DIR`).
pub(crate) fn self_check(config: &Config, state: Option<&Path>, receipt: Option<&Path>) -> u8 {
    let mut results = Map::new();
    for database in Database::ALL {
        let path = match state {
            Some(state) => state.join(database.writer()).join(database.file_name()),
            None => config.database(database),
        };
        let result = if fs::symlink_metadata(&path).is_ok() {
            check_database(&path, schema_version(database))
        } else {
            json!({"ok": null, "absent": true})
        };
        results.insert(database.writer().into(), result);
    }
    let failed: Vec<&str> = results
        .iter()
        .filter(|(_, result)| result["ok"] == false)
        .map(|(name, _)| name.as_str())
        .collect();
    let message = if failed.is_empty() {
        "All present databases are intact.".to_owned()
    } else {
        format!("Problems in: {}", failed.join(", "))
    };
    let report = json!({
        "date": time::now_isoformat(),
        "result": if failed.is_empty() { "passed" } else { "failed" },
        "databases": results,
        "message": message,
    });
    let text = serde_json::to_string_pretty(&report).unwrap_or_default();
    if let Some(receipt) = receipt
        && let Err(error) = atomic_write(receipt, text.as_bytes(), 0o644)
    {
        crate::complain(&format!("Cannot write {}: {error}", receipt.display()));
        return 1;
    }
    say(&text);
    u8::from(!failed.is_empty())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn database(path: &Path, schema: &str) {
        Connection::open(path)
            .unwrap()
            .execute_batch(schema)
            .unwrap();
    }

    #[test]
    fn backup_and_self_check_work_through_a_linked_state_directory() {
        // The operator moved all state to another disk and linked it back.
        let directory = tempfile::tempdir().unwrap();
        let disk = directory.path().join("disk");
        fs::create_dir(&disk).unwrap();
        let state = directory.path().join("state");
        symlink(&disk, &state).unwrap();
        let config = garrison_testing::config(&state, "http://127.0.0.1:9");
        let events = config.database(Database::Events);
        fs::create_dir_all(events.parent().unwrap()).unwrap();
        database(&events, "CREATE TABLE events(a); PRAGMA user_version = 1;");
        let target = directory.path().join("backup");
        write_backup(&config, &target).unwrap();
        let copy = target
            .join(Database::Events.writer())
            .join(Database::Events.file_name());
        assert_eq!(check_database(&copy, 9)["ok"], true);
        assert_eq!(self_check(&config, None, None), 0);
    }

    #[test]
    fn root_reads_no_linked_or_foreign_database() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let plain = root.join("plain.sqlite");
        database(
            &plain,
            "CREATE TABLE events(a); INSERT INTO events VALUES (1); PRAGMA user_version = 1;",
        );
        copy(Database::Events, &plain, &root.join("copy.sqlite")).unwrap();
        assert_eq!(check_database(&root.join("copy.sqlite"), 9)["ok"], true);

        // A service user replaced its file with a link to another database.
        let link = root.join("link.sqlite");
        symlink(&plain, &link).unwrap();
        assert!(copy(Database::Events, &link, &root.join("linked.sqlite")).is_err());
        assert_eq!(check_database(&link, 9)["ok"], false);

        // Or with a file that would run SQLite's full-text module.
        let foreign = root.join("foreign.sqlite");
        database(
            &foreign,
            "CREATE TABLE events(a); CREATE VIRTUAL TABLE f USING fts3(b);",
        );
        let refused = copy(
            Database::Events,
            &foreign,
            &root.join("foreign-copy.sqlite"),
        );
        assert!(refused.unwrap_err().contains("never creates"));
        let checked = check_database(&foreign, 9);
        assert_eq!(checked["ok"], false);
        assert!(
            checked["integrity"]
                .as_str()
                .unwrap()
                .contains("never creates")
        );
        assert_eq!(checked["rows"], json!({}));
    }
}
