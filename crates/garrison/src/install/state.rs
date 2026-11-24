//! Putting Garrison's state back as a backup holds it.
//!
//! `install --rollback --restore-state` puts back every database and the
//! policy. The switch back after a failed upgrade puts back only the
//! databases the new release had already changed, so that every other one
//! keeps what was recorded until the upgrade stopped the services.
//!
//! Whoever calls has stopped every writer first: a service that still runs
//! would write into a file that is no longer the database.

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use garrison_core::config::{Config, Database};
use garrison_core::version;
use rustix::fs::{Gid, Uid};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::files::{Step, announce, relabel, replace_in};
use super::requirements::{exact_room, size};
use super::states;
use crate::state::State;

/// What a backup says of itself in `backup.json`.
#[derive(Debug, Default, Deserialize)]
struct Manifest {
    /// The release that wrote it; a backup of a release that did not say
    /// has none.
    #[serde(default)]
    release: Option<String>,
    /// For each service's database, "copied" or "absent".
    #[serde(default)]
    databases: Map<String, Value>,
}

/// The backup's own account of itself; an empty one where it cannot be read.
fn manifest(source: &Path) -> Manifest {
    fs::read(source.join("backup.json"))
        .ok()
        .and_then(|text| serde_json::from_slice(&text).ok())
        .unwrap_or_default()
}

/// Whether the backup says that `database` did not exist when it was made.
fn absent_before(manifest: &Manifest, database: Database) -> bool {
    manifest.databases.get(database.writer()) == Some(&Value::from("absent"))
}

/// Why release `target` cannot take the state in `source`, if it cannot: a
/// release newer than `target` wrote it, and no release reads a database a
/// newer one has written. A backup that does not name its release passes.
pub(super) fn unsuited(source: &Path, target: &str) -> Option<State> {
    let written_by = manifest(source).release?;
    version::newer(&written_by, target)
        .unwrap_or(false)
        .then(|| states::state_newer(source, &written_by, target))
}

/// The databases a release's `self-check` report in `report` calls
/// unreadable, each with its schema version and its integrity as the release
/// gives them; its own words where the report cannot be read.
pub(super) fn unreadable(report: &[u8]) -> String {
    let parsed: Option<Value> = serde_json::from_slice(report).ok();
    let named: Option<Vec<String>> = parsed
        .as_ref()
        .and_then(|report| report["databases"].as_object())
        .map(|databases| {
            databases
                .iter()
                .filter(|(_, result)| result["ok"] == false)
                .map(|(name, result)| {
                    let version = match &result["schemaVersion"] {
                        Value::Null => "unknown".to_owned(),
                        version => version.to_string(),
                    };
                    let integrity = result["integrity"].as_str().unwrap_or("unknown");
                    format!("{name} (schema {version}, integrity {integrity})")
                })
                .collect()
        });
    match named {
        Some(named) if !named.is_empty() => named.join(", "),
        _ => String::from_utf8_lossy(report).trim().to_owned(),
    }
}

/// Remove the files SQLite keeps beside `database`: a WAL or journal of a
/// file that is replaced or removed must not survive it.
fn without_journals(folder: &Path, database: Database) {
    let journal = format!("{}-", database.file_name());
    for stale in fs::read_dir(folder).into_iter().flatten().flatten() {
        if stale.file_name().to_string_lossy().starts_with(&journal) {
            let _ = fs::remove_file(stale.path());
        }
    }
}

/// Put the backup's copy of `database` in the place of the live file.
fn put_back(config: &Config, database: Database, copy: &Path) -> Step {
    let destination = config.database(database);
    let Some(folder) = destination.parent() else {
        return Ok(());
    };
    without_journals(folder, database);
    // The service user owns this directory: replace the file without
    // following anything planted there, and keep the directory's owner.
    replace_in(folder, database.file_name(), copy, database.mode(), None)?;
    relabel(std::slice::from_ref(&destination));
    Ok(())
}

/// Remove a database that did not exist when the backup was made. The
/// release that wrote the backup makes its own when it starts; one a newer
/// release made in between it could not read. Unlinking follows no link.
fn take_away(config: &Config, database: Database) -> Step {
    let destination = config.database(database);
    if fs::symlink_metadata(&destination).is_err() {
        return Ok(());
    }
    if let Some(folder) = destination.parent() {
        without_journals(folder, database);
    }
    fs::remove_file(&destination).map_err(|error| states::io(destination.display(), error))
}

fn copy_of(source: &Path, database: Database) -> std::path::PathBuf {
    source.join(database.writer()).join(database.file_name())
}

/// Who owns the access policy, as the installer leaves it: root, with the
/// broker's group, which alone reads it. Asked before anything stops.
pub(super) fn policy_owner() -> Step<(Uid, Gid)> {
    let group = crate::access::group_id("garrison-broker").ok_or_else(states::no_broker_group)?;
    Ok((Uid::ROOT, Gid::from_raw(group)))
}

/// Put back every database and the policy as `source` holds them, the
/// policy owned by `owner`, and remove the databases it says did not exist.
/// What went back and what was removed is in `restored`, also where a later
/// one failed.
pub(super) fn restore_all(
    source: &Path,
    config: &Config,
    owner: (Uid, Gid),
    restored: &mut Returned,
) -> Step {
    announce(&format!(
        "Restoring Garrison state from {}",
        source.display()
    ));
    let manifest = manifest(source);
    for database in Database::ALL {
        let copy = copy_of(source, database);
        if copy.exists() {
            put_back(config, database, &copy)?;
            restored.back.push(database.writer());
        } else if absent_before(&manifest, database) {
            take_away(config, database)?;
            restored.removed.push(database.writer());
        }
    }
    let policy = source.join(crate::ops::POLICY_COPY);
    if policy.exists() {
        put_policy_back(&policy, &config.broker.policy, owner)?;
        restored.back.push("the access policy");
    }
    Ok(())
}

/// The access policy as the broker reads it: a file of its own, made new
/// with `owner`, root and the broker's group, mode 0640, and renamed into
/// place. A link or a folder that `broker.policy` names stays as it is,
/// and so does what a link points to; a policy kept outside /etc/garrison
/// may lie in a folder that others can write.
fn put_policy_back(copy: &Path, target: &Path, owner: (Uid, Gid)) -> Step {
    if fs::symlink_metadata(target).is_ok_and(|kind| !kind.is_file()) {
        return Err(states::policy_left(target));
    }
    let (Some(folder), Some(name)) = (target.parent(), target.file_name().and_then(OsStr::to_str))
    else {
        return Err(states::policy_nameless(target));
    };
    // The broker reaches the file through the folders' links, as here.
    let folder =
        fs::canonicalize(folder).map_err(|error| states::policy_unreachable(target, error))?;
    replace_in(&folder, name, copy, 0o640, Some(owner))?;
    relabel(&[target.to_owned()]);
    Ok(())
}

/// What a switch back did: the services whose database went back to its
/// copy, and those whose database was removed, as it did not exist then.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Returned {
    pub(super) back: Vec<&'static str>,
    pub(super) removed: Vec<&'static str>,
}

impl Returned {
    /// What went back from `source`; none where nothing changed.
    pub(super) fn said(&self, source: &Path) -> Option<State> {
        states::went_back(source, &self.back, &self.removed)
    }
}

/// Put back only the databases whose schema has risen since `source` was
/// made, and remove one that was made since: what a new release changed
/// before its start failed, and the release that ran cannot read. Every
/// other database keeps its data. Every copy must fit beside the database
/// it replaces before any goes back. What was done is in `returned`, also
/// where a later step failed.
pub(super) fn restore_migrated(source: &Path, config: &Config, returned: &mut Returned) -> Step {
    let manifest = manifest(source);
    let (mut back, mut gone) = (Vec::new(), Vec::new());
    for database in Database::ALL {
        let copy = copy_of(source, database);
        let live = crate::ops::stored_version(&config.database(database));
        match crate::ops::stored_version(&copy) {
            // Also a live file that can no longer be read as a database.
            Some(before) if live.is_none_or(|now| now > before) => back.push(database),
            None if absent_before(&manifest, database) && live.is_some() => gone.push(database),
            // As it was before, or never copied: it keeps its data.
            Some(_) | None => {}
        }
    }
    let folders: Vec<(std::path::PathBuf, u64)> = back
        .iter()
        .filter_map(|database| {
            let folder = config.database(*database).parent()?.to_owned();
            Some((folder, size(&copy_of(source, *database))))
        })
        .collect();
    let needs: Vec<(&Path, u64)> = folders
        .iter()
        .map(|(folder, bytes)| (folder.as_path(), *bytes))
        .collect();
    exact_room(&needs)?;
    for database in back {
        put_back(config, database, &copy_of(source, database))?;
        returned.back.push(database.writer());
    }
    for database in gone {
        take_away(config, database)?;
        returned.removed.push(database.writer());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
