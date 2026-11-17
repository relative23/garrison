//! `garrison install --rollback [--restore-state]`: back to the previous
//! release, with the state from before the upgrade if asked.
//!
//! Every check comes before the services stop. Once they have stopped, any
//! failure returns to the release that ran and starts it again.

use std::fs;
use std::path::{Path, PathBuf};

use garrison_core::config::{self, Database};
use rustix::fs::{Gid, Uid};

use super::files::{Step, announce, io, lock, switch};
use super::system::install_system_files;
use super::{
    BACKUPS, BASE, CONFIG, LAST, LOCK, cli, precheck, preflight, start, state, stop_services,
};

/// Whether this release will raise the schema of a database whose copy from
/// before the upgrade is in `backup`. The release that ran before cannot read
/// such a database, so only `--restore-state` takes the state back with it.
pub(super) fn schema_rises(backup: &Path) -> bool {
    Database::ALL.into_iter().any(|database| {
        let copy = backup.join(database.writer()).join(database.file_name());
        crate::ops::stored_version(&copy).is_some_and(|stored| {
            usize::try_from(stored)
                .is_ok_and(|stored| stored < crate::ops::schema_version(database))
        })
    })
}

/// The backup `--restore-state` returns to, found before anything stops. It
/// must suit the release `name` that will read it.
fn restore_source(name: &str) -> Step<PathBuf> {
    let last = Path::new(BACKUPS).join(LAST);
    let source = match fs::canonicalize(&last) {
        Ok(source) if source.is_dir() => source,
        _ => {
            return Err(format!(
                "There is no state from before an upgrade to restore ({}); nothing was changed.",
                last.display()
            ));
        }
    };
    match state::unsuited(&source, name) {
        Some(reason) => Err(format!("{reason} Nothing was changed.")),
        None => Ok(source),
    }
}

/// Before anything stops: the access policy that the state in `source`
/// brings, where it brings one, goes where the broker reads it and suits
/// today's configuration as `target` reads it, and every copy fits beside
/// the database it replaces. Returns the policy's owner.
fn state_fits(target: &Path, source: &Path, comes_back: bool) -> Step<(Uid, Gid)> {
    let refused = |reason: String| format!("{reason} Nothing was changed.");
    let owner = state::policy_owner().map_err(refused)?;
    let settings = Path::new(CONFIG).join("garrison.toml");
    let config = config::load(&settings)
        .map_err(|error| refused(format!("Cannot load {}: {error}.", settings.display())))?;
    if comes_back {
        precheck::policy_place(&config).map_err(refused)?;
        if let Err(said) = precheck::policy_comes_back(target, source)? {
            return Err(format!(
                "The access policy from before the upgrade, in {}, does not suit {}, as {}'s \
                 check-config says:\n{said}\nNothing was changed.",
                source.display(),
                settings.display(),
                target.file_name().unwrap_or_default().to_string_lossy()
            ));
        }
    }
    precheck::copies_fit(source, &config, &[])?;
    Ok(owner)
}

/// Put the pre-upgrade copies of the databases and the policy back, the
/// policy owned by `owner`; what went back is in `restored`.
fn restore_state(source: &Path, owner: (Uid, Gid), restored: &mut Vec<&'static str>) -> Step {
    // The configured state directories, which need not be the defaults.
    let settings = Path::new(CONFIG).join("garrison.toml");
    let config = config::load(&settings)
        .map_err(|error| format!("Cannot load {}: {error}", settings.display()))?;
    state::restore_all(source, &config, owner, restored)
}

/// Make `target` current and `current` previous, then start `target`.
fn roll_back_to(
    target: &Path,
    current: &Path,
    source: Option<(&Path, (Uid, Gid))>,
    restored: &mut Vec<&'static str>,
) -> Step {
    if let Some((source, owner)) = source {
        restore_state(source, owner, restored)?;
    }
    let base = Path::new(BASE);
    switch(&base.join("current"), target)?;
    switch(&base.join("previous"), current)?;
    install_system_files(target)?;
    start(target)
}

pub(super) fn rollback(with_state: bool) -> Step {
    preflight()?;
    let _held = lock(Path::new(LOCK))?;
    let base = Path::new(BASE);
    let previous = base.join("previous");
    let Ok(target) = fs::canonicalize(&previous) else {
        return Err("There is no previous release to return to.".into());
    };
    let current = io(
        fs::canonicalize(base.join("current")),
        &base.join("current"),
    )?;
    let name = target.file_name().unwrap_or_default().to_string_lossy();
    let source = if with_state {
        Some(restore_source(&name)?)
    } else {
        None
    };
    // The previous release must load today's configuration: a setting added
    // since, such as `modules`, would keep it from starting, and neither
    // --restore-state nor its self-check would notice before the switch.
    // Where the state brings its access policy, that one is judged instead.
    let comes_back = source.as_deref().is_some_and(precheck::brings_policy);
    if let Err(said) = precheck::configuration(&target, comes_back)? {
        return Err(format!(
            "{name} cannot load {CONFIG}/garrison.toml:\n{said}\n\
             Remove the settings {name} does not know, or put back the file from \
             before the upgrade ({BACKUPS}/{LAST}/etc/garrison.toml), then roll back."
        ));
    }
    // After a schema change only the pre-upgrade copies suit the previous
    // release, and only its own self-check knows which schemas it reads.
    if !with_state && !cli(&target, &["self-check"])?.status.success() {
        return Err(format!(
            "{name} cannot read the current data, probably because a database schema changed. \
             Roll back with --restore-state to return to the data from before the upgrade."
        ));
    }
    let source = match source {
        Some(source) => Some((source.clone(), state_fits(&target, &source, comes_back)?)),
        None => None,
    };
    stop_services();
    let restoring = source
        .as_ref()
        .map(|(source, owner)| (source.as_path(), *owner));
    let mut restored = Vec::new();
    if let Err(error) = roll_back_to(&target, &current, restoring, &mut restored) {
        // Garrison is stopped now: back to the release that ran, and running.
        announce("Rollback failed; starting the release that ran before.");
        switch(&base.join("current"), &current)?;
        switch(&previous, &target)?;
        install_system_files(&current)?;
        let outcome = if start(&current).is_ok() {
            "the release that ran before is running again"
        } else {
            "the release that ran before did not start either"
        };
        // What went back stays: the release that ran runs on it now.
        let back = restoring.map_or_else(String::new, |(source, _)| {
            state::went_back(&restored, source)
        });
        return Err(format!(
            "The rollback failed ({error}); {outcome}.{back} See the journal."
        ));
    }
    announce(&format!("Rolled back to {name}."));
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;

    /// A backup that holds `database` at schema `version`.
    fn copy(backup: &Path, database: Database, version: usize) {
        let directory = backup.join(database.writer());
        fs::create_dir_all(&directory).unwrap();
        Connection::open(directory.join(database.file_name()))
            .unwrap()
            .execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS t(a); PRAGMA user_version = {version};"
            ))
            .unwrap();
    }

    #[test]
    fn a_schema_this_release_raises_needs_the_state_from_before() {
        let directory = tempfile::tempdir().unwrap();
        let backup = directory.path();
        assert!(!schema_rises(backup), "an empty backup raises nothing");
        for database in Database::ALL {
            copy(backup, database, crate::ops::schema_version(database));
        }
        assert!(!schema_rises(backup), "every schema is this release's");
        // 0.1.2 raised the status database to 2; a copy from 0.1.1 holds 1.
        let status = crate::ops::schema_version(Database::Status);
        assert!(status >= 2);
        copy(backup, Database::Status, status - 1);
        assert!(schema_rises(backup));
    }
}
