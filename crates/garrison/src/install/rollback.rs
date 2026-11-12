//! `garrison install --rollback [--restore-state]`: back to the previous
//! release, with the state from before the upgrade if asked.
//!
//! Every check comes before the services stop. Once they have stopped, any
//! failure returns to the release that ran and starts it again.

use std::fs;
use std::path::{Path, PathBuf};

use garrison_core::config::{self, Database};

use super::files::{Step, announce, io, lock, place, relabel, replace_in, switch};
use super::system::install_system_files;
use super::{BACKUPS, BASE, CONFIG, LAST, LOCK, cli, preflight, start, stop_services};

/// The backup `--restore-state` returns to, found before anything stops.
fn restore_source() -> Step<PathBuf> {
    let last = Path::new(BACKUPS).join(LAST);
    match fs::canonicalize(&last) {
        Ok(source) if source.is_dir() => Ok(source),
        _ => Err(format!(
            "There is no state from before an upgrade to restore ({}); nothing was changed.",
            last.display()
        )),
    }
}

/// Put the pre-upgrade copies of the databases and the policy back.
fn restore_state(source: &Path) -> Step {
    // The configured state directories, which need not be the defaults.
    let settings = Path::new(CONFIG).join("garrison.toml");
    let config = config::load(&settings)
        .map_err(|error| format!("Cannot load {}: {error}", settings.display()))?;
    announce(&format!(
        "Restoring Garrison state from {}",
        source.display()
    ));
    for database in Database::ALL {
        let copy = source.join(database.writer()).join(database.file_name());
        let destination = config.database(database);
        let Some(folder) = destination.parent().filter(|_| copy.exists()) else {
            continue;
        };
        // A WAL or journal of the replaced file must not survive.
        let journal = format!("{}-", database.file_name());
        for stale in fs::read_dir(folder).into_iter().flatten().flatten() {
            if stale.file_name().to_string_lossy().starts_with(&journal) {
                let _ = fs::remove_file(stale.path());
            }
        }
        // The service user owns this directory: replace the file without
        // following anything planted there, and keep the directory's owner.
        replace_in(folder, database.file_name(), &copy, database.mode())?;
        relabel(std::slice::from_ref(&destination));
    }
    let policy = source.join(crate::ops::POLICY_COPY);
    if policy.exists() {
        let target = config.broker.policy.clone();
        place(&policy, &target, 0o640)?;
        relabel(&[target]);
    }
    Ok(())
}

/// Make `target` current and `current` previous, then start `target`.
fn roll_back_to(target: &Path, current: &Path, source: Option<&Path>) -> Step {
    if let Some(source) = source {
        restore_state(source)?;
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
    // The previous release must load today's configuration: a setting added
    // since, such as `modules`, would keep it from starting, and neither
    // --restore-state nor its self-check would notice before the switch.
    let check = cli(&target, &["check-config"])?;
    if !check.status.success() {
        return Err(format!(
            "{name} cannot load {CONFIG}/garrison.toml:\n{}\n\
             Remove the settings {name} does not know, or put back the file from \
             before the upgrade ({BACKUPS}/{LAST}/etc/garrison.toml), then roll back.",
            String::from_utf8_lossy(&check.stderr).trim()
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
    let source = if with_state {
        Some(restore_source()?)
    } else {
        None
    };
    stop_services();
    if let Err(error) = roll_back_to(&target, &current, source.as_deref()) {
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
        return Err(format!(
            "The rollback failed ({error}); {outcome}. See the journal."
        ));
    }
    announce(&format!("Rolled back to {name}."));
    Ok(())
}
