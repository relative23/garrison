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
    BACKUPS, BASE, CONFIG, LAST, LOCK, cli, precheck, preflight, start, state, states,
    stop_services,
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
        _ => return Err(states::no_state(&last)),
    };
    match state::unsuited(&source, name) {
        Some(refusal) => Err(refusal),
        None => Ok(source),
    }
}

/// Before anything stops: the access policy that the state in `source`
/// brings, where it brings one, goes where the broker reads it and suits
/// today's configuration as `target` reads it, and every copy fits beside
/// the database it replaces. Returns the policy's owner.
fn state_fits(target: &Path, source: &Path, comes_back: bool) -> Step<(Uid, Gid)> {
    let owner = state::policy_owner()?;
    let settings = Path::new(CONFIG).join("garrison.toml");
    let config = config::load(&settings)
        .map_err(|error| states::unchanged(states::unloadable(&settings, error)))?;
    if comes_back {
        precheck::policy_place(&config)?;
        if let Err(said) = precheck::policy_comes_back(target, source)? {
            let release = super::name(target);
            return Err(states::rollback_policy(source, &settings, &release, &said));
        }
    }
    precheck::copies_fit(source, &config, &[], "the rollback")?;
    Ok(owner)
}

/// Put the pre-upgrade copies of the databases and the policy back, the
/// policy owned by `owner`; what went back is in `restored`.
fn restore_state(source: &Path, owner: (Uid, Gid), restored: &mut state::Returned) -> Step {
    // The configured state directories, which need not be the defaults.
    let settings = Path::new(CONFIG).join("garrison.toml");
    let config = config::load(&settings).map_err(|error| states::unloadable(&settings, error))?;
    state::restore_all(source, &config, owner, restored)
}

/// Put the state back where asked, make `target` current and start it, and
/// only then make `left` previous: until `target` runs, `previous` names it,
/// so that the same rollback run again goes there.
fn roll_back_to(
    target: &Path,
    left: &Path,
    source: Option<(&Path, (Uid, Gid))>,
    restored: &mut state::Returned,
) -> Step {
    if let Some((source, owner)) = source {
        restore_state(source, owner, restored)?;
    }
    let base = Path::new(BASE);
    switch(&base.join("current"), target)?;
    install_system_files(target)?;
    start(target)?;
    switch(&base.join("previous"), left)
}

/// Where a rollback goes: to `target`, the release `previous` names, from
/// `current`, leaving `left`. That is `current`, or, where `current` names
/// the target already, as a rollback cut short once it switched `current`
/// leaves it, the installed release of `installer`, the binary that runs
/// this, which that rollback's first line named.
struct Plan {
    target: PathBuf,
    current: PathBuf,
    left: PathBuf,
}

fn plan(base: &Path, installer: Option<PathBuf>) -> Step<Plan> {
    let current = io(
        fs::canonicalize(base.join("current")),
        &base.join("current"),
    )?;
    let Ok(target) = fs::canonicalize(base.join("previous")) else {
        return Err(states::no_previous());
    };
    if target != current {
        return Ok(Plan {
            target,
            left: current.clone(),
            current,
        });
    }
    let releases = fs::canonicalize(base.join("releases")).ok();
    let installer = installer
        .and_then(|binary| Some(binary.parent()?.parent()?.to_owned()))
        .filter(|release| release.parent() == releases.as_deref() && *release != target);
    match installer {
        Some(left) => Ok(Plan {
            target,
            current,
            left,
        }),
        None => Err(states::no_other_release()),
    }
}

pub(super) fn rollback(with_state: bool) -> Step {
    preflight()?;
    super::requirements::base_shown()?;
    let _held = lock(Path::new(LOCK))?;
    let base = Path::new(BASE);
    let Plan {
        target,
        current,
        left,
    } = plan(base, std::env::current_exe().ok())?;
    let name = super::name(&target);
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
        return Err(states::rollback_unloadable(&name, &said));
    }
    // After a schema change only the pre-upgrade copies suit the previous
    // release, and only its own self-check knows which schemas it reads.
    if !with_state {
        let checked = cli(&target, &["self-check"])?;
        if !checked.status.success() {
            let unreadable = state::unreadable(&checked.stdout);
            return Err(states::rollback_unreadable(&name, &unreadable));
        }
    }
    let source = match source {
        Some(source) => Some((source.clone(), state_fits(&target, &source, comes_back)?)),
        None => None,
    };
    let again = format!(
        "{} install --rollback{}",
        left.join("bin/garrison").display(),
        if with_state { " --restore-state" } else { "" }
    );
    announce(&states::rolling_back(&name, &again).to_string());
    // The system files of the target protect the policy as it is.
    super::system::protect_policy().map_err(states::unchanged)?;
    stop_services();
    let restoring = source
        .as_ref()
        .map(|(source, owner)| (source.as_path(), *owner));
    let mut restored = state::Returned::default();
    if let Err(error) = roll_back_to(&target, &left, restoring, &mut restored) {
        // What went back stays: a release that starts now runs on it.
        let back = restoring.and_then(|(source, _)| restored.said(source));
        if current == target {
            stop_services();
            return Err(states::rollback_stopped(&error, &name, back.as_ref()));
        }
        // Garrison is stopped now: back to the release that ran, and running.
        announce("Rollback failed; starting the release that ran before.");
        switch(&base.join("current"), &current)?;
        switch(&base.join("previous"), &target)?;
        install_system_files(&current)?;
        return Err(if start(&current).is_ok() {
            states::rollback_returned(&error, back.as_ref())
        } else {
            states::rollback_neither(&error, back.as_ref())
        });
    }
    announce(&states::rolled_back(&name).to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use rusqlite::Connection;

    use super::*;

    /// A rollback goes to `previous` and leaves `current`; where `current`
    /// names the target already, it leaves the installed release whose
    /// installer runs it, and without one it changes nothing.
    #[test]
    fn a_rollback_cut_short_is_finished_by_the_installer_it_named() {
        let directory = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(directory.path()).unwrap();
        for release in ["0.1", "0.2"] {
            fs::create_dir_all(base.join("releases").join(release).join("bin")).unwrap();
        }
        let release = |name: &str| base.join("releases").join(name);
        let installer = |name: &str| Some(release(name).join("bin/garrison"));
        let link = |name: &str, to: &str| {
            let _ = fs::remove_file(base.join(name));
            symlink(release(to), base.join(name)).unwrap();
        };
        let left = |found: Step<Plan>| found.map(|plan| (plan.target, plan.left));
        assert!(plan(&base, installer("0.2")).is_err(), "no current release");
        link("current", "0.2");
        let refused = plan(&base, installer("0.2")).err().unwrap();
        assert_eq!(refused, states::no_previous());
        // Begun: whichever installer runs it.
        link("previous", "0.1");
        for name in ["0.1", "0.2"] {
            let found = left(plan(&base, installer(name)));
            assert_eq!(found, Ok((release("0.1"), release("0.2"))), "{name}");
        }
        // Cut short once it switched `current`: the installer it named.
        link("current", "0.1");
        let found = left(plan(&base, installer("0.2")));
        assert_eq!(found, Ok((release("0.1"), release("0.2"))));
        // Run by the target's own installer, or by a binary outside the
        // releases: nothing tells the release it left.
        for binary in [
            installer("0.1"),
            Some(base.join("unpacked/bin/garrison")),
            None,
        ] {
            let refused = plan(&base, binary.clone()).err().unwrap();
            assert_eq!(refused, states::no_other_release(), "{binary:?}");
        }
    }

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
