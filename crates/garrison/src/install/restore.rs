//! `garrison restore --from DIR`: put back the state that `garrison backup`
//! wrote.
//!
//! ```text
//! sudo garrison restore --from /var/backups/garrison/latest
//! ```
//!
//! Every check comes before the services stop: the directory is a backup,
//! this release reads it, its copies are intact, and this release's
//! check-config takes today's configuration with the access policy that
//! comes back (`precheck.rs`). The state as it is goes to
//! `pre-restore-*` first, so that a restore can be taken back with another
//! one. Then every database and the access policy go back as
//! `--rollback --restore-state` puts them back, and the services start.
//!
//! A backup holds no sessions and no credentials: users sign in again, and
//! where `/etc/garrison/credentials` was lost as well, `garrison stalwart
//! setup` makes new ones.

use std::fs;
use std::path::{Path, PathBuf};

use garrison_core::config;

use super::files::{Step, announce, fresh_folder, io, lock};
use super::requirements::{preflight, state_size};
use super::{BACKUPS, BASE, CONFIG, LOCK, cli, precheck, start, state, states, stop_services};
use crate::state::State;

/// The backup at `from`, if it is one that `garrison backup` wrote.
fn backup_at(from: &Path) -> Step<PathBuf> {
    let source = fs::canonicalize(from).map_err(|_| states::not_a_backup(from))?;
    if source.is_dir() && source.join("backup.json").is_file() {
        Ok(source)
    } else {
        Err(states::not_a_backup(from))
    }
}

fn restore(from: &Path) -> Step {
    preflight()?;
    super::requirements::base_shown()?;
    let _held = lock(Path::new(LOCK))?;
    super::leftover()?;
    let source = backup_at(from)?;
    let link = Path::new(BASE).join("current");
    let current = io(fs::canonicalize(&link), &link)?;
    let name = current.file_name().unwrap_or_default().to_string_lossy();
    if let Some(refusal) = state::unsuited(&source, &name) {
        return Err(refusal);
    }
    // The running release's own check of the copies: intact, and of a schema
    // it reads.
    let place = source.display().to_string();
    let check = cli(&current, &["self-check", "--state", &place])?;
    if !check.status.success() {
        let said = String::from_utf8_lossy(&check.stdout);
        return Err(states::copies_refused(&place, said.trim()));
    }
    let settings = Path::new(CONFIG).join("garrison.toml");
    let config = config::load(&settings).map_err(|error| states::unloadable(&settings, error))?;
    let owner = state::policy_owner()?;
    // The release that starts again takes today's configuration with the
    // access policy that comes back, which the services still run without.
    let comes_back = precheck::brings_policy(&source);
    if let Err(said) = precheck::configuration(&current, comes_back)? {
        return Err(states::restore_config_refused(&name, &settings, &said));
    }
    if comes_back {
        precheck::policy_place(&config)?;
        if let Err(said) = precheck::policy_comes_back(&current, &source)? {
            return Err(states::restore_policy(&place, &settings, &name, &said));
        }
    }
    // Each copy beside the database it replaces, and the state as it is.
    let copy_room = [(Path::new(BACKUPS), state_size())];
    precheck::copies_fit(&source, &config, &copy_room, "the restore")?;
    let kept = keep(&current)?;
    stop_services();
    let mut restored = state::Returned::default();
    let result = state::restore_all(&source, &config, owner, &mut restored);
    // Garrison is stopped now: whatever was put back, it starts again.
    let started = start(&current);
    let put_back = Restored {
        place: &place,
        release: &name,
        kept: &kept,
        went_back: restored.said(&source),
    };
    put_back.said(result, started)
}

/// What a restore put back, from where, and where the state from before is.
struct Restored<'a> {
    place: &'a str,
    release: &'a str,
    kept: &'a Path,
    went_back: Option<State>,
}

impl Restored<'_> {
    /// The restore's last word.
    fn said(&self, result: Step, started: Step) -> Step {
        let (went, kept) = (self.went_back.as_ref(), self.kept);
        match (result, started) {
            (Ok(()), Ok(())) => {
                announce(&states::restored(self.place, self.release, kept).to_string());
                Ok(())
            }
            (Err(error), Ok(())) => Err(states::restore_failed(&error, went, kept)),
            (Err(error), Err(_)) => Err(states::restore_neither(&error, went, kept)),
            (Ok(()), Err(error)) => Err(states::restore_unstarted(&error, kept)),
        }
    }
}

/// What is there now, copied by `current`'s own backup, so that this restore
/// can be taken back.
fn keep(current: &Path) -> Step<PathBuf> {
    let kept = fresh_folder(Path::new(BACKUPS), "pre-restore")
        .map_err(|error| states::keep_failed(&error))?;
    announce(&format!(
        "Backing up the state as it is to {}",
        kept.display()
    ));
    let backup = cli(current, &["backup", "--to", &kept.display().to_string()])?;
    if !backup.status.success() {
        let _ = fs::remove_dir_all(&kept);
        let said = String::from_utf8_lossy(&backup.stderr);
        return Err(states::keep_failed(said.trim()));
    }
    Ok(kept)
}

pub(crate) fn run_restore(from: &Path) -> u8 {
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
    match restore(from) {
        Ok(()) => 0,
        Err(refusal) => {
            crate::complain(&refusal.to_string());
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_directory_that_backup_wrote_is_a_backup() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent");
        assert_eq!(
            backup_at(&absent).unwrap_err(),
            states::not_a_backup(&absent)
        );
        // A directory without the backup's own account of itself.
        assert!(backup_at(directory.path()).is_err());
        fs::write(directory.path().join("backup.json"), "{}").unwrap();
        assert_eq!(
            backup_at(directory.path()).unwrap(),
            fs::canonicalize(directory.path()).unwrap()
        );
        // A file of that name is none.
        assert!(backup_at(&directory.path().join("backup.json")).is_err());
    }
}
