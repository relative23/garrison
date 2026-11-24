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
//! Run again after it was interrupted before Garrison started, a restore
//! makes no new copy and names the first run's (`unfinished.rs`). Once
//! Garrison runs, also on a state that went back only in part, the record
//! goes, and a restore run again copies the state as it is first.
//!
//! A backup holds no sessions and no credentials: users sign in again, and
//! where `/etc/garrison/credentials` was lost as well, `garrison stalwart
//! setup` makes new ones.

use std::fs;
use std::path::{Path, PathBuf};

use garrison_core::config;

use super::files::{Step, announce, fresh_folder, io, lock};
use super::requirements::{preflight, state_size};
use super::unfinished::{self, Seen, Unfinished};
use super::{BACKUPS, BASE, CONFIG, LOCK, cli, precheck, start, state, stop_services};

/// The backup at `from`, if it is one that `garrison backup` wrote.
fn backup_at(from: &Path) -> Step<PathBuf> {
    let refused = || {
        format!(
            "{} is no backup that `garrison backup` wrote (no backup.json there); nothing \
             was changed.",
            from.display()
        )
    };
    let source = fs::canonicalize(from).map_err(|_| refused())?;
    if source.is_dir() && source.join("backup.json").is_file() {
        Ok(source)
    } else {
        Err(refused())
    }
}

fn restore(from: &Path) -> Step {
    preflight()?;
    let _held = lock(Path::new(LOCK))?;
    // An interrupted restore's copy stays the state from before, while
    // nothing has written the state since.
    let earlier = match unfinished::read()? {
        Seen::Holds(Unfinished::Restore { kept, .. }) => Some(kept),
        Seen::Holds(record) | Seen::Failed(record) => return Err(record.finish_first()),
        Seen::Stale(_) | Seen::Nothing => None,
    };
    let source = backup_at(from)?;
    let link = Path::new(BASE).join("current");
    let current = io(fs::canonicalize(&link), &link)?;
    let name = current.file_name().unwrap_or_default().to_string_lossy();
    if let Some(reason) = state::unsuited(&source, &name) {
        return Err(format!("{reason} Nothing was changed."));
    }
    // The running release's own check of the copies: intact, and of a schema
    // it reads.
    let place = source.display().to_string();
    let check = cli(&current, &["self-check", "--state", &place])?;
    if !check.status.success() {
        return Err(format!(
            "The copies in {place} did not pass `garrison self-check --state`; nothing was \
             changed.\n{}",
            String::from_utf8_lossy(&check.stdout).trim()
        ));
    }
    let settings = Path::new(CONFIG).join("garrison.toml");
    let config = config::load(&settings)
        .map_err(|error| format!("Cannot load {}: {error}", settings.display()))?;
    let owner = state::policy_owner().map_err(|error| format!("{error} Nothing was changed."))?;
    // The release that starts again takes today's configuration with the
    // access policy that comes back, which the services still run without.
    let comes_back = precheck::brings_policy(&source);
    if let Err(said) = precheck::configuration(&current, comes_back)? {
        return Err(format!(
            "Garrison {name}'s check-config refuses {}; nothing was changed:\n{said}",
            settings.display()
        ));
    }
    if comes_back {
        precheck::policy_place(&config)
            .map_err(|refusal| format!("{refusal} Nothing was changed."))?;
        if let Err(said) = precheck::policy_comes_back(&current, &source)? {
            return Err(format!(
                "The access policy in {place} does not suit {}, as Garrison {name}'s \
                 check-config says; nothing was changed:\n{said}",
                settings.display()
            ));
        }
    }
    // Each copy beside the database it replaces, and the state as it is
    // where this run copies it.
    let copy_room = [(Path::new(BACKUPS), state_size())];
    let besides: &[(&Path, u64)] = if earlier.is_some() { &[] } else { &copy_room };
    precheck::copies_fit(&source, &config, besides, "the restore")?;
    let kept = match earlier {
        Some(kept) => {
            announce(&format!(
                "An earlier restore did not finish; the state from before it is in {}.",
                kept.display()
            ));
            kept
        }
        None => keep(&current)?,
    };
    // From here on, a run that is killed leaves a record for the next.
    unfinished::write(&Unfinished::Restore {
        source: source.clone(),
        kept: kept.clone(),
    })?;
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
    went_back: String,
}

impl Restored<'_> {
    /// The restore's last word. Once Garrison runs, it records on what was
    /// put back, which no copy holds: the record goes, also after a failure.
    fn said(&self, result: Step, started: Step) -> Step {
        let left = match &started {
            Ok(()) => unfinished::done().err(),
            Err(_) => None,
        };
        let left = left.map(|error| format!(" {error}.")).unwrap_or_default();
        let (place, name, kept) = (self.place, self.release, self.kept.display());
        match (result, started) {
            (Ok(()), Ok(())) if left.is_empty() => {
                announce(&format!(
                    "Restored the state from {place}; Garrison {name} is running. Users sign \
                     in again: a backup holds no sessions. The state from before is in {kept}."
                ));
                Ok(())
            }
            (Ok(()), Ok(())) => Err(format!(
                "Restored the state from {place}; Garrison {name} is running, but{left} The \
                 state from before is in {kept}."
            )),
            (Err(error), started) => Err(format!(
                "The restore failed ({error}); Garrison {}.{} The state from before is in \
                 {kept}.{left}",
                if started.is_ok() {
                    "is running with what could be put back"
                } else {
                    "did not start either"
                },
                self.went_back,
            )),
            (Ok(()), Err(error)) => Err(format!(
                "The state was put back, but Garrison did not start ({error}). The state from \
                 before is in {kept}; see the journal."
            )),
        }
    }
}

/// What is there now, copied by `current`'s own backup, so that this restore
/// can be taken back.
fn keep(current: &Path) -> Step<PathBuf> {
    let kept = fresh_folder(Path::new(BACKUPS), "pre-restore").map_err(|error| {
        format!("The state as it is could not be backed up ({error}); nothing was changed.")
    })?;
    announce(&format!(
        "Backing up the state as it is to {}",
        kept.display()
    ));
    let backup = cli(current, &["backup", "--to", &kept.display().to_string()])?;
    if !backup.status.success() {
        let _ = fs::remove_dir_all(&kept);
        return Err(format!(
            "The state as it is could not be backed up ({}); nothing was changed.",
            String::from_utf8_lossy(&backup.stderr).trim()
        ));
    }
    Ok(kept)
}

pub(crate) fn run_restore(from: &Path) -> u8 {
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
    match restore(from) {
        Ok(()) => 0,
        Err(error) => {
            crate::complain(&error);
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
        let refusal = backup_at(&directory.path().join("absent")).unwrap_err();
        assert!(refusal.contains("nothing was changed"), "{refusal}");
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
