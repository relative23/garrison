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
use garrison_core::time;

use super::files::{Step, announce, io, lock};
use super::requirements::preflight;
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
    // What is there now, so that this restore can be taken back.
    let stamp = time::now().strftime("%Y%m%dT%H%M%S").to_string();
    let kept = Path::new(BACKUPS).join(format!("pre-restore-{stamp}"));
    announce(&format!(
        "Backing up the state as it is to {}",
        kept.display()
    ));
    let backup = cli(&current, &["backup", "--to", &kept.display().to_string()])?;
    if !backup.status.success() {
        return Err(format!(
            "The state as it is could not be backed up ({}); nothing was changed.",
            String::from_utf8_lossy(&backup.stderr).trim()
        ));
    }
    stop_services();
    let restored = state::restore_all(&source, &config, owner);
    // Garrison is stopped now: whatever was put back, it starts again.
    let started = start(&current);
    match (restored, started) {
        (Ok(()), Ok(())) => {
            announce(&format!(
                "Restored the state from {place}; Garrison {name} is running. Users sign in \
                 again: a backup holds no sessions. The state from before is in {}.",
                kept.display()
            ));
            Ok(())
        }
        (Err(error), started) => Err(format!(
            "The restore failed ({error}); Garrison {}. The state from before is in {}.",
            if started.is_ok() {
                "is running with what could be put back"
            } else {
                "did not start either"
            },
            kept.display()
        )),
        (Ok(()), Err(error)) => Err(format!(
            "The state was put back, but Garrison did not start ({error}). The state from \
             before is in {}; see the journal.",
            kept.display()
        )),
    }
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
