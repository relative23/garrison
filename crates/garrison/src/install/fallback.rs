//! After a failed upgrade: back to the release that ran, with a state it
//! can read.
//!
//! By the time a new release fails to start or to stay up, its services may
//! have opened their databases and raised their schema, and a collection run
//! of the new timer may have done the same to the status database. The
//! release that ran refuses to open such a database. So before it starts
//! again, every writer stops and each database whose schema rose goes back
//! to its copy from before the upgrade; the others keep what they recorded.
//!
//! The release counts as running only when it reads every database and its
//! services stay up. Otherwise the links stay as the upgrade set them:
//! `previous` then still names the release to return to, and `install
//! --rollback --restore-state` is the second attempt.
//!
//! An upgrade that an earlier run did not finish (`unfinished.rs`) goes on
//! here, or is switched back before anything else, while its record holds.

use std::path::{Path, PathBuf};

use garrison_core::config;

use super::files::{Step, announce, fresh_folder, switch};
use super::requirements::{room, state_size};
use super::system::install_system_files;
use super::unfinished::{self, Seen, Unfinished, name};
use super::{BACKUPS, BASE, CONFIG, cli, command, start, state, stop_services};

/// An upgrade an earlier run began, which this run of its release goes on with.
pub(super) struct Resumed {
    /// The release that ran before it.
    pub(super) from: PathBuf,
    /// What `previous` named before it.
    pub(super) previous: Option<PathBuf>,
    /// The state from before it.
    pub(super) backup: PathBuf,
}

/// Before an installer of release `version` goes on: an upgrade that an
/// earlier run began goes on where this run installs that upgrade's release
/// again and `current` already names it, since its state may already be the
/// new release's; any other run first switches back to the release that
/// ran, as after a failed start. Another unfinished command is to be
/// finished first. A record that no longer holds is not acted on: the run
/// goes on from the release that runs. Where the new release was started
/// since and does not run, the state as it is is copied before it goes back.
pub(super) fn before_install(version: &str) -> Step<Option<Resumed>> {
    let (from, to, previous, backup, failed) = match unfinished::read()? {
        Seen::Holds(Unfinished::Upgrade {
            from,
            to,
            previous,
            backup,
        }) => (from, to, previous, backup, false),
        Seen::Failed(Unfinished::Upgrade {
            from,
            to,
            previous,
            backup,
        }) => (from, to, previous, backup, true),
        Seen::Holds(other) | Seen::Failed(other) => return Err(other.finish_first()),
        Seen::Nothing | Seen::Stale(_) => return Ok(None),
    };
    if failed {
        let kept = kept_by(&to)?;
        announce(&format!(
            "An earlier run did not finish the upgrade to {}, which was started since and does \
             not run; the state as it is was copied to {}.",
            name(&to),
            kept.display()
        ));
    }
    let current = std::fs::canonicalize(Path::new(BASE).join("current")).ok();
    if !failed && current.as_deref() == Some(to.as_path()) && name(&to) == version {
        announce(&format!(
            "Going on with the upgrade from {} to {version} that an earlier run did not finish.",
            name(&from)
        ));
        return Ok(Some(Resumed {
            from,
            previous,
            backup,
        }));
    }
    announce(&format!(
        "Switching back to {} first: an earlier run did not finish the upgrade to {}.",
        name(&from),
        name(&to)
    ));
    switch_back(&from, previous.as_deref(), &to, Some(&backup)).map_err(|failure| {
        format!(
            "An earlier run did not finish the upgrade to {}, and {failure}.",
            name(&to)
        )
    })?;
    unfinished::done()?;
    Ok(None)
}

/// The state as it is, copied by `release`'s own backup into a folder of
/// its own, before anything changes.
fn kept_by(release: &Path) -> Step<PathBuf> {
    room(
        &[(Path::new(BACKUPS), state_size())],
        "the copy of the state as it is",
    )?;
    let kept = fresh_folder(Path::new(BACKUPS), "pre-switch-back")?;
    let copied = cli(release, &["backup", "--to", &kept.display().to_string()])?;
    if !copied.status.success() {
        let _ = std::fs::remove_dir_all(&kept);
        return Err(format!(
            "The state as it is could not be copied before the switch back ({}); nothing was \
             changed.",
            String::from_utf8_lossy(&copied.stderr).trim()
        ));
    }
    Ok(kept)
}

/// Back to `old`, the release that ran, from `attempted`: what the new
/// release migrated goes back to its copy in `backup`, `old` must read the
/// state and stay up, and `previous` names `earlier` again. Where that
/// fails, nothing of a release that is not current keeps running, and the
/// links are set so that `install --rollback --restore-state` is the second
/// attempt; the error says so. Where `current` did not name `attempted` yet,
/// it stays at `old`: the rollback takes its target from the record.
pub(super) fn switch_back(
    old: &Path,
    earlier: Option<&Path>,
    attempted: &Path,
    backup: Option<&Path>,
) -> Step {
    let record = backup.map(|backup| Unfinished::Upgrade {
        from: old.to_owned(),
        to: attempted.to_owned(),
        previous: earlier.map(Path::to_owned),
        backup: backup.to_owned(),
    });
    let base = Path::new(BASE);
    let switched = std::fs::canonicalize(base.join("current")).ok().as_deref() == Some(attempted);
    let mut returned = state::Returned::default();
    switched_back(old, earlier, backup, record.as_ref(), &mut returned).map_err(|failure| {
        stop_services();
        // Stopped again, the record holds for the second attempt; one that
        // cannot be written is stale for the next run, which then acts on
        // nothing it says.
        if let Some(record) = &record {
            let _ = unfinished::write(record);
        }
        let kept = if switched {
            switch(&base.join("current"), attempted)
                .and_then(|()| switch(&base.join("previous"), old))
        } else {
            switch(&base.join("current"), old)
        };
        let what = match failure {
            Failure::Before(error) => format!("switching back to {} failed ({error})", name(old)),
            Failure::Start(error) => format!("the previous release did not start either ({error})"),
        };
        let went = backup.map_or_else(String::new, |backup| returned.said(backup));
        match kept {
            Ok(()) => format!(
                "{what}.{went} `{} install --rollback --restore-state` returns to it with the state \
                 from before the upgrade",
                command::name()
            ),
            Err(links) => format!("{what}, and the links could not be set back ({links}).{went}"),
        }
    })
}

/// Why a switch back failed: before the release that ran started again,
/// or as it started.
enum Failure {
    Before(String),
    Start(String),
}

/// Return what the new release migrated, then start `old` and see that it
/// reads the state and stays up.
fn switched_back(
    old: &Path,
    earlier: Option<&Path>,
    backup: Option<&Path>,
    record: Option<&Unfinished>,
    returned: &mut state::Returned,
) -> Result<(), Failure> {
    // A service of the new release that still runs, or a collection run its
    // timer started, would write into a database that is being replaced.
    stop_services();
    // Everything is stopped again: written anew, the record holds until
    // `old` starts, though the new release started since it was first.
    if let Some(record) = record {
        unfinished::write(record).map_err(Failure::Before)?;
    }
    if let Some(backup) = backup {
        let settings = Path::new(CONFIG).join("garrison.toml");
        let config = config::load(&settings).map_err(|error| {
            Failure::Before(format!("cannot load {}: {error}", settings.display()))
        })?;
        state::restore_migrated(backup, &config, returned).map_err(Failure::Before)?;
        let went = returned.said(backup);
        if !went.is_empty() {
            announce(&format!(
                "The new release had changed what the release that ran cannot read.{went} The \
                 other databases keep their data."
            ));
        }
    }
    let base = Path::new(BASE);
    switch(&base.join("current"), old).map_err(Failure::Before)?;
    install_system_files(old).map_err(Failure::Before)?;
    // Only the release itself knows which schemas it reads. The collector
    // opens its database when its timer runs, after this installer is gone:
    // a database it cannot read must be found now.
    let checked = cli(old, &["self-check"]).map_err(Failure::Before)?;
    if !checked.status.success() {
        return Err(Failure::Before(format!(
            "{} cannot read the current state, as its self-check says of {}",
            name(old),
            state::unreadable(&checked.stdout)
        )));
    }
    start(old).map_err(Failure::Start)?;
    // `previous` as it was before the upgrade.
    let previous = base.join("previous");
    if let Some(earlier) = earlier {
        return switch(&previous, earlier).map_err(Failure::Before);
    }
    let _ = std::fs::remove_file(&previous);
    Ok(())
}
