//! The record of a root command that has not finished, so that the same
//! command run again finishes it: an upgrade, a rollback or a restore that
//! dies between two steps leaves links and a state that do not say what was
//! under way. `/opt/garrison/unfinished.json`, root's alone, is written just
//! before the services stop, again once a switch back has stopped them, and
//! removed once a release runs and the links name it and the one to roll
//! back to.
//!
//! It says what the state is only until a service of Garrison's starts
//! again: from then on it is stale, and nothing goes back on its word, but
//! for an upgrade whose new release does not run (`stale.rs`).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use garrison_core::files::atomic_write;
use serde::{Deserialize, Serialize};

use super::BASE;
use super::files::{Step, announce, io};
use super::stale::{self, Stamp};

const RECORD: &str = "unfinished.json";

/// What an earlier run began; every path a release or a backup, resolved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "lowercase")]
pub(super) enum Unfinished {
    /// An upgrade from the release that ran, `from`, to `to`. `previous` is
    /// what that link named before it, `backup` the state from before it.
    Upgrade {
        from: PathBuf,
        to: PathBuf,
        previous: Option<PathBuf>,
        backup: PathBuf,
    },
    /// A rollback that leaves `from` for `to`; `previous` is what that link
    /// names once it is done.
    Rollback {
        from: PathBuf,
        to: PathBuf,
        previous: Option<PathBuf>,
    },
    /// A restore of the state in `source`; `kept` holds the state from
    /// before it.
    Restore { source: PathBuf, kept: PathBuf },
}

/// The record as it lies on disk: the run, and when it was written.
#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    #[serde(flatten)]
    run: Unfinished,
    #[serde(default)]
    written: Option<Stamp>,
}

/// What a run finds of an earlier one.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Seen {
    /// No record, or one the links no longer fit, which was removed.
    Nothing,
    /// A record that says what the state is: nothing has started since.
    Holds(Unfinished),
    /// An upgrade whose new release was started since, is current and does
    /// not run: acted on as one that holds, once the state as it is has been
    /// copied, since the new release may have recorded what no copy holds.
    Failed(Unfinished),
    /// A record that no longer says what the state is, which was removed
    /// with a line; the links are as its run had set them by its last step.
    Stale(Unfinished),
}

fn path(base: &Path) -> PathBuf {
    base.join(RECORD)
}

/// The record an earlier run left, and whether it still holds.
pub(super) fn read() -> Step<Seen> {
    read_in(Path::new(BASE), Stamp::take().as_ref(), stale::runs)
}

/// As `read`, with `now` the writers' starts as they are now and `runs`
/// whether the release `current` names runs.
fn read_in(base: &Path, now: Option<&Stamp>, runs: impl Fn() -> bool) -> Step<Seen> {
    let Some(stored) = recorded(base)? else {
        return Ok(Seen::Nothing);
    };
    if !stored.run.fits(base) {
        announce(&format!(
            "{} named {}, which the links in {} no longer show; it was removed.",
            path(base).display(),
            stored.run.describe(),
            base.display()
        ));
        clear_in(base)?;
        return Ok(Seen::Nothing);
    }
    if !stale::started_since(stored.written.as_ref(), now) {
        return Ok(Seen::Holds(stored.run));
    }
    if let Unfinished::Upgrade { to, .. } = &stored.run
        && fs::canonicalize(base.join("current")).ok().as_ref() == Some(to)
        && !runs()
    {
        return Ok(Seen::Failed(stored.run));
    }
    announce(&stale::resolve(&stored.run, base, &path(base))?);
    clear_in(base)?;
    Ok(Seen::Stale(stored.run))
}

/// The record as it is, without the look at the links.
fn recorded(base: &Path) -> Step<Option<Stored>> {
    let path = path(base);
    let text = match fs::read(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    serde_json::from_slice(&text).map(Some).map_err(|error| {
        format!(
            "{} cannot be read ({error}); remove it once the links in {} name the right \
             releases.",
            path.display(),
            base.display()
        )
    })
}

/// The release an unfinished upgrade began from, where one fits the host:
/// the release `garrison upgrade` compares an archive with. Nothing is
/// changed, as that command holds no lock; the installer it starts judges
/// the record.
pub(super) fn upgrading_from() -> Option<PathBuf> {
    let base = Path::new(BASE);
    let stored = recorded(base).ok().flatten()?;
    if !stored.run.fits(base) {
        return None;
    }
    match stored.run {
        Unfinished::Upgrade { from, .. } => Some(from),
        _ => None,
    }
}

/// Write the record, with the writers' starts as they are now.
pub(super) fn write(record: &Unfinished) -> Step {
    write_in(Path::new(BASE), record, Stamp::take())
}

fn write_in(base: &Path, record: &Unfinished, written: Option<Stamp>) -> Step {
    let path = path(base);
    let stored = Stored {
        run: record.clone(),
        written,
    };
    let text = serde_json::to_vec_pretty(&stored).map_err(|error| error.to_string())?;
    io(atomic_write(&path, &text, 0o600), &path)
}

/// No record: nothing is unfinished.
pub(super) fn clear() -> Step {
    clear_in(Path::new(BASE))
}

/// Nothing is unfinished any more. A record left behind would make the next
/// run undo what is done, so one that cannot be removed is an error.
pub(super) fn done() -> Step {
    clear().map_err(|error| {
        format!("{error}; remove that file, or the next installer run takes this for unfinished")
    })
}

fn clear_in(base: &Path) -> Step {
    let path = path(base);
    match fs::remove_file(&path) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            Err(format!("{}: {error}", path.display()))
        }
        _ => Ok(()),
    }
}

/// A release's name: its folder's.
pub(super) fn name(release: &Path) -> String {
    release
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

impl Unfinished {
    /// Whether the links are as this command leaves them at one of its steps.
    fn fits(&self, base: &Path) -> bool {
        let link = |name: &str| fs::canonicalize(base.join(name)).ok();
        let (current, previous) = (link("current"), link("previous"));
        let current = current.as_deref();
        match self {
            Self::Upgrade {
                from,
                to,
                previous: before,
                backup,
            } => {
                from.is_dir()
                    && backup.is_dir()
                    && (current == Some(from.as_path()) || current == Some(to.as_path()))
                    && (previous.as_deref() == Some(from.as_path()) || previous == *before)
            }
            Self::Rollback {
                from,
                to,
                previous: after,
            } => {
                to.is_dir()
                    && (current == Some(from.as_path()) || current == Some(to.as_path()))
                    && (previous.as_deref() == Some(from.as_path())
                        || previous.as_deref() == Some(to.as_path())
                        || previous == *after)
            }
            Self::Restore { kept, .. } => kept.is_dir(),
        }
    }

    /// What was under way, for a line.
    pub(super) fn describe(&self) -> String {
        match self {
            Self::Upgrade { from, to, .. } => {
                format!("an upgrade from {} to {}", name(from), name(to))
            }
            Self::Rollback { from, to, .. } => {
                format!("a rollback from {} to {}", name(from), name(to))
            }
            Self::Restore { source, .. } => format!("a restore from {}", source.display()),
        }
    }

    /// Why another command must wait for this one, and what finishes it.
    pub(super) fn finish_first(&self) -> String {
        let how = match self {
            Self::Upgrade { to, .. } => format!("run the installer of {} again", name(to)),
            Self::Rollback { from, .. } => format!(
                "run `{} install --rollback`",
                from.join("bin/garrison").display()
            ),
            Self::Restore { source, .. } => format!(
                "run `{} restore --from {}`",
                super::command::name(),
                source.display()
            ),
        };
        format!(
            "An earlier run left {} unfinished; {how} to finish it. Nothing was changed.",
            self.describe()
        )
    }
}

#[cfg(test)]
mod tests;
