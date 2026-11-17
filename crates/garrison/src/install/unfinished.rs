//! The record of a root command that has not finished, so that the same
//! command run again finishes it: an upgrade or a rollback that dies
//! between two steps leaves links and a state that do not say what was
//! under way. `/opt/garrison/unfinished.json`, root's alone, is written just
//! before the services stop and removed once a release runs and the links
//! name it and the one to roll back to.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use garrison_core::files::atomic_write;
use serde::{Deserialize, Serialize};

use super::BASE;
use super::files::{Step, announce, io};

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
}

fn path(base: &Path) -> PathBuf {
    base.join(RECORD)
}

/// The record an earlier run left, if the host still fits it.
pub(super) fn read() -> Step<Option<Unfinished>> {
    read_in(Path::new(BASE))
}

fn read_in(base: &Path) -> Step<Option<Unfinished>> {
    let Some(record) = recorded(base)? else {
        return Ok(None);
    };
    if record.fits(base) {
        return Ok(Some(record));
    }
    announce(&format!(
        "{} named {}, which the links in {} no longer show; it was removed.",
        path(base).display(),
        record.describe(),
        base.display()
    ));
    clear_in(base)?;
    Ok(None)
}

/// The record as it is, without the look at the links.
fn recorded(base: &Path) -> Step<Option<Unfinished>> {
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
/// changed, as that command holds no lock.
pub(super) fn upgrading_from() -> Option<PathBuf> {
    let base = Path::new(BASE);
    let record = recorded(base).ok().flatten()?;
    if !record.fits(base) {
        return None;
    }
    match record {
        Unfinished::Upgrade { from, .. } => Some(from),
        Unfinished::Rollback { .. } => None,
    }
}

pub(super) fn write(record: &Unfinished) -> Step {
    write_in(Path::new(BASE), record)
}

fn write_in(base: &Path, record: &Unfinished) -> Step {
    let path = path(base);
    let text = serde_json::to_vec_pretty(record).map_err(|error| error.to_string())?;
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
        };
        format!(
            "An earlier run left {} unfinished; {how} to finish it. Nothing was changed.",
            self.describe()
        )
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    /// `base` with the releases `names`, `current` and `previous` as given.
    fn host(names: &[&str], current: &str, previous: Option<&str>) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        for name in names {
            fs::create_dir_all(base.join("releases").join(name)).unwrap();
        }
        fs::create_dir_all(base.join("backup")).unwrap();
        symlink(base.join("releases").join(current), base.join("current")).unwrap();
        if let Some(previous) = previous {
            symlink(base.join("releases").join(previous), base.join("previous")).unwrap();
        }
        directory
    }

    fn release(base: &Path, name: &str) -> PathBuf {
        fs::canonicalize(base.join("releases").join(name)).unwrap()
    }

    fn upgrade(base: &Path) -> Unfinished {
        Unfinished::Upgrade {
            from: release(base, "0.1"),
            to: release(base, "0.2"),
            previous: Some(release(base, "0.0")),
            backup: fs::canonicalize(base.join("backup")).unwrap(),
        }
    }

    /// Every step of an upgrade leaves links the record fits: before the
    /// switch, between the two links, after it, and during a switch back.
    #[test]
    fn an_upgrade_is_known_at_every_step_and_forgotten_once_done() {
        for (current, previous) in [("0.1", "0.0"), ("0.1", "0.1"), ("0.2", "0.1")] {
            let directory = host(&["0.0", "0.1", "0.2"], current, Some(previous));
            let base = directory.path();
            write_in(base, &upgrade(base)).unwrap();
            assert_eq!(
                read_in(base).unwrap(),
                Some(upgrade(base)),
                "{current} {previous}"
            );
            clear_in(base).unwrap();
            assert_eq!(read_in(base).unwrap(), None);
            // Clearing what is not there is no error.
            clear_in(base).unwrap();
        }
    }

    /// A record the links no longer fit, as after an older installer ran,
    /// is removed and says so; one that cannot be read stops everything.
    #[test]
    fn a_record_the_host_no_longer_fits_is_removed() {
        let directory = host(&["0.0", "0.1", "0.2", "0.3"], "0.3", Some("0.2"));
        let base = directory.path();
        write_in(base, &upgrade(base)).unwrap();
        assert_eq!(read_in(base).unwrap(), None);
        assert!(!path(base).exists());
        // Without the release it began from there is nothing to return to.
        let directory = host(&["0.0", "0.1", "0.2"], "0.2", Some("0.1"));
        let base = directory.path();
        write_in(base, &upgrade(base)).unwrap();
        fs::remove_dir(base.join("releases/0.1")).unwrap();
        assert_eq!(read_in(base).unwrap(), None);
        fs::write(path(base), "{}").unwrap();
        let refused = read_in(base).unwrap_err();
        assert!(refused.contains("cannot be read"), "{refused}");
        assert!(path(base).exists());
    }

    #[test]
    fn a_rollback_is_known_on_both_sides_of_its_switch() {
        for (current, previous) in [("0.2", "0.1"), ("0.1", "0.1"), ("0.1", "0.2")] {
            let directory = host(&["0.1", "0.2"], current, Some(previous));
            let base = directory.path();
            let record = Unfinished::Rollback {
                from: release(base, "0.2"),
                to: release(base, "0.1"),
                previous: Some(release(base, "0.2")),
            };
            write_in(base, &record).unwrap();
            assert_eq!(read_in(base).unwrap(), Some(record), "{current} {previous}");
        }
    }

    #[test]
    fn the_record_is_roots_alone_and_says_what_finishes_it() {
        use std::os::unix::fs::PermissionsExt;
        let directory = host(&["0.0", "0.1", "0.2"], "0.2", Some("0.1"));
        let base = directory.path();
        write_in(base, &upgrade(base)).unwrap();
        let mode = fs::metadata(path(base)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            upgrade(base).finish_first(),
            "An earlier run left an upgrade from 0.1 to 0.2 unfinished; run the installer of 0.2 \
             again to finish it. Nothing was changed."
        );
    }
}
