//! The test restore: the newest snapshot's copy of a path, restored into a
//! directory of its own, counted and removed again.
//!
//! The directory lies in `/var/tmp`, which every user can write to. A run
//! that is interrupted leaves its copy there, so a restore first removes
//! what earlier runs left; it takes only folders of its own making that no
//! run holds, never a link or another user's folder of that name.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use garrison_collector::backups::{Run, Tool};
use rustix::fs::{FlockOperation, Mode, OFlags};

use super::{Ran, Repository, now, run};
use crate::{complain, say};

/// Restores go to disk, not into `/tmp`, which may be memory.
const RESTORES: &str = "/var/tmp";
const PREFIX: &str = "garrison-restore-";
/// A run holds its directory from the moment after it made it. One that
/// has not changed for this long is no run's that has just begun.
const SETTLED: Duration = Duration::from_hours(1);

/// The files below `directory` and their bytes; links are not followed.
fn restored(directory: &Path) -> (u64, u64) {
    let (mut files, mut bytes) = (0, 0);
    let mut open = vec![directory.to_path_buf()];
    while let Some(next) = open.pop() {
        for entry in fs::read_dir(&next).into_iter().flatten().flatten() {
            let Ok(kind) = entry.metadata().map(|_| entry.file_type()) else {
                continue;
            };
            match kind {
                Ok(kind) if kind.is_dir() => open.push(entry.path()),
                Ok(kind) if kind.is_file() => {
                    files += 1;
                    bytes += entry.metadata().map_or(0, |metadata| metadata.len());
                }
                _ => {}
            }
        }
    }
    (files, bytes)
}

/// A folder of this name, opened without following a link: an open
/// descriptor of it to lock and to look at.
fn opened(path: &Path) -> Option<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::open(path, flags, Mode::empty())
        .ok()
        .map(File::from)
}

/// A directory of its own for one restore, readable by root alone, and its
/// lock, which the run holds until it has removed the directory: a later
/// run sees it and leaves the directory alone, and the kernel lets go of
/// it however this run ends.
fn restore_directory() -> Result<(PathBuf, Option<File>), String> {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random)
        .map_err(|error| format!("No name could be drawn for the restore's directory: {error}"))?;
    let name = garrison_core::hex::encode(&random);
    let path = Path::new(RESTORES).join(format!("{PREFIX}{name}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    // A file system without locks on folders restores all the same; the
    // directory is then left alone only for `SETTLED`.
    let held = opened(&path).filter(|folder| {
        rustix::fs::flock(folder, FlockOperation::NonBlockingLockExclusive).is_ok()
    });
    Ok((path, held))
}

/// Whether `name` is one that `restore_directory` gives.
fn is_restore(name: &OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_prefix(PREFIX))
        .is_some_and(|hex| {
            hex.len() == 16
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// The lock of the folder at `path` where it is a copy an earlier run left:
/// a folder, not a link, of this user's own, which has not changed for
/// `SETTLED` and which no run holds.
fn leftover(path: &Path) -> Option<File> {
    let folder = opened(path)?;
    let status = rustix::fs::fstat(&folder).ok()?;
    if status.st_uid != rustix::process::geteuid().as_raw() {
        return None;
    }
    let changed = folder.metadata().ok()?.modified().ok()?;
    // A time ahead of the clock is no old one.
    if !SystemTime::now()
        .duration_since(changed)
        .is_ok_and(|age| age >= SETTLED)
    {
        return None;
    }
    rustix::fs::flock(&folder, FlockOperation::NonBlockingLockExclusive).ok()?;
    // Still the folder that was looked at: only its owner, this user, could
    // have put another in its place.
    let now = rustix::fs::lstat(path).ok()?;
    ((now.st_dev, now.st_ino) == (status.st_dev, status.st_ino)).then_some(folder)
}

/// Remove what interrupted restores left in `folder`: each copy removed,
/// or why it could not be.
fn leftovers_in(folder: &Path) -> Vec<Result<PathBuf, String>> {
    let Ok(entries) = fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        if !is_restore(&entry.file_name()) {
            continue;
        }
        let path = entry.path();
        let Some(held) = leftover(&path) else {
            continue;
        };
        // `remove_dir_all` follows no link inside the folder.
        removed.push(match fs::remove_dir_all(&path) {
            Ok(()) => Ok(path),
            Err(error) => Err(not_removed(&path, &error)),
        });
        drop(held);
    }
    removed
}

/// Remove what interrupted restores left in `/var/tmp`.
fn leftovers() -> Vec<Result<PathBuf, String>> {
    leftovers_in(Path::new(RESTORES))
}

fn not_removed(path: &Path, error: &std::io::Error) -> String {
    format!(
        "{} could not be removed ({error}); it holds a copy of what the backup holds: \
         remove it as root with rm -r {}",
        path.display(),
        path.display()
    )
}

/// The test restore of `path` as a run makes it: what interrupted restores
/// left goes first, since it is mail on disk that nobody looks at, then the
/// restore; each said as it happens. The restore's result, and whether
/// something failed, a copy that could not be removed among it.
pub(super) fn tested(repository: &Repository, path: &str, newest: Option<&str>) -> (Run, bool) {
    let mut failed = false;
    for removed in leftovers() {
        match removed {
            Ok(copy) => say(&format!(
                "Removed {}, a copy of restored data that an interrupted test restore left.",
                copy.display()
            )),
            Err(why) => {
                complain(&format!(
                    "A copy that an interrupted test restore left: {why}"
                ));
                failed = true;
            }
        }
    }
    let (run, left) = repository.restore(path, newest);
    say(&format!(
        "Restore test: {} ({})",
        if run.ok { "passed" } else { "FAILED" },
        run.detail
    ));
    if let Some(why) = left {
        complain(&format!("This test restore's copy: {why}"));
        failed = true;
    }
    failed |= !run.ok;
    (run, failed)
}

impl Repository {
    /// Restore `path` from the newest snapshot into a directory of its own,
    /// count what arrived and remove it again; and why the directory could
    /// not be removed, where it could not.
    fn restore(&self, path: &str, newest: Option<&str>) -> (Run, Option<String>) {
        let at = now();
        let failed = |detail: String| Run {
            at: at.clone(),
            ok: false,
            detail,
        };
        let (directory, held) = match restore_directory() {
            Ok(made) => made,
            Err(error) => return (failed(error), None),
        };
        let ran = match self.tool {
            Tool::Restic => {
                let target = directory.display().to_string();
                let mut arguments = self.restic();
                arguments.extend([
                    "restore",
                    "latest",
                    "--no-lock",
                    "--target",
                    &target,
                    "--include",
                    path,
                ]);
                run(self.tool, &arguments, None)
            }
            Tool::Borg => match newest {
                Some(newest) => {
                    // borg restores into the directory it runs in, and names
                    // paths without their first slash.
                    let archive = self.borg(Some(newest));
                    run(
                        self.tool,
                        &["extract", &archive, path.trim_start_matches('/')],
                        Some(&directory),
                    )
                }
                None => Ran {
                    ok: false,
                    stdout: String::new(),
                    last: "the repository has no archive".to_owned(),
                },
            },
        };
        let (files, bytes) = restored(&directory);
        let left = fs::remove_dir_all(&directory)
            .err()
            .map(|error| not_removed(&directory, &error));
        drop(held);
        if !ran.ok {
            return (failed(ran.last), left);
        }
        if files == 0 {
            return (
                failed(format!(
                    "{path} was not in the newest snapshot: nothing was restored"
                )),
                left,
            );
        }
        let restored = Run {
            at,
            ok: true,
            detail: format!("{path}: {files} files, {bytes} bytes"),
        };
        (restored, left)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    #[test]
    fn what_a_restore_brought_is_counted_without_following_links() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("data/mail")).unwrap();
        fs::write(directory.path().join("data/mail/a.txt"), "hello\n").unwrap();
        fs::write(directory.path().join("data/b.bin"), [0u8; 100]).unwrap();
        symlink("/etc", directory.path().join("data/link")).unwrap();
        assert_eq!(restored(directory.path()), (2, 106));
        assert_eq!(restored(&directory.path().join("missing")), (0, 0));
    }

    /// A folder of a restore's name in `folder`, with a copy of a mail in
    /// it, last changed `age` ago, or ahead of the clock.
    fn left(folder: &Path, hex: &str, age: Duration, ahead: bool) -> PathBuf {
        let path = folder.join(format!("{PREFIX}{hex}"));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        fs::create_dir_all(path.join("var/vmail")).unwrap();
        fs::write(path.join("var/vmail/inbox"), "A copy of a mail.\n").unwrap();
        let changed = if ahead {
            SystemTime::now() + age
        } else {
            SystemTime::now() - age
        };
        File::open(&path).unwrap().set_modified(changed).unwrap();
        path
    }

    /// What interrupted restores left goes, and nothing else of that name:
    /// not a run that has just made its folder or restores now, not a
    /// folder dated ahead of the clock, a link, a file or another name.
    #[test]
    fn a_restore_takes_away_what_interrupted_ones_left_and_nothing_else() {
        let folder = tempfile::tempdir().unwrap();
        let hours = Duration::from_hours(2);
        let stale = left(folder.path(), "00000000000000a1", hours, false);
        let fresh = left(folder.path(), "00000000000000a2", Duration::ZERO, false);
        let held = left(folder.path(), "00000000000000a3", hours, false);
        let holding = opened(&held).unwrap();
        rustix::fs::flock(&holding, FlockOperation::LockExclusive).unwrap();
        let ahead = left(folder.path(), "00000000000000a4", hours, true);
        let elsewhere = tempfile::tempdir().unwrap();
        fs::write(elsewhere.path().join("inbox"), "Not a restore's.\n").unwrap();
        let link = folder.path().join(format!("{PREFIX}00000000000000a5"));
        symlink(elsewhere.path(), &link).unwrap();
        let file = folder.path().join(format!("{PREFIX}00000000000000a6"));
        fs::write(&file, "Not a restore's.\n").unwrap();
        let named = left(folder.path(), "00000000000000a7", hours, false);
        let other = folder.path().join(format!("{PREFIX}manual"));
        fs::rename(&named, &other).unwrap();
        let upper = left(folder.path(), "00000000000000a8", hours, false);
        let shouting = folder.path().join(format!("{PREFIX}00000000000000A8"));
        fs::rename(&upper, &shouting).unwrap();

        assert_eq!(leftovers_in(folder.path()), [Ok(stale.clone())]);
        assert!(!stale.exists());
        for kept in [&fresh, &held, &ahead, &other, &shouting] {
            assert!(kept.join("var/vmail/inbox").exists(), "{}", kept.display());
        }
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(elsewhere.path().join("inbox").exists());
        assert!(file.is_file());
        // Once the run that held it has ended, it goes too.
        drop(holding);
        assert_eq!(leftovers_in(folder.path()), [Ok(held.clone())]);
        assert_eq!(leftovers_in(folder.path()), []);
    }

    /// A copy that cannot be removed is named, with how to remove it, since
    /// it holds what the backup holds.
    #[test]
    fn a_copy_that_cannot_be_removed_is_named() {
        // Root removes what the mode says it may not.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let folder = tempfile::tempdir().unwrap();
        let stuck = left(
            folder.path(),
            "00000000000000b1",
            Duration::from_secs(7200),
            false,
        );
        let inner = stuck.join("var");
        fs::set_permissions(&inner, fs::Permissions::from_mode(0o555)).unwrap();
        File::open(&stuck)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_hours(2))
            .unwrap();
        let said = leftovers_in(folder.path());
        fs::set_permissions(&inner, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(said.len(), 1);
        let why = said[0].clone().unwrap_err();
        assert!(
            why.starts_with(&format!("{} could not be removed (", stuck.display()))
                && why.ends_with(&format!(
                    "it holds a copy of what the backup holds: remove it as root with rm -r {}",
                    stuck.display()
                )),
            "{why}"
        );
    }
}
