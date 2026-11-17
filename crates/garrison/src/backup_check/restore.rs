//! The test restore: the newest snapshot's copy of a path, restored into a
//! directory of its own, counted and removed again.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use garrison_collector::backups::{Run, Tool};

use super::{Ran, Repository, now, run};

/// Restores go to disk, not into `/tmp`, which may be memory.
const RESTORES: &str = "/var/tmp";

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

/// A directory of its own for one restore, readable by root alone.
fn restore_directory() -> Result<PathBuf, String> {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|error| error.to_string())?;
    let name = garrison_core::hex::encode(&random);
    let path = Path::new(RESTORES).join(format!("garrison-restore-{name}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

impl Repository {
    /// Restore `path` from the newest snapshot into a directory of its own,
    /// count what arrived and remove it again.
    pub(super) fn restore(&self, path: &str, newest: Option<&str>) -> Run {
        let at = now();
        let failed = |detail: String| Run {
            at: at.clone(),
            ok: false,
            detail,
        };
        let directory = match restore_directory() {
            Ok(directory) => directory,
            Err(error) => return failed(error),
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
        let _ = fs::remove_dir_all(&directory);
        if !ran.ok {
            return failed(ran.last);
        }
        if files == 0 {
            return failed(format!(
                "{path} was not in the newest snapshot: nothing was restored"
            ));
        }
        Run {
            at,
            ok: true,
            detail: format!("{path}: {files} files, {bytes} bytes"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_a_restore_brought_is_counted_without_following_links() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("data/mail")).unwrap();
        fs::write(directory.path().join("data/mail/a.txt"), "hello\n").unwrap();
        fs::write(directory.path().join("data/b.bin"), [0u8; 100]).unwrap();
        std::os::unix::fs::symlink("/etc", directory.path().join("data/link")).unwrap();
        assert_eq!(restored(directory.path()), (2, 106));
        assert_eq!(restored(&directory.path().join("missing")), (0, 0));
    }
}
