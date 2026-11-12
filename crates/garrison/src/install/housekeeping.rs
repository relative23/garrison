//! Old releases and backups, removed after a successful installation so that
//! years of upgrades do not fill the disk. Only the installer's own entries
//! are considered, links are never followed, and a failure only warns: the
//! installation itself has succeeded.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The running release, the previous one and one older.
const RELEASES: usize = 3;
/// Backups kept besides the one `--rollback --restore-state` returns to.
const BACKUPS: usize = 3;

/// Remove what is no longer kept; returns a line for each removal.
pub(super) fn prune(base: &Path, backups: &Path, last: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    for path in old_releases(base) {
        lines.push(remove(&path, "release"));
    }
    for path in old_backups(backups, last) {
        lines.push(remove(&path, "backup"));
    }
    lines
}

fn remove(path: &Path, what: &str) -> String {
    match fs::remove_dir_all(path) {
        Ok(()) => format!("Removed the old {what} {}", path.display()),
        Err(error) => format!(
            "Could not remove the old {what} {}: {error}",
            path.display()
        ),
    }
}

/// Directories that are neither links nor hidden (an interrupted run's trees).
fn directories(parent: &Path) -> Vec<PathBuf> {
    fs::read_dir(parent)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| !entry.file_name().as_encoded_bytes().starts_with(b"."))
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .collect()
}

fn installed_at(path: &Path) -> SystemTime {
    fs::symlink_metadata(path)
        .and_then(|metadata| metadata.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// Releases beyond `current`, `previous` and the newest others up to RELEASES.
fn old_releases(base: &Path) -> Vec<PathBuf> {
    let kept: Vec<PathBuf> = ["current", "previous"]
        .iter()
        .filter_map(|link| fs::canonicalize(base.join(link)).ok())
        .collect();
    let mut others: Vec<PathBuf> = directories(&base.join("releases"))
        .into_iter()
        .filter(|path| !kept.contains(path))
        .collect();
    others.sort_by_key(|path| std::cmp::Reverse(installed_at(path)));
    others
        .into_iter()
        .skip(RELEASES.saturating_sub(kept.len()))
        .collect()
}

/// The installer's backups beyond the newest BACKUPS, never the one `last`
/// points to. `garrison backup --to` targets of the operator's own are kept.
fn old_backups(backups: &Path, last: &Path) -> Vec<PathBuf> {
    let restore = fs::canonicalize(last).ok();
    let stamp = |path: &PathBuf| -> Option<String> {
        let name = path.file_name()?.to_str()?;
        let stamp = name
            .strip_prefix("pre-upgrade-")
            .or_else(|| name.strip_prefix("pre-reinstall-"))?;
        let digits = stamp.chars().filter(char::is_ascii_digit).count();
        (stamp.len() == 15 && digits == 14 && stamp.as_bytes()[8] == b'T').then(|| stamp.to_owned())
    };
    let mut ours: Vec<(String, PathBuf)> = directories(backups)
        .into_iter()
        .filter_map(|path| Some((stamp(&path)?, path)))
        .collect();
    ours.sort_by(|left, right| right.0.cmp(&left.0));
    ours.into_iter()
        .skip(BACKUPS)
        .map(|(_, path)| path)
        .filter(|path| Some(path) != restore.as_ref())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::time::Duration;

    use super::*;

    fn set_age(path: &Path, seconds_ago: u64) {
        let file = fs::File::open(path).unwrap();
        let time = SystemTime::now() - Duration::from_secs(seconds_ago);
        file.set_modified(time).unwrap();
    }

    #[test]
    fn the_running_the_previous_and_one_older_release_stay() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        for (age, version) in [
            (50, "0.1"),
            (40, "0.2"),
            (30, "0.3"),
            (20, "0.4"),
            (10, "0.5"),
        ] {
            let path = base.join("releases").join(version);
            fs::create_dir_all(&path).unwrap();
            set_age(&path, age);
        }
        fs::create_dir(base.join("releases/.staging")).unwrap();
        // A rollback made 0.4 current and 0.5 previous.
        symlink(base.join("releases/0.4"), base.join("current")).unwrap();
        symlink(base.join("releases/0.5"), base.join("previous")).unwrap();
        let mut removed = old_releases(base);
        removed.sort();
        assert_eq!(
            removed,
            [base.join("releases/0.1"), base.join("releases/0.2")]
        );
        // Without a previous release, two older ones stay.
        fs::remove_file(base.join("previous")).unwrap();
        assert_eq!(old_releases(base).len(), 2);
    }

    #[test]
    fn three_backups_stay_besides_the_one_a_rollback_restores() {
        let directory = tempfile::tempdir().unwrap();
        let backups = directory.path();
        for name in [
            "pre-upgrade-20261028T100000",
            "pre-reinstall-20261029T100000",
            "pre-upgrade-20261030T064159",
            "pre-upgrade-20261030T112756",
            "pre-upgrade-20261030T132151",
            "latest",
            "pre-upgrade-yesterday",
        ] {
            fs::create_dir(backups.join(name)).unwrap();
        }
        let last = backups.join("last-pre-upgrade");
        symlink(backups.join("pre-upgrade-20261028T100000"), &last).unwrap();
        let lines = prune(&directory.path().join("no-base"), backups, &last);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(!backups.join("pre-reinstall-20261029T100000").exists());
        for kept in [
            "pre-upgrade-20261028T100000",
            "pre-upgrade-20261030T064159",
            "pre-upgrade-20261030T112756",
            "pre-upgrade-20261030T132151",
            "latest",
            "pre-upgrade-yesterday",
        ] {
            assert!(backups.join(kept).is_dir(), "{kept}");
        }
    }
}
