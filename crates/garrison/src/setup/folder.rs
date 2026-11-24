//! The credentials directory, where setup writes the secrets of the keys
//! and credentials it makes.

use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use garrison_core::files::atomic_write;
use rustix::fs::Access;

use super::states;
use crate::state::State;

pub(super) fn write_secret(path: &Path, value: &str) -> Result<(), State> {
    atomic_write(path, format!("{value}\n").as_bytes(), 0o600)
        .map_err(|error| states::unwritten(path, error))
}

/// What a write that did not end left in `directory`: `atomic_write`
/// writes a new file under a name of its own, `.pending-` and a random
/// part, and renames it, so a run killed in between leaves it, with a
/// secret or part of one, and nothing else removes it.
pub(super) fn sweep(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let pending = name
            .to_str()
            .is_some_and(|name| name.starts_with(".pending-"));
        if pending && entry.file_type().is_ok_and(|kind| kind.is_file()) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Before anything changes: setup writes the keys that Stalwart makes to
/// the credentials directory, so it must take new files there, or a key
/// would be made whose secret is lost. The installer makes it root's and
/// 0700, so another user may not even look into it. The exit code goes
/// with the state: 2 for a run without root, which was called wrongly;
/// with root, it names `again` as the run that mends it.
pub(super) fn writable(directory: &Path, again: &str) -> Result<(), (u8, State)> {
    let checked = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .and_then(|()| {
            rustix::fs::access(directory, Access::WRITE_OK | Access::EXEC_OK)
                .map_err(io::Error::from)
        });
    let Err(error) = checked else {
        return Ok(());
    };
    if error.kind() == io::ErrorKind::PermissionDenied && !rustix::process::geteuid().is_root() {
        return Err((2, states::not_root(directory, error)));
    }
    Err((1, states::folder_unwritable(directory, error, again)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a write that did not end left goes; the secrets' files, and a
    /// folder or a link of such a name, stay.
    #[test]
    fn what_an_interrupted_write_left_goes() {
        let directory = tempfile::tempdir().unwrap();
        let path = |name: &str| directory.path().join(name);
        std::fs::write(path(".pending-a1B2c3"), "part of a key").unwrap();
        std::fs::write(path("broker-native-key"), "a key").unwrap();
        std::fs::create_dir(path(".pending-folder")).unwrap();
        std::os::unix::fs::symlink(path("broker-native-key"), path(".pending-link")).unwrap();
        sweep(directory.path());
        let mut left: Vec<String> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [".pending-folder", ".pending-link", "broker-native-key"]
        );
    }
}
