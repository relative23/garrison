//! Replacing the configuration file the way an operator's edit would: owner
//! and mode stay, the old text stays next to it as `<file>.previous`, and each
//! file is written atomically. Callers check that the new text loads first.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use garrison_core::files::atomic_write;

/// Write `updated` over `path`, whose text was `current`; returns where the
/// previous text went.
pub(crate) fn replace(path: &Path, current: &str, updated: &str) -> Result<PathBuf, String> {
    let failed = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
    let metadata = fs::metadata(path).map_err(|error| failed(&error))?;
    let mode = metadata.permissions().mode() & 0o7777;
    let owner = (
        Some(rustix::fs::Uid::from_raw(metadata.uid())),
        Some(rustix::fs::Gid::from_raw(metadata.gid())),
    );
    let place = |target: &Path, data: &str| -> Result<(), String> {
        atomic_write(target, data.as_bytes(), mode).map_err(|error| failed(&error))?;
        // A group that may read the file keeps reading it.
        rustix::fs::chown(target, owner.0, owner.1).map_err(|error| failed(&error))
    };
    let previous = PathBuf::from(format!("{}.previous", path.display()));
    place(&previous, current)?;
    place(path, updated)?;
    Ok(previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_old_text_stays_and_the_mode_is_kept() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("garrison.toml");
        fs::write(&path, "old\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let previous = replace(&path, "old\n", "new\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
        assert_eq!(fs::read_to_string(previous).unwrap(), "old\n");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
}
