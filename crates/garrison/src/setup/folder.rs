//! The credentials directory, where setup writes the secrets of the keys
//! and credentials it makes.

use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use garrison_core::files::atomic_write;
use rustix::fs::Access;

pub(super) fn write_secret(path: &Path, value: &str) -> Result<(), String> {
    atomic_write(path, format!("{value}\n").as_bytes(), 0o600)
        .map_err(|error| format!("Could not write {}: {error}", path.display()))
}

/// Before anything changes: setup writes the keys that Stalwart makes to
/// the credentials directory, so it must take new files there, or a key
/// would be made whose secret is lost. The installer makes it root's and
/// 0700, so another user may not even look into it. The exit code goes
/// with the message: 2 for a run without root, which was called wrongly.
pub(super) fn writable(directory: &Path) -> Result<(), (u8, String)> {
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
    let refused = format!(
        "Setup cannot write the credentials folder {}: {error}.",
        directory.display()
    );
    if error.kind() == io::ErrorKind::PermissionDenied && !rustix::process::geteuid().is_root() {
        return Err((
            2,
            format!(
                "{refused} Run it as root, as `sudo garrison stalwart setup`; nothing was changed."
            ),
        ));
    }
    Err((
        1,
        format!(
            "{refused} Nothing was changed; run `garrison stalwart setup` again once this is \
             mended."
        ),
    ))
}
