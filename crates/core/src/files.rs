//! Bounded file reads, protected files and atomic writes.
//!
//! Files are opened without following symbolic links and without blocking on a
//! FIFO; only regular files are read, and never more than a fixed size.

use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use serde_json::Value;

use crate::json::{self, JsonError};

#[derive(Debug, thiserror::Error)]
pub enum ProtectedFileError {
    #[error("Protected file is unavailable: {}", .0.display())]
    Unavailable(PathBuf),
    #[error("Protected file permissions are not private: {}", .0.display())]
    NotPrivate(PathBuf),
    #[error("Protected file permissions are too open: {}", .0.display())]
    TooOpen(PathBuf),
    #[error("Protected file is too large: {}", .0.display())]
    TooLarge(PathBuf),
    #[error("Protected file is not valid JSON: {}", .0.display())]
    InvalidJson(PathBuf),
    #[error("Protected secret has an invalid format: {}", .0.display())]
    InvalidSecret(PathBuf),
}

/// Who may read a private file besides its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privacy {
    /// An ordinary file: owned by this user, no access for group or others.
    Owned,
    /// A systemd credential of a non-root service: root-owned with an ACL for
    /// the service user, so only "no access for others" can be required.
    SystemdCredential,
}

fn open_regular(path: &Path) -> io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = File::from(rustix::fs::open(path, flags, Mode::empty())?);
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(file)
}

/// Read at most `limit` bytes; a longer file is an error, not a truncated read.
fn read_limited(file: File, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut data = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut data)?;
    Ok((data.len() <= limit).then_some(data))
}

/// Read a regular file of at most `limit` bytes, never following symbolic links.
pub fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    read_limited(open_regular(path)?, limit)?
        .ok_or_else(|| io::Error::other("file exceeds its size limit"))
}

/// Return parsed JSON, or `None` when the file is absent, unreadable or invalid.
///
/// Collectors use this for optional observations: an unreadable source becomes
/// an Unknown observation instead of an error that hides every other result.
pub fn read_json(path: &Path, limit: usize) -> Option<Value> {
    json::parse(&read_bounded(path, limit).ok()?, limit).ok()
}

/// [`read_json`] with the metadata of the file that was read, so that a check
/// of who can change it applies to these very bytes.
pub fn read_json_with_metadata(path: &Path, limit: usize) -> Option<(Value, Metadata)> {
    let file = open_regular(path).ok()?;
    let metadata = file.metadata().ok()?;
    let data = read_limited(file, limit).ok()??;
    Some((json::parse(&data, limit).ok()?, metadata))
}

/// Whether only root or this process's own user can have changed a file:
/// owned by one of them, not writable by others, and writable by its group
/// only when that group is root.
pub fn changed_only_by_trusted(metadata: &Metadata) -> bool {
    let mode = metadata.mode();
    [0, effective_uid()].contains(&metadata.uid())
        && mode & 0o002 == 0
        && (mode & 0o020 == 0 || metadata.gid() == 0)
}

fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Read a secret that no other user can read.
pub fn read_private(
    path: &Path,
    limit: usize,
    privacy: Privacy,
) -> Result<Vec<u8>, ProtectedFileError> {
    let file = open_regular(path).map_err(|_| ProtectedFileError::Unavailable(path.into()))?;
    let info = file
        .metadata()
        .map_err(|_| ProtectedFileError::Unavailable(path.into()))?;
    let private = match privacy {
        Privacy::Owned => info.uid() == effective_uid() && info.mode() & 0o077 == 0,
        Privacy::SystemdCredential => info.mode() & 0o007 == 0,
    };
    if !private {
        return Err(ProtectedFileError::NotPrivate(path.into()));
    }
    read_limited(file, limit)
        .map_err(|_| ProtectedFileError::Unavailable(path.into()))?
        .ok_or_else(|| ProtectedFileError::TooLarge(path.into()))
}

/// Read a single-line secret such as an API key or an HMAC key.
pub fn read_secret(path: &Path, privacy: Privacy) -> Result<String, ProtectedFileError> {
    let data = read_private(path, 16384, privacy)?;
    let invalid = || ProtectedFileError::InvalidSecret(path.into());
    let text = std::str::from_utf8(&data).map_err(|_| invalid())?.trim();
    let printable = text.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
    if !(16..=8192).contains(&text.len()) || !printable {
        return Err(invalid());
    }
    Ok(text.to_owned())
}

/// Read an authorization file that only root (or this user) can change.
///
/// The access policy is owned by root and readable by the broker's group. It must
/// not be writable by anyone else or readable by every local user.
pub fn read_protected(path: &Path, limit: usize) -> Result<Value, ProtectedFileError> {
    let file = open_regular(path).map_err(|_| ProtectedFileError::Unavailable(path.into()))?;
    let info = file
        .metadata()
        .map_err(|_| ProtectedFileError::Unavailable(path.into()))?;
    if ![0, effective_uid()].contains(&info.uid()) || info.mode() & 0o026 != 0 {
        return Err(ProtectedFileError::TooOpen(path.into()));
    }
    let mut data = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| ProtectedFileError::Unavailable(path.into()))?;
    // A file over its limit is said to be too large, not to be no JSON: the
    // operator would look for a mistake in a file that has none.
    json::parse(&data, limit).map_err(|error| match error {
        JsonError::TooLarge => ProtectedFileError::TooLarge(path.into()),
        JsonError::Invalid(_) => ProtectedFileError::InvalidJson(path.into()),
    })
}

/// Replace a file atomically and durably; readers never see a partial file.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(directory)?;
    let mut pending = tempfile::Builder::new()
        .prefix(".pending-")
        .tempfile_in(directory)?;
    pending
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    pending.write_all(data)?;
    pending.as_file().sync_all()?;
    pending.persist(path).map_err(|error| error.error)?;
    File::open(directory)?.sync_all()
}

#[cfg(test)]
mod tests;
