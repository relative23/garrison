//! The policy's folder, where `garrison access` keeps the policy, its lock
//! and its backups.
//!
//! Root runs the command, and `broker.policy` may name a folder that other
//! users can write to. So every file in it is reached from the folder's own
//! descriptor by its name: no link there is followed, nothing that is there
//! is written over or taken for the command's own (a lock is one only where
//! the command's user owns it under that one name), the policy is read no
//! further than a policy can be, and owner and mode are set on the file the
//! command made before it takes the policy's name.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use garrison_core::time;
use rustix::fs::{AtFlags, CWD, FlockOperation, Gid, Mode, OFlags, Uid};
use rustix::io::Errno;

/// As much of the policy as the broker reads: a larger file is no policy.
pub(super) const MAX_POLICY: usize = 65536;

/// What mends a policy larger than the broker reads, which is no policy:
/// a way out that is always there, and one where a backup is.
pub(crate) fn way_out(path: &Path) -> String {
    format!(
        "move it away and run `garrison access init`, or copy back the newest backup beside it \
         ({}.<time>.bak) with sudo cp where there is one",
        path.display()
    )
}

/// What every command says of a policy larger than the broker reads.
pub(crate) fn too_large(path: &Path) -> String {
    format!(
        "The access policy {} is larger than the broker reads ({} KiB), so it is no policy: {}.",
        path.display(),
        MAX_POLICY / 1024,
        way_out(path)
    )
}

/// What is at the policy's name.
pub(super) enum Current {
    Missing,
    /// A regular file.
    File,
    /// A link, a folder or anything else that is no file of its own.
    Other,
}

/// `path` and what went wrong with it, and for an operator who is not root
/// that the command is root's.
pub(super) fn failed(path: &Path, error: impl Into<io::Error>) -> String {
    let error: io::Error = error.into();
    let root = rustix::process::geteuid().is_root();
    let denied = error.kind() == io::ErrorKind::PermissionDenied;
    let hint = if denied && !root {
        "; run `garrison access` as root"
    } else {
        ""
    };
    format!("{}: {error}{hint}", path.display())
}

/// The folder `broker.policy` names, opened.
pub(super) struct Folder {
    descriptor: OwnedFd,
    path: PathBuf,
    /// The policy's own name in it.
    name: OsString,
}

const FOLDER: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

impl Folder {
    /// The folder of `policy`; made where `make` and it is missing.
    pub(super) fn open(policy: &Path, make: bool) -> Result<Folder, String> {
        let (Some(name), Some(parent)) = (policy.file_name(), policy.parent()) else {
            return Err(format!("broker.policy names no file: {}", policy.display()));
        };
        let path = if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent.to_owned()
        };
        let descriptor = if make {
            made(&path)?
        } else {
            rustix::fs::open(&path, FOLDER, Mode::empty()).map_err(|error| {
                if error == Errno::NOENT {
                    missing(policy)
                } else {
                    failed(&path, error)
                }
            })?
        };
        Ok(Folder {
            descriptor,
            path,
            name: name.to_owned(),
        })
    }

    /// The path of the file `name` in the folder, as messages name it.
    fn at(&self, name: &OsString) -> PathBuf {
        self.path.join(name)
    }

    /// A name beside the policy's: its own with `before` and `after`.
    fn beside(&self, before: &str, after: &str) -> OsString {
        let mut name = OsString::from(before);
        name.push(&self.name);
        name.push(after);
        name
    }

    /// `<policy>.lock`, held until the file is dropped. A lock that is not a
    /// file of this command's, as a link, is refused and left as it is.
    pub(super) fn lock(&self) -> Result<File, String> {
        let name = self.beside("", ".lock");
        let path = self.at(&name);
        let flags =
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let opened = rustix::fs::openat(
            &self.descriptor,
            name.as_os_str(),
            flags,
            Mode::RUSR | Mode::WUSR,
        );
        let file = File::from(opened.map_err(|error| {
            if error == Errno::LOOP {
                format!(
                    "{} is a link, not the lock of `garrison access`: remove it, then run the \
                     command again.",
                    path.display()
                )
            } else {
                failed(&path, error)
            }
        })?);
        let status = rustix::fs::fstat(&file).map_err(|error| failed(&path, error))?;
        if rustix::fs::FileType::from_raw_mode(status.st_mode) != rustix::fs::FileType::RegularFile
        {
            return Err(format!(
                "{} is not a file, so not the lock of `garrison access`: remove it, then run \
                 the command again.",
                path.display()
            ));
        }
        // A file that another user put there, or that has another name too,
        // a hard link to a file elsewhere, is no lock of the command's:
        // taking it would change that file, and its owner could hold it.
        if status.st_uid != rustix::process::geteuid().as_raw() {
            return Err(format!(
                "{} is another user's file, not the lock of `garrison access`: remove it, then \
                 run the command again.",
                path.display()
            ));
        }
        if status.st_nlink != 1 {
            return Err(format!(
                "{} has another name too (a hard link), so it is not the lock of `garrison \
                 access`: remove it, then run the command again.",
                path.display()
            ));
        }
        // One that an earlier release made may be readable for others, and
        // a process that opened it then can hold it: it is not waited for.
        rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|error| failed(&path, error))?;
        match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(file),
            Err(Errno::WOULDBLOCK) => Err(format!(
                "{} is held by another process, as another `garrison access` command: try \
                 again once it has ended. Where none runs, remove the file and run the command \
                 again.",
                path.display()
            )),
            Err(error) => Err(failed(&path, error)),
        }
    }

    /// What is at the policy's name now, looked at without reading it.
    pub(super) fn current(&self) -> Result<Current, String> {
        let path = self.at(&self.name);
        let status = match rustix::fs::statat(
            &self.descriptor,
            self.name.as_os_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(status) => status,
            Err(Errno::NOENT) => return Ok(Current::Missing),
            Err(error) => return Err(failed(&path, error)),
        };
        let kind = rustix::fs::FileType::from_raw_mode(status.st_mode);
        Ok(if kind == rustix::fs::FileType::RegularFile {
            Current::File
        } else {
            Current::Other
        })
    }

    /// What the file at the policy's name holds, for its backup: read
    /// without following a link and no further than a policy can be, so
    /// that a larger file, which is no policy, is said to be one.
    pub(super) fn content(&self) -> Result<Vec<u8>, String> {
        let path = self.at(&self.name);
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let opened = rustix::fs::openat(
            &self.descriptor,
            self.name.as_os_str(),
            flags,
            Mode::empty(),
        );
        let file = File::from(opened.map_err(|error| failed(&path, error))?);
        if !file
            .metadata()
            .map_err(|error| failed(&path, error))?
            .is_file()
        {
            return Err(format!("{} is no file", path.display()));
        }
        let mut data = Vec::new();
        (&file)
            .take(MAX_POLICY as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|error| failed(&path, error))?;
        if data.len() > MAX_POLICY {
            return Err(too_large(&path));
        }
        Ok(data)
    }

    /// Keep `data`, the policy before a change, in a new backup beside it,
    /// readable by root alone: `<policy>.<time>.bak`, or with `-1`, `-2` …
    /// after the time where that name is taken.
    pub(super) fn back_up(&self, data: &[u8]) -> Result<PathBuf, String> {
        let stamp = time::now().strftime("%Y%m%dT%H%M%S").to_string();
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        for copy in 0..100 {
            let suffix = if copy == 0 {
                format!(".{stamp}.bak")
            } else {
                format!(".{stamp}-{copy}.bak")
            };
            let name = self.beside("", &suffix);
            let path = self.at(&name);
            let created = rustix::fs::openat(
                &self.descriptor,
                name.as_os_str(),
                flags,
                Mode::RUSR | Mode::WUSR,
            );
            let file = match created {
                Ok(file) => File::from(file),
                // Whatever has that name stays as it is.
                Err(Errno::EXIST) => continue,
                Err(error) => return Err(failed(&path, error)),
            };
            written(&file, data, Mode::RUSR | Mode::WUSR).map_err(|error| failed(&path, error))?;
            return Ok(path);
        }
        Err(format!(
            "No backup of {} could be kept: every name for one of this second is taken.",
            self.at(&self.name).display()
        ))
    }

    /// Put `data` in the policy's place: written to `.<policy>.pending`
    /// first, root's and readable by `group`, then renamed to the policy's
    /// name. Why the broker cannot read it, where the group could not be set.
    pub(super) fn replace(
        &self,
        data: &[u8],
        group: Option<Gid>,
    ) -> Result<Option<String>, String> {
        let pending = self.beside(".", ".pending");
        let path = self.at(&pending);
        // A file an interrupted run left there goes first, and a link put
        // there with it: unlink never follows one.
        match rustix::fs::unlinkat(&self.descriptor, pending.as_os_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(Errno::ISDIR) => {
                return Err(format!(
                    "{} is a folder, not the file `garrison access` writes the policy to first: \
                     remove it, then run the command again.",
                    path.display()
                ));
            }
            Err(error) => return Err(failed(&path, error)),
        }
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let created = rustix::fs::openat(
            &self.descriptor,
            pending.as_os_str(),
            flags,
            Mode::RUSR | Mode::WUSR,
        );
        let file = File::from(created.map_err(|error| failed(&path, error))?);
        let readable = Mode::RUSR | Mode::WUSR | Mode::RGRP;
        written(&file, data, readable).map_err(|error| failed(&path, error))?;
        let policy = self.at(&self.name);
        let note = match group {
            None => Some(format!(
                "Note: the broker cannot read {}: this host has no group garrison-broker. Run \
                 the installer, which makes the group and gives it the policy.",
                policy.display()
            )),
            Some(group) => rustix::fs::fchown(&file, Some(Uid::ROOT), Some(group))
                .err()
                .map(|error| {
                    format!(
                        "Note: the broker cannot read {}: it could not be made root's with the \
                         group garrison-broker ({error}). Run the command as root, or the \
                         installer again, which does.",
                        policy.display()
                    )
                }),
        };
        rustix::fs::renameat(
            &self.descriptor,
            pending.as_os_str(),
            &self.descriptor,
            self.name.as_os_str(),
        )
        .map_err(|error| failed(&policy, error))?;
        rustix::fs::fsync(&self.descriptor).map_err(|error| failed(&self.path, error))?;
        Ok(note)
    }
}

/// `data` in `file`, with `mode` whatever the umask, on the disk.
fn written(file: &File, data: &[u8], mode: Mode) -> io::Result<()> {
    rustix::fs::fchmod(file, mode)?;
    let mut file = file;
    file.write_all(data)?;
    file.sync_all()
}

/// What to say of a policy that is not there.
pub(super) fn missing(policy: &Path) -> String {
    format!(
        "The access policy {} is missing: `garrison access init` makes it.",
        policy.display()
    )
}

/// The folder `path`, with every folder up to it that is missing made as
/// /etc/garrison is: the command's user's, with mode 755 whatever the umask,
/// so that the broker reaches the policy in it. A folder that is made is
/// reached from the one it is made in, never through a link put in its place.
fn made(path: &Path) -> Result<OwnedFd, String> {
    let mut absent = Vec::new();
    let mut existing = path;
    loop {
        match std::fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                absent.push(existing);
                existing = match existing.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => parent,
                    _ => Path::new("."),
                };
            }
            Err(error) => return Err(failed(existing, error)),
        }
    }
    let mut folder = rustix::fs::openat(CWD, existing, FOLDER, Mode::empty())
        .map_err(|error| failed(existing, error))?;
    let shared = Mode::from_raw_mode(0o755);
    for path in absent.into_iter().rev() {
        let name = path.file_name().unwrap_or_default();
        let made = rustix::fs::mkdirat(&folder, name, shared);
        if let Err(error) = made
            && error != Errno::EXIST
        {
            return Err(failed(path, error));
        }
        let next = rustix::fs::openat(&folder, name, FOLDER | OFlags::NOFOLLOW, Mode::empty())
            .map_err(|error| failed(path, error))?;
        // One that someone else made meanwhile keeps its mode.
        if made.is_ok() {
            rustix::fs::fchmod(&next, shared).map_err(|error| failed(path, error))?;
        }
        folder = next;
    }
    Ok(folder)
}
