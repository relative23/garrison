//! The policy's folder, where `garrison access` keeps the policy, its lock
//! and its backups.
//!
//! Root runs the command, and `broker.policy` may name a folder that other
//! users can write to. So every file in it is reached from the folder's own
//! descriptor by its name: no link there is followed, nothing that is there
//! is written over, and owner and mode are set on the file the command made
//! before it takes the policy's name.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use garrison_core::time;
use rustix::fs::{AtFlags, FlockOperation, Gid, Mode, OFlags, Uid};
use rustix::io::Errno;

/// What is at the policy's name.
pub(super) enum Current {
    Missing,
    /// A regular file, with what it holds.
    File(Vec<u8>),
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
    /// The folder of `policy`.
    pub(super) fn open(policy: &Path) -> Result<Folder, String> {
        let (Some(name), Some(parent)) = (policy.file_name(), policy.parent()) else {
            return Err(format!("broker.policy names no file: {}", policy.display()));
        };
        let path = if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent.to_owned()
        };
        let descriptor = rustix::fs::open(&path, FOLDER, Mode::empty()).map_err(|error| {
            if error == Errno::NOENT {
                missing(policy)
            } else {
                failed(&path, error)
            }
        })?;
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
        if !file
            .metadata()
            .map_err(|error| failed(&path, error))?
            .is_file()
        {
            return Err(format!(
                "{} is not a file, so not the lock of `garrison access`: remove it, then run \
                 the command again.",
                path.display()
            ));
        }
        // A lock file someone else made would let them hold it: it becomes
        // this command's own.
        let owner = rustix::process::geteuid();
        if status.st_uid != owner.as_raw() {
            rustix::fs::fchown(&file, Some(owner), None).map_err(|error| failed(&path, error))?;
        }
        rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|error| failed(&path, error))?;
        rustix::fs::flock(&file, FlockOperation::LockExclusive)
            .map_err(|error| failed(&path, error))?;
        Ok(file)
    }

    /// What is at the policy's name now.
    pub(super) fn current(&self) -> Result<Current, String> {
        let path = self.at(&self.name);
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let file = match rustix::fs::openat(
            &self.descriptor,
            self.name.as_os_str(),
            flags,
            Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(Errno::NOENT) => return Ok(Current::Missing),
            Err(Errno::LOOP) => return Ok(Current::Other),
            Err(error) => return Err(failed(&path, error)),
        };
        if !file
            .metadata()
            .map_err(|error| failed(&path, error))?
            .is_file()
        {
            return Ok(Current::Other);
        }
        let mut data = Vec::new();
        (&file)
            .read_to_end(&mut data)
            .map_err(|error| failed(&path, error))?;
        Ok(Current::File(data))
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
