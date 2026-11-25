//! A rebuilt copy of the status database put in its place. The copy is made
//! beside the database, so that one rename puts it there and a power cut
//! leaves either file whole; it has the database's mode, owner, group and
//! SELinux label before SQLite writes to it, and is on disk before the
//! rename. A reader that opened the database reads that file to its end,
//! and the next one opens the copy: nobody waits for the rebuild.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, fchown};
use std::path::{Path, PathBuf};

use rustix::fs::XattrFlags;
use rustix::io::Errno;

/// The attribute that holds a file's SELinux label.
const LABEL: &str = "security.selinux";

/// Where the copy of the database at `path` is made: beside it, with a name
/// that begins like the names of its journals, which the installer removes
/// with it.
pub(super) fn copy_of(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push("-clearing");
    path.with_file_name(name)
}

/// Remove a copy at `copy`, as a run that was ended leaves one, with a
/// journal of its own; unlinking follows no link.
pub(super) fn remove(copy: &Path) {
    let mut journal = copy.as_os_str().to_owned();
    journal.push("-journal");
    for file in [copy, Path::new(&journal)] {
        let _ = fs::remove_file(file);
    }
}

/// An empty file at `copy`, made as the file at `path` is.
pub(super) fn made_like(path: &Path, copy: &Path) -> io::Result<()> {
    made_with(path, copy, LABEL)
}

/// An empty file at `copy` with the mode, owner and group of the file at
/// `path`, and its value of `attribute` where it has one.
pub(super) fn made_with(path: &Path, copy: &Path, attribute: &str) -> io::Result<()> {
    let live = File::open(path)?;
    let metadata = live.metadata()?;
    let mode = metadata.mode() & 0o7777;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(copy)?;
    // The umask may take bits away, and root, running it by hand, makes the
    // file its own.
    let fresh = file.metadata()?;
    let wanted = (metadata.uid(), metadata.gid());
    if let Some((owner, group)) = owner_to_give((fresh.uid(), fresh.gid()), wanted) {
        fchown(&file, Some(owner), Some(group))?;
    }
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    // A new file gets the label the policy gives the folder's, which is the
    // database's unless someone relabelled that.
    if let Some(label) = attribute_of(&live, attribute)?
        && attribute_of(&file, attribute)?.as_ref() != Some(&label)
    {
        rustix::fs::fsetxattr(&file, attribute, &label, XattrFlags::empty())?;
    }
    Ok(())
}

/// The owner and group to give a file made with `made`, where the database
/// has `wanted`: none where they are the same already. The collector's unit
/// makes the copy with the database's own (`User=`, `Group=`) and filters
/// the call that would change them, with every other one a service has no
/// business with (`SystemCallFilter=~@privileged`), and a call it filters
/// ends the collector. Root, running a collection by hand, makes the file
/// its own and may give it away.
pub(super) fn owner_to_give(made: (u32, u32), wanted: (u32, u32)) -> Option<(u32, u32)> {
    (made != wanted).then_some(wanted)
}

/// The value of `name` on `file`; `None` where it has none, or the file
/// system keeps no such attributes.
pub(super) fn attribute_of(file: &File, name: &str) -> io::Result<Option<Vec<u8>>> {
    let mut value = [0; 1024];
    match rustix::fs::fgetxattr(file, name, &mut value[..]) {
        Ok(length) => Ok(Some(value[..length].to_vec())),
        Err(Errno::NODATA | Errno::NOTSUP) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Put the copy at `copy` in the place of the database at `path`: the copy
/// on disk first, then the rename, then the folder that records it.
pub(super) fn put_in_place(copy: &Path, path: &Path) -> io::Result<()> {
    File::open(copy)?.sync_all()?;
    fs::rename(copy, path)?;
    let folder = path
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(folder)?.sync_all()
}
