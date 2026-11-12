//! File operations of the installer: copies without foreign labels, atomic
//! links and swaps, the installer lock.

use std::fs::{self, File};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rustix::fs::{AtFlags, CWD, FlockOperation, Gid, Mode, OFlags, RenameFlags, Uid};

use crate::say;

pub(super) type Step<T = ()> = Result<T, String>;

pub(super) fn announce(message: &str) {
    say(&format!("==> {message}"));
}

pub(super) fn run(program: &str, arguments: &[&str]) -> Step<Output> {
    Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("{program}: {error}"))
}

/// Run and require success.
pub(super) fn must(program: &str, arguments: &[&str]) -> Step {
    let output = run(program, arguments)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

pub(super) fn io<T>(result: std::io::Result<T>, what: &Path) -> Step<T> {
    result.map_err(|error| format!("{}: {error}", what.display()))
}

/// Copy contents and permission bits only. Extended attributes, such as the
/// SELinux label of an extracted archive, are not copied: new files take the
/// label of their directory and `relabel` fixes files that already existed.
pub(super) fn place(source: &Path, target: &Path, mode: u32) -> Step {
    io(fs::copy(source, target), source)?;
    io(
        fs::set_permissions(target, fs::Permissions::from_mode(mode)),
        target,
    )
}

fn at<T>(result: rustix::io::Result<T>, what: &Path) -> Step<T> {
    result.map_err(|error| format!("{}: {error}", what.display()))
}

/// Replace `name` in `directory` with a copy of `source`, owned like the
/// directory and with `mode`.
///
/// Root runs this in a state directory that a service user owns, and that user
/// may have planted symbolic links there. So no path inside the directory is
/// resolved: the copy is a new file next to the target, owner and mode are set
/// on its descriptor, and a rename replaces whatever `name` was without
/// following it.
pub(super) fn replace_in(directory: &Path, name: &str, source: &Path, mode: u32) -> Step {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let folder = at(rustix::fs::open(directory, flags, Mode::empty()), directory)?;
    let owner = at(rustix::fs::fstat(&folder), directory)?;
    let pending = format!(".{name}.restoring");
    // A leftover or a planted link under that name goes first; unlink never follows it.
    match rustix::fs::unlinkat(&folder, pending.as_str(), AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(format!("{}/{pending}: {error}", directory.display())),
    }
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let created = rustix::fs::openat(&folder, pending.as_str(), flags, Mode::RUSR | Mode::WUSR);
    let mut file = File::from(at(created, directory)?);
    io(
        std::io::copy(&mut io(File::open(source), source)?, &mut file),
        source,
    )?;
    at(
        rustix::fs::fchmod(&file, Mode::from_raw_mode(mode)),
        directory,
    )?;
    let (uid, gid) = (Uid::from_raw(owner.st_uid), Gid::from_raw(owner.st_gid));
    at(rustix::fs::fchown(&file, Some(uid), Some(gid)), directory)?;
    io(file.sync_all(), directory)?;
    at(
        rustix::fs::renameat(&folder, pending.as_str(), &folder, name),
        directory,
    )?;
    at(rustix::fs::fsync(&folder), directory)
}

/// Copy a tree of the release. `verify` already refused anything but files and
/// directories; a link found here anyway is refused too, because root would
/// copy whatever it points to.
pub(super) fn copy_tree(source: &Path, target: &Path) -> Step {
    io(fs::create_dir_all(target), target)?;
    for entry in io(fs::read_dir(source), source)? {
        let entry = io(entry, source)?;
        let (from, to) = (entry.path(), target.join(entry.file_name()));
        let kind = io(fs::symlink_metadata(&from), &from)?;
        if kind.is_dir() {
            copy_tree(&from, &to)?;
        } else if kind.is_file() {
            place(&from, &to, (kind.permissions().mode() & 0o755) | 0o644)?;
        } else {
            return Err(format!("{} is not a regular file.", from.display()));
        }
    }
    Ok(())
}

/// Restore default SELinux labels where SELinux is in use.
pub(super) fn relabel(paths: &[PathBuf]) {
    if Path::new("/usr/sbin/restorecon").exists() {
        let mut arguments = vec!["-F".to_owned()];
        arguments.extend(paths.iter().map(|path| path.display().to_string()));
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let _ = run("/usr/sbin/restorecon", &arguments);
    }
}

/// Swap two directories in one step, so each name always holds a complete tree.
pub(super) fn exchange(one: &Path, two: &Path) -> Step {
    at(
        rustix::fs::renameat_with(CWD, one, CWD, two, RenameFlags::EXCHANGE),
        two,
    )
}

/// Held while an installer runs: a second one is refused, not queued. The
/// kernel releases the lock when its holder ends, however it ends.
pub(super) fn lock(path: &Path) -> Step<File> {
    let flags = OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = File::from(at(
        rustix::fs::open(path, flags, Mode::RUSR | Mode::WUSR),
        path,
    )?);
    // A lock file that someone created by hand, readable for others, would let
    // any user who opens it hold the lock and block every installation. Owner
    // and mode are set on the descriptor, so the file is the installer's own.
    let owner = rustix::process::geteuid();
    if at(rustix::fs::fstat(&file), path)?.st_uid != owner.as_raw() {
        at(rustix::fs::fchown(&file, Some(owner), None), path)?;
    }
    at(rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR), path)?;
    match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(
            "Another garrison install is already running; try again when it has finished.".into(),
        ),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Atomic: the link always points somewhere valid.
pub(super) fn switch(link: &Path, target: &Path) -> Step {
    let temporary = link.with_file_name(format!(
        "{}.new",
        link.file_name().unwrap_or_default().to_string_lossy()
    ));
    let _ = fs::remove_file(&temporary);
    io(symlink(target, &temporary), &temporary)?;
    io(fs::rename(&temporary, link), link)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_refuses_links_instead_of_copying_their_targets() {
        let directory = tempfile::tempdir().unwrap();
        let (source, target) = (
            directory.path().join("source"),
            directory.path().join("target"),
        );
        fs::create_dir_all(source.join("assets")).unwrap();
        fs::write(source.join("assets/app.js"), "app").unwrap();
        fs::write(directory.path().join("secret"), "secret").unwrap();
        copy_tree(&source, &target).unwrap();
        assert_eq!(
            fs::read_to_string(target.join("assets/app.js")).unwrap(),
            "app"
        );

        symlink(directory.path().join("secret"), source.join("assets/leak")).unwrap();
        let refused = copy_tree(&source, &directory.path().join("again")).unwrap_err();
        assert!(
            refused.ends_with("assets/leak is not a regular file."),
            "{refused}"
        );
        assert!(!directory.path().join("again/assets/leak").exists());
    }

    #[test]
    fn a_restore_replaces_planted_links_without_writing_through_them() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let (state, victim, copy) = (
            directory.path().join("state"),
            directory.path().join("victim"),
            directory.path().join("copy"),
        );
        fs::create_dir(&state).unwrap();
        fs::write(&victim, "keep").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&copy, "restored").unwrap();
        // The service user points both the target and the pending name elsewhere.
        symlink(&victim, state.join("web.sqlite")).unwrap();
        symlink(&victim, state.join(".web.sqlite.restoring")).unwrap();
        replace_in(&state, "web.sqlite", &copy, 0o600).unwrap();

        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o777, 0o644);
        let restored = fs::symlink_metadata(state.join("web.sqlite")).unwrap();
        assert!(restored.file_type().is_file());
        assert_eq!(restored.mode() & 0o777, 0o600);
        let folder = fs::metadata(&state).unwrap();
        assert_eq!(
            (restored.uid(), restored.gid()),
            (folder.uid(), folder.gid())
        );
        assert_eq!(
            fs::read_to_string(state.join("web.sqlite")).unwrap(),
            "restored"
        );
        assert!(fs::symlink_metadata(state.join(".web.sqlite.restoring")).is_err());

        // A state directory that is itself a link is refused.
        let link = directory.path().join("link");
        symlink(&state, &link).unwrap();
        assert!(replace_in(&link, "web.sqlite", &copy, 0o600).is_err());
    }

    #[test]
    fn one_installer_holds_the_lock_until_it_ends() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("install.lock");
        let held = lock(&path).unwrap();
        assert_eq!(
            lock(&path).unwrap_err(),
            "Another garrison install is already running; try again when it has finished."
        );
        drop(held);
        assert!(lock(&path).is_ok());
        // A lock file made by hand with a looser mode becomes the installer's own.
        let loose = directory.path().join("loose.lock");
        fs::write(&loose, "").unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
        let held = lock(&loose).unwrap();
        assert_eq!(
            fs::metadata(&loose).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(held);
        // A link planted under the lock's name is not followed.
        let link = directory.path().join("planted.lock");
        symlink(directory.path().join("elsewhere"), &link).unwrap();
        assert!(lock(&link).is_err());
        assert!(!directory.path().join("elsewhere").exists());
    }

    #[test]
    fn two_trees_swap_in_one_step() {
        let directory = tempfile::tempdir().unwrap();
        let (one, two) = (directory.path().join("one"), directory.path().join("two"));
        fs::create_dir(&one).unwrap();
        fs::create_dir(&two).unwrap();
        fs::write(one.join("marker"), "one").unwrap();
        fs::write(two.join("marker"), "two").unwrap();
        exchange(&one, &two).unwrap();
        assert_eq!(fs::read_to_string(one.join("marker")).unwrap(), "two");
        assert_eq!(fs::read_to_string(two.join("marker")).unwrap(), "one");
        assert!(exchange(&one, &directory.path().join("absent")).is_err());
    }

    #[test]
    fn links_switch_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let (one, two, link) = (
            directory.path().join("one"),
            directory.path().join("two"),
            directory.path().join("current"),
        );
        fs::create_dir(&one).unwrap();
        fs::create_dir(&two).unwrap();
        switch(&link, &one).unwrap();
        switch(&link, &two).unwrap();
        assert_eq!(fs::read_link(&link).unwrap(), two);
        assert!(!directory.path().join("current.new").exists());
    }
}
