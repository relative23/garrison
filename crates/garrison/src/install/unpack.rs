//! A release's tree in `/opt/garrison/releases`: unpacked from its archive,
//! and compared with it, so that a release unpacked already is not unpacked
//! again.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::BASE;
use super::files::{Step, announce, copy_tree, exchange, io, place};

/// Take away the hidden trees an interrupted run left in `releases`, and say
/// whether there were any.
pub(super) fn clear_staging(releases: &Path) -> Step<bool> {
    io(fs::create_dir_all(releases), releases)?;
    let mut cleared = false;
    for entry in io(fs::read_dir(releases), releases)?.flatten() {
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            let path = entry.path();
            let removed = if path.is_dir() && !path.is_symlink() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            io(removed, &path)?;
            cleared = true;
        }
    }
    Ok(cleared)
}

/// Whether `target` holds what `install_release` makes of `here`: the same
/// files with the same contents and modes, and nothing else.
pub(super) fn unpacked_as(here: &Path, target: &Path) -> bool {
    let names = |folder: &Path| {
        let mut names: Vec<OsString> = fs::read_dir(folder)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        names.sort();
        names
    };
    names(target) == ["VERSION", "bin", "share", "static"]
        && names(&target.join("bin")) == ["garrison"]
        && names(&target.join("share")) == ["deploy", "docs"]
        && same_file(
            &here.join("bin/garrison"),
            &target.join("bin/garrison"),
            0o755,
        )
        && same_file(&here.join("VERSION"), &target.join("VERSION"), 0o644)
        && [
            ("static", "static"),
            ("deploy", "share/deploy"),
            ("docs", "share/docs"),
        ]
        .into_iter()
        .all(|(from, to)| same_tree(&here.join(from), &target.join(to)))
}

/// Whether `to` holds the tree `copy_tree` makes of `from`.
fn same_tree(from: &Path, to: &Path) -> bool {
    let names = |folder: &Path| {
        let mut names: Vec<OsString> = fs::read_dir(folder)
            .ok()?
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        names.sort();
        Some(names)
    };
    let sources = names(from);
    fs::symlink_metadata(to).is_ok_and(|kind| kind.is_dir())
        && sources.is_some()
        && sources == names(to)
        && sources.iter().flatten().all(|name| {
            let (source, copy) = (from.join(name), to.join(name));
            match fs::symlink_metadata(&source) {
                Ok(kind) if kind.is_dir() => same_tree(&source, &copy),
                Ok(kind) if kind.is_file() => {
                    same_file(&source, &copy, (kind.permissions().mode() & 0o755) | 0o644)
                }
                _ => false,
            }
        })
}

/// Whether `to` is a file of mode `mode` that holds what `from` holds.
fn same_file(from: &Path, to: &Path, mode: u32) -> bool {
    fs::symlink_metadata(to)
        .is_ok_and(|kind| kind.is_file() && kind.permissions().mode() & 0o7777 == mode)
        && fs::read(from).is_ok_and(|wanted| fs::read(to).is_ok_and(|held| held == wanted))
}

/// Count `release` as installed now, as an unpack does: housekeeping keeps
/// the releases installed last, by their folder's time.
pub(super) fn installed_now(release: &Path) -> Step {
    let folder = io(fs::File::open(release), release)?;
    io(folder.set_modified(std::time::SystemTime::now()), release)
}

/// Unpack next to the target, then rename it into place: the release's name
/// only ever holds a complete tree, also the running one's on a reinstall.
pub(super) fn install_release(here: &Path, version: &str) -> Step<PathBuf> {
    let releases = Path::new(BASE).join("releases");
    let (target, staging) = (releases.join(version), releases.join(format!(".{version}")));
    announce(&format!("Creating {}", target.display()));
    io(fs::create_dir_all(staging.join("bin")), &staging)?;
    place(
        &here.join("bin/garrison"),
        &staging.join("bin/garrison"),
        0o755,
    )?;
    copy_tree(&here.join("static"), &staging.join("static"))?;
    copy_tree(&here.join("deploy"), &staging.join("share/deploy"))?;
    copy_tree(&here.join("docs"), &staging.join("share/docs"))?;
    place(&here.join("VERSION"), &staging.join("VERSION"), 0o644)?;
    if target.exists() {
        announce(&format!(
            "Release {version} was unpacked already; replacing it."
        ));
        exchange(&staging, &target)?;
        io(fs::remove_dir_all(&staging), &staging)?;
    } else {
        io(fs::rename(&staging, &target), &target)?;
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;

    /// A release made current again counts as installed now, as one just
    /// unpacked does, for housekeeping's order.
    #[test]
    fn a_release_made_current_counts_as_installed_now() {
        let directory = tempfile::tempdir().unwrap();
        let release = directory.path().join("0.2.0");
        fs::create_dir(&release).unwrap();
        let long_ago = SystemTime::now() - Duration::from_hours(720);
        fs::File::open(&release)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        installed_now(&release).unwrap();
        let age = fs::metadata(&release)
            .unwrap()
            .modified()
            .unwrap()
            .elapsed()
            .unwrap();
        assert!(age < Duration::from_secs(60), "{age:?}");
        assert!(installed_now(&directory.path().join("absent")).is_err());
    }

    /// A release is unpacked as its archive where every file it installs is
    /// there with the same contents and the installer's modes, and nothing
    /// else is; the archive's other files do not count.
    #[test]
    fn a_release_is_unpacked_as_its_archive_only_where_every_file_is() {
        let directory = tempfile::tempdir().unwrap();
        let (here, target) = (
            directory.path().join("archive"),
            directory.path().join("0.2.0"),
        );
        for (path, text) in [
            ("bin/garrison", "binary"),
            ("VERSION", "0.2.0\n"),
            ("static/index.html", "<p>"),
            ("static/assets/app.js", "app"),
            ("deploy/systemd/garrison-web.service", "[Unit]\n"),
            ("docs/operator/installation.md", "# Installation\n"),
            ("SHA256SUMS", "sums"),
        ] {
            fs::create_dir_all(here.join(path).parent().unwrap()).unwrap();
            fs::write(here.join(path), text).unwrap();
        }
        let unpack = || {
            let _ = fs::remove_dir_all(&target);
            fs::create_dir_all(target.join("bin")).unwrap();
            place(
                &here.join("bin/garrison"),
                &target.join("bin/garrison"),
                0o755,
            )
            .unwrap();
            place(&here.join("VERSION"), &target.join("VERSION"), 0o644).unwrap();
            copy_tree(&here.join("static"), &target.join("static")).unwrap();
            copy_tree(&here.join("deploy"), &target.join("share/deploy")).unwrap();
            copy_tree(&here.join("docs"), &target.join("share/docs")).unwrap();
        };
        assert!(!unpacked_as(&here, &target), "not unpacked yet");
        unpack();
        assert!(unpacked_as(&here, &target));
        let mode = |path: &str, mode: u32| {
            fs::set_permissions(target.join(path), fs::Permissions::from_mode(mode)).unwrap();
        };
        let changes: [&dyn Fn(); 5] = [
            &|| fs::write(target.join("static/assets/app.js"), "changed").unwrap(),
            &|| fs::write(target.join("static/extra.js"), "extra").unwrap(),
            &|| fs::remove_file(target.join("share/docs/operator/installation.md")).unwrap(),
            &|| mode("bin/garrison", 0o777),
            &|| fs::create_dir(target.join("share/other")).unwrap(),
        ];
        for (index, change) in changes.iter().enumerate() {
            unpack();
            change();
            assert!(!unpacked_as(&here, &target), "change {index}");
        }
    }
}
