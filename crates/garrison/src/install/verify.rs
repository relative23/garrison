//! The check of an unpacked release before anything is installed.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use garrison_core::hex;
use sha2::{Digest, Sha256};

use super::states;
use crate::state::State;

fn io<T>(result: std::io::Result<T>, path: &Path) -> Result<T, State> {
    result.map_err(|error| states::io(path.display(), error))
}

/// Every file of the release must be listed in SHA256SUMS and match it, and the
/// release may hold nothing but directories and regular files. Root copies the
/// tree, so an unlisted file or a link pointing elsewhere (say, to `/etc`) must
/// stop the installation before it starts.
pub(super) fn verify(here: &Path) -> Result<String, State> {
    let sums = here.join("SHA256SUMS");
    let text = match fs::read_to_string(&sums) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(states::sums_missing());
        }
        Err(error) => return Err(states::io(sums.display(), error)),
    };
    let mut listed = BTreeSet::new();
    for line in text.lines() {
        let (digest, name) = line.split_once("  ").ok_or_else(states::sums_malformed)?;
        if !inside(name) || name == "SHA256SUMS" {
            return Err(states::sums_outside(name));
        }
        if !listed.insert(name) {
            return Err(states::sums_twice(name));
        }
        let path = here.join(name);
        if !io(fs::symlink_metadata(&path), &path)?.is_file() {
            return Err(states::not_a_file(name));
        }
        let data = io(fs::read(&path), &path)?;
        if hex::encode(&Sha256::digest(&data)) != digest {
            return Err(states::checksum_mismatch(name));
        }
    }
    let mut present = Vec::new();
    files(here, "", &mut present)?;
    if let Some(extra) = present
        .iter()
        .find(|name| *name != "SHA256SUMS" && !listed.contains(name.as_str()))
    {
        return Err(states::unlisted(extra));
    }
    let path = here.join("VERSION");
    let version = io(fs::read_to_string(&path), &path)?.trim().to_owned();
    // The version names a directory under /opt/garrison/releases.
    let usable = version.len() <= 64
        && version.starts_with(|first: char| first.is_ascii_digit())
        && version
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".+-".contains(character));
    if !usable {
        return Err(states::bad_version(&version));
    }
    Ok(version)
}

/// A relative path without empty, `.` or `..` parts.
fn inside(name: &str) -> bool {
    name.split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// The regular files below `directory`, relative to the release. Anything but
/// a directory or a regular file is refused; links are not followed.
fn files(directory: &Path, prefix: &str, found: &mut Vec<String>) -> Result<(), State> {
    for entry in io(fs::read_dir(directory), directory)? {
        let entry = io(entry, directory)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let path = entry.path();
        let kind = io(fs::symlink_metadata(&path), &path)?;
        if kind.is_dir() {
            files(&path, &relative, found)?;
        } else if kind.is_file() {
            found.push(relative);
        } else {
            return Err(states::not_a_file(relative));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    fn sums(root: &Path, names: &[&str]) {
        let lines: Vec<String> = names
            .iter()
            .map(|name| {
                let digest = hex::encode(&Sha256::digest(fs::read(root.join(name)).unwrap()));
                format!("{digest}  {name}\n")
            })
            .collect();
        fs::write(root.join("SHA256SUMS"), lines.concat()).unwrap();
    }

    #[test]
    fn a_release_is_verified_file_by_file() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join("VERSION"), "0.1.0-dev\n").unwrap();
        fs::write(root.join("a.txt"), "a").unwrap();
        sums(root, &["VERSION", "a.txt"]);
        assert_eq!(verify(root).unwrap(), "0.1.0-dev");
        fs::write(root.join("VERSION"), "../../etc\n").unwrap();
        sums(root, &["VERSION", "a.txt"]);
        assert_eq!(verify(root).unwrap_err(), states::bad_version("../../etc"));
        fs::write(root.join("a.txt"), "b").unwrap();
        assert_eq!(
            verify(root).unwrap_err(),
            states::checksum_mismatch("a.txt")
        );
        // A list that cannot be read says why, not that it is missing.
        let list = root.join("SHA256SUMS");
        fs::set_permissions(&list, fs::Permissions::from_mode(0o000)).unwrap();
        if let Err(error) = fs::read(&list) {
            assert_eq!(verify(root).unwrap_err(), states::io(list.display(), error));
        }
        fs::remove_file(&list).unwrap();
        assert_eq!(verify(root).unwrap_err(), states::sums_missing());
    }

    #[test]
    fn a_release_holds_only_the_files_its_list_names() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("static")).unwrap();
        fs::write(root.join("VERSION"), "0.1.0-dev\n").unwrap();
        fs::write(root.join("static/index.html"), "<p>").unwrap();
        sums(root, &["VERSION", "static/index.html"]);
        assert_eq!(verify(root).unwrap(), "0.1.0-dev");

        // An unlisted file, as an archive changed after its list was made.
        fs::write(root.join("static/extra.js"), "steal()").unwrap();
        assert_eq!(
            verify(root).unwrap_err(),
            states::unlisted("static/extra.js")
        );
        fs::remove_file(root.join("static/extra.js")).unwrap();

        // A link, listed or not, would make root copy what it points to.
        symlink("/etc", root.join("static/etc")).unwrap();
        assert_eq!(verify(root).unwrap_err(), states::not_a_file("static/etc"));
        fs::remove_file(root.join("static/etc")).unwrap();
        symlink("index.html", root.join("static/copy.html")).unwrap();
        let digest = hex::encode(&Sha256::digest(b"<p>"));
        let list = fs::read_to_string(root.join("SHA256SUMS")).unwrap();
        fs::write(
            root.join("SHA256SUMS"),
            format!("{list}{digest}  static/copy.html\n"),
        )
        .unwrap();
        assert_eq!(
            verify(root).unwrap_err(),
            states::not_a_file("static/copy.html")
        );
    }

    #[test]
    fn random_names_inside_the_release_never_climb_out() {
        let mut noise = garrison_testing::noise::Noise::new(37);
        for _ in 0..20_000 {
            let name = noise.text("ab./", 16);
            if inside(&name) {
                assert!(
                    !name.starts_with('/')
                        && !name.split('/').any(|part| part == ".." || part.is_empty()),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn the_list_names_only_files_inside_the_release() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join("VERSION"), "0.1.0-dev\n").unwrap();
        let digest = hex::encode(&Sha256::digest(b"0.1.0-dev\n"));
        for name in [
            "../VERSION",
            "/etc/passwd",
            "./VERSION",
            "a//b",
            "SHA256SUMS",
        ] {
            fs::write(root.join("SHA256SUMS"), format!("{digest}  {name}\n")).unwrap();
            assert_eq!(verify(root).unwrap_err(), states::sums_outside(name));
        }
        fs::write(
            root.join("SHA256SUMS"),
            format!("{digest}  VERSION\n{digest}  VERSION\n"),
        )
        .unwrap();
        assert_eq!(verify(root).unwrap_err(), states::sums_twice("VERSION"));
    }
}
