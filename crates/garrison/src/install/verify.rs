//! The check of an unpacked release before anything is installed.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use garrison_core::hex;
use sha2::{Digest, Sha256};

use super::files::{Step, io};

/// Every file of the release must be listed in SHA256SUMS and match it, and the
/// release may hold nothing but directories and regular files. Root copies the
/// tree, so an unlisted file or a link pointing elsewhere (say, to `/etc`) must
/// stop the installation before it starts.
pub(super) fn verify(here: &Path) -> Step<String> {
    let sums = here.join("SHA256SUMS");
    let text = match fs::read_to_string(&sums) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("SHA256SUMS is missing; this is not a complete release.".into());
        }
        Err(error) => return Err(format!("{}: {error}", sums.display())),
    };
    let mut listed = BTreeSet::new();
    for line in text.lines() {
        let (digest, name) = line.split_once("  ").ok_or("SHA256SUMS is malformed.")?;
        if !inside(name) || name == "SHA256SUMS" {
            return Err(format!(
                "SHA256SUMS lists {name:?}, which is no file of a release; nothing was installed."
            ));
        }
        if !listed.insert(name) {
            return Err(format!(
                "SHA256SUMS lists {name} twice; nothing was installed."
            ));
        }
        let path = here.join(name);
        if !io(fs::symlink_metadata(&path), &path)?.is_file() {
            return Err(format!(
                "{name} is not a regular file; nothing was installed."
            ));
        }
        let data = io(fs::read(&path), &path)?;
        if hex::encode(&Sha256::digest(&data)) != digest {
            return Err(format!(
                "Checksum mismatch for {name}; nothing was installed."
            ));
        }
    }
    let mut present = Vec::new();
    files(here, "", &mut present)?;
    if let Some(extra) = present
        .iter()
        .find(|name| *name != "SHA256SUMS" && !listed.contains(name.as_str()))
    {
        return Err(format!(
            "{extra} is not listed in SHA256SUMS; nothing was installed."
        ));
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
        return Err(format!(
            "VERSION {version:?} is not a release version; nothing was installed."
        ));
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
fn files(directory: &Path, prefix: &str, found: &mut Vec<String>) -> Step {
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
            return Err(format!(
                "{relative} is not a regular file; nothing was installed."
            ));
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
        assert!(
            verify(root)
                .unwrap_err()
                .starts_with("VERSION \"../../etc\"")
        );
        fs::write(root.join("a.txt"), "b").unwrap();
        assert_eq!(
            verify(root).unwrap_err(),
            "Checksum mismatch for a.txt; nothing was installed."
        );
        // A list that cannot be read says why, not that it is missing.
        let list = root.join("SHA256SUMS");
        fs::set_permissions(&list, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&list).is_err() {
            let refused = verify(root).unwrap_err();
            assert!(
                refused.ends_with("SHA256SUMS: Permission denied (os error 13)"),
                "{refused}"
            );
        }
        fs::remove_file(&list).unwrap();
        assert_eq!(
            verify(root).unwrap_err(),
            "SHA256SUMS is missing; this is not a complete release."
        );
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
            "static/extra.js is not listed in SHA256SUMS; nothing was installed."
        );
        fs::remove_file(root.join("static/extra.js")).unwrap();

        // A link, listed or not, would make root copy what it points to.
        symlink("/etc", root.join("static/etc")).unwrap();
        assert_eq!(
            verify(root).unwrap_err(),
            "static/etc is not a regular file; nothing was installed."
        );
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
            "static/copy.html is not a regular file; nothing was installed."
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
            assert_eq!(
                verify(root).unwrap_err(),
                format!(
                    "SHA256SUMS lists {name:?}, which is no file of a release; nothing was installed."
                )
            );
        }
        fs::write(
            root.join("SHA256SUMS"),
            format!("{digest}  VERSION\n{digest}  VERSION\n"),
        )
        .unwrap();
        assert_eq!(
            verify(root).unwrap_err(),
            "SHA256SUMS lists VERSION twice; nothing was installed."
        );
    }
}
