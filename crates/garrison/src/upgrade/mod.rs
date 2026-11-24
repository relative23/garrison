//! `garrison upgrade <archive>`: install a newer release, or the same one
//! again, once a key that the installed release trusts has signed it.
//!
//! The installed binary is the trust anchor. It reads the archive once, checks
//! the signature over exactly those bytes and unpacks those same bytes, so the
//! file cannot change between the check and the installation; then it runs
//! the new release's installer, which checks every file against SHA256SUMS.

mod signature;
mod states;

use std::fs;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::install::BASE;
use crate::state::State;
use crate::{complain, say};
use signature::{announced, check, trusted};

const TAR: [&str; 2] = ["/usr/bin/tar", "/bin/tar"];

pub(crate) fn run(archive: &Path, signature: Option<&Path>) -> u8 {
    match upgrade(archive, signature) {
        Ok(code) => code,
        Err(refusal) => {
            complain(&states::nothing_installed(refusal).to_string());
            1
        }
    }
}

fn upgrade(archive: &Path, signature: Option<&Path>) -> Result<u8, State> {
    if !rustix::process::geteuid().is_root() {
        return Err(states::not_root());
    }
    let name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let release = announced(name).ok_or_else(|| states::not_an_archive(archive))?;
    let host = std::env::consts::ARCH;
    if release.architecture != host {
        return Err(states::other_architecture(
            name,
            &release.architecture,
            host,
        ));
    }
    admitted(&release.version, &running_version()?)?;
    let keys = trusted()?;
    if keys.is_empty() {
        return Err(states::no_keys());
    }
    let signature_path = signature.map_or_else(
        || PathBuf::from(format!("{}.minisig", archive.display())),
        Path::to_owned,
    );
    let signature_text = fs::read_to_string(&signature_path)
        .map_err(|error| states::io(signature_path.display(), error))?;
    let bytes = fs::read(archive).map_err(|error| states::io(archive.display(), error))?;
    check(&keys, &bytes, &signature_text, &release)?;
    say(&format!(
        "==> {name} carries a valid signature for {}",
        release.comment()
    ));

    let staging = staging(Path::new(BASE))?;
    let started = unpack(&bytes, &staging).and_then(|()| {
        let installer = staging
            .join(format!(
                "garrison-{}-{}",
                release.version, release.architecture
            ))
            .join("bin/garrison");
        Command::new(&installer)
            .arg("install")
            .status()
            .map_err(|error| states::io(installer.display(), error))
    });
    // The installer copied the release into place; the unpacked tree goes.
    let _ = fs::remove_dir_all(&staging);
    let status = started?;
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1))
}

/// Whether an archive of `version` is installed over the `running` release:
/// a newer one, and the same one, whose installer finishes what an
/// installation cut short left or changes nothing where it runs.
fn admitted(version: &str, running: &str) -> Result<(), State> {
    match garrison_core::version::newer(running, version) {
        Some(false) => Ok(()),
        Some(true) => Err(states::older_archive(version, running)),
        None => Err(states::no_version(version, running)),
    }
}

/// The version of the installed release that this binary belongs to. Only an
/// installed release upgrades: its compiled-in keys are the ones to trust.
fn running_version() -> Result<String, State> {
    let binary =
        std::env::current_exe().map_err(|error| states::io("Cannot find this binary", error))?;
    let release = installed_release(&binary, Path::new(BASE)).ok_or_else(states::not_installed)?;
    version_of(release)
}

/// The version an installed release names in its `VERSION`.
fn version_of(release: &Path) -> Result<String, State> {
    let path = release.join("VERSION");
    let text = fs::read_to_string(&path).map_err(|error| states::io(path.display(), error))?;
    Ok(text.trim().to_owned())
}

/// The release `binary` belongs to, if it is one installed under `base`:
/// `<base>/releases/<version>/bin/garrison`. The system names a running
/// binary by its resolved path, so `base` is resolved as well: /opt may be a
/// link to another disk.
fn installed_release<'a>(binary: &'a Path, base: &Path) -> Option<&'a Path> {
    let releases = fs::canonicalize(base.join("releases")).ok()?;
    binary
        .parent()
        .and_then(Path::parent)
        .filter(|release| release.parent() == Some(releases.as_path()))
}

/// A fresh directory only root can enter, next to the releases rather than in
/// /tmp, which may forbid running programs. Trees of upgrades whose process
/// has ended are removed first; a running upgrade keeps its own.
fn staging(base: &Path) -> Result<PathBuf, State> {
    for entry in fs::read_dir(base).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(pid) = name.strip_prefix("upgrade.") else {
            continue;
        };
        if !Path::new("/proc").join(pid).exists() {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
    let path = base.join(format!("upgrade.{}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|error| states::io(path.display(), error))?;
    Ok(path)
}

/// Unpack the checked bytes with the system's tar, which refuses absolute
/// names and `..`; files belong to root whatever the archive says.
fn unpack(bytes: &[u8], into: &Path) -> Result<(), State> {
    let tar = TAR
        .iter()
        .find(|path| Path::new(path).exists())
        .ok_or_else(states::no_tar)?;
    let mut child = Command::new(tar)
        .args(["-xz", "--no-same-owner", "-C"])
        .arg(into)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| states::io(tar, error))?;
    if let Some(mut input) = child.stdin.take() {
        // A closed pipe means tar stopped early; its status says why.
        let _ = input.write_all(bytes);
    }
    let output = child
        .wait_with_output()
        .map_err(|error| states::io(tar, error))?;
    if output.status.success() {
        Ok(())
    } else {
        let said = String::from_utf8_lossy(&output.stderr);
        Err(states::unpack_failed(said.trim()))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn an_archive_is_admitted_unless_it_is_older_than_the_running_release() {
        for (version, running) in [
            ("0.2.0", "0.1.2"),
            ("0.2.0", "0.2.0"),
            ("0.2.0", "0.2.0-rc.1"),
        ] {
            assert_eq!(
                admitted(version, running),
                Ok(()),
                "{version} over {running}"
            );
        }
        assert_eq!(
            admitted("0.1.2", "0.2.0"),
            Err(states::older_archive("0.1.2", "0.2.0"))
        );
        assert_eq!(
            admitted("0.2.0-rc.1", "0.2.0"),
            Err(states::older_archive("0.2.0-rc.1", "0.2.0"))
        );
        assert_eq!(
            admitted("latest", "0.2.0"),
            Err(states::no_version("latest", "0.2.0"))
        );
    }

    #[test]
    fn the_installed_release_is_found_where_the_base_is_a_link() {
        let directory = tempfile::tempdir().unwrap();
        let disk = fs::canonicalize(directory.path()).unwrap().join("disk");
        let release = disk.join("garrison/releases/0.5.0");
        fs::create_dir_all(release.join("bin")).unwrap();
        // /opt/garrison is a link to another disk; the running binary is
        // named by where it really lies.
        let base = directory.path().join("opt-garrison");
        std::os::unix::fs::symlink(disk.join("garrison"), &base).unwrap();
        let binary = release.join("bin/garrison");
        assert_eq!(installed_release(&binary, &base), Some(release.as_path()));
        assert_eq!(
            installed_release(&binary, &disk.join("garrison")),
            Some(release.as_path())
        );
        // A binary from an unpacked archive is no installed release.
        let unpacked = disk.join("garrison-0.5.0-x86_64/bin/garrison");
        assert_eq!(installed_release(&unpacked, &base), None);
        assert_eq!(
            installed_release(&binary, &directory.path().join("absent")),
            None
        );
    }

    #[test]
    fn an_upgrade_unpacks_into_its_own_private_directory() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        // A tree of an upgrade that ended, and one of a process that still runs.
        fs::create_dir(base.join("upgrade.999999999")).unwrap();
        let running = base.join(format!("upgrade.{}", std::os::unix::process::parent_id()));
        fs::create_dir(&running).unwrap();
        let staging = staging(base).unwrap();
        assert!(!base.join("upgrade.999999999").exists());
        assert!(running.exists());
        assert_eq!(
            fs::metadata(&staging).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let source = base.join("source");
        fs::create_dir_all(source.join("garrison-1.0.0-x86_64/bin")).unwrap();
        fs::write(source.join("garrison-1.0.0-x86_64/bin/garrison"), "binary").unwrap();
        let packed = Command::new("tar")
            .args(["-cz", "-C"])
            .arg(&source)
            .arg("garrison-1.0.0-x86_64")
            .output()
            .unwrap();
        unpack(&packed.stdout, &staging).unwrap();
        assert_eq!(
            fs::read_to_string(staging.join("garrison-1.0.0-x86_64/bin/garrison")).unwrap(),
            "binary"
        );
        let refused = unpack(b"not an archive", &staging).unwrap_err();
        assert_eq!(refused.name, "upgrade-unpack-failed");
    }
}
