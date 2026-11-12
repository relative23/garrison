//! `garrison upgrade <archive>`: install a newer release once a key that the
//! installed release trusts has signed it.
//!
//! The installed binary is the trust anchor. It reads the archive once, checks
//! the signature over exactly those bytes and unpacks those same bytes, so the
//! file cannot change between the check and the installation; then it runs
//! the new release's installer, which checks every file against SHA256SUMS.

mod signature;

use std::fs;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::install::BASE;
use crate::{complain, say};
use signature::{announced, check, trusted};

const TAR: [&str; 2] = ["/usr/bin/tar", "/bin/tar"];

pub(crate) fn run(archive: &Path, signature: Option<&Path>) -> u8 {
    match upgrade(archive, signature) {
        Ok(code) => code,
        Err(message) => {
            complain(&format!("{message} Nothing was installed."));
            1
        }
    }
}

fn upgrade(archive: &Path, signature: Option<&Path>) -> Result<u8, String> {
    if !rustix::process::geteuid().is_root() {
        return Err("Run as root.".into());
    }
    let name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let release = announced(name).ok_or_else(|| {
        format!(
            "{} is not named like a release archive, garrison-<version>-<arch>.tar.gz.",
            archive.display()
        )
    })?;
    let host = std::env::consts::ARCH;
    if release.architecture != host {
        return Err(format!(
            "{name} is built for {}, this host is {host}.",
            release.architecture
        ));
    }
    let running = running_version()?;
    match garrison_core::version::newer(&release.version, &running) {
        Some(true) => {}
        Some(false) => {
            return Err(format!(
                "{} is not newer than the running {running}; go back with `garrison install --rollback` instead.",
                release.version
            ));
        }
        None => {
            return Err(format!(
                "{} or {running} is no semantic version.",
                release.version
            ));
        }
    }
    let keys = trusted()?;
    if keys.is_empty() {
        return Err("This release trusts no signing key yet, so it cannot check an archive. \
                    Check the archive by hand (docs/operator/installation.md) and run its own installer."
            .into());
    }
    let signature_path = signature.map_or_else(
        || PathBuf::from(format!("{}.minisig", archive.display())),
        Path::to_owned,
    );
    let signature_text = fs::read_to_string(&signature_path)
        .map_err(|error| format!("{}: {error}.", signature_path.display()))?;
    let bytes = fs::read(archive).map_err(|error| format!("{}: {error}.", archive.display()))?;
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
            .map_err(|error| format!("{}: {error}.", installer.display()))
    });
    // The installer copied the release into place; the unpacked tree goes.
    let _ = fs::remove_dir_all(&staging);
    let status = started?;
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1))
}

/// The version of the installed release that this binary belongs to. Only an
/// installed release upgrades: its compiled-in keys are the ones to trust.
fn running_version() -> Result<String, String> {
    let binary =
        std::env::current_exe().map_err(|error| format!("Cannot find this binary: {error}."))?;
    let release = binary
        .parent()
        .and_then(Path::parent)
        .filter(|release| release.parent() == Some(&Path::new(BASE).join("releases")))
        .ok_or_else(|| {
            format!("Run the installed release: {BASE}/current/bin/garrison upgrade <archive>.")
        })?;
    let path = release.join("VERSION");
    let text =
        fs::read_to_string(&path).map_err(|error| format!("{}: {error}.", path.display()))?;
    Ok(text.trim().to_owned())
}

/// A fresh directory only root can enter, next to the releases rather than in
/// /tmp, which may forbid running programs. Trees of upgrades whose process
/// has ended are removed first; a running upgrade keeps its own.
fn staging(base: &Path) -> Result<PathBuf, String> {
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
        .map_err(|error| format!("{}: {error}.", path.display()))?;
    Ok(path)
}

/// Unpack the checked bytes with the system's tar, which refuses absolute
/// names and `..`; files belong to root whatever the archive says.
fn unpack(bytes: &[u8], into: &Path) -> Result<(), String> {
    let tar = TAR
        .iter()
        .find(|path| Path::new(path).exists())
        .ok_or("tar is required.")?;
    let mut child = Command::new(tar)
        .args(["-xz", "--no-same-owner", "-C"])
        .arg(into)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{tar}: {error}."))?;
    if let Some(mut input) = child.stdin.take() {
        // A closed pipe means tar stopped early; its status says why.
        let _ = input.write_all(bytes);
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("{tar}: {error}."))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "The archive cannot be unpacked: {}.",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

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
        assert!(
            refused.starts_with("The archive cannot be unpacked:"),
            "{refused}"
        );
    }
}
