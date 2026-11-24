//! What the host must offer before the installer changes anything: root, a
//! systemd that knows the units' settings, polkit with JavaScript rules for
//! the broker's actions, and room for the release and the backup.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use garrison_core::config::{self, Database};

use super::files::{Step, io, run};
use super::{BASE, CONFIG, SYSTEMCTL};

/// `LoadCredential=` in the units arrived with systemd 247.
const SYSTEMD: u32 = 247;
const PKACTION: &str = "/usr/bin/pkaction";
/// Left free after the installation, for the services' own writes.
const SPARE: u64 = 64 << 20;

/// What an uninstallation needs: root and systemctl. Neither polkit nor a
/// systemd that knows the units' settings, which only a start needs.
pub(super) fn root_with_systemctl() -> Step {
    if !rustix::process::geteuid().is_root() {
        return Err("Run as root.".into());
    }
    if !Path::new(SYSTEMCTL).exists() {
        return Err(format!("{SYSTEMCTL} is required."));
    }
    Ok(())
}

pub(super) fn preflight() -> Step {
    root_with_systemctl()?;
    if !Path::new("/usr/bin/systemd-sysusers").exists() {
        return Err("/usr/bin/systemd-sysusers is required.".into());
    }
    let output = run(SYSTEMCTL, &["--version"])?;
    match systemd_version(&String::from_utf8_lossy(&output.stdout)) {
        Some(version) if version >= SYSTEMD => {}
        Some(version) => {
            return Err(format!(
                "systemd {version} is too old: Garrison's units need systemd {SYSTEMD} or newer."
            ));
        }
        None => return Err("`systemctl --version` names no systemd version.".into()),
    }
    // polkit 0.105, still shipped by some long-term releases, ignores rules files
    // and has no rules.d; naming its version tells the operator what to change.
    if Path::new(PKACTION).exists() {
        let output = run(PKACTION, &["--version"])?;
        let text = String::from_utf8_lossy(&output.stdout);
        if let Some(version) = text.trim().strip_prefix("pkaction version ")
            && !has_rules(version)
        {
            return Err(format!(
                "polkit {version} has no JavaScript rules: Garrison needs polkit 0.106 or newer."
            ));
        }
    }
    if !Path::new("/etc/polkit-1/rules.d").is_dir() {
        return Err(
            "polkit is required for service actions, with JavaScript rules \
                    (polkit 0.106 or newer, /etc/polkit-1/rules.d)."
                .into(),
        );
    }
    Ok(())
}

/// Before a command that starts the services: the units must find the
/// release where it lies, not through a link into a place they hide.
pub(super) fn base_shown() -> Step {
    match crate::units::hidden_base(Path::new(BASE)) {
        Some(why) => Err(format!("{why}; nothing was changed.")),
        None => Ok(()),
    }
}

/// `systemd 257 (257.13-1~deb13u1)` is 257.
fn systemd_version(text: &str) -> Option<u32> {
    text.lines()
        .next()?
        .strip_prefix("systemd ")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Rules came with polkit 0.106; releases since 121 count without the `0.`.
fn has_rules(version: &str) -> bool {
    let mut parts = version.split('.').map(str::parse::<u32>);
    match (parts.next(), parts.next()) {
        (Some(Ok(0)), Some(Ok(minor))) => minor >= 106,
        (Some(Ok(major)), _) => major > 0,
        // An unknown format: the rules directory above decides.
        _ => true,
    }
}

/// Bytes of the files below `path`, links not followed.
pub(super) fn size(path: &Path) -> u64 {
    let Ok(kind) = fs::symlink_metadata(path) else {
        return 0;
    };
    if !kind.is_dir() {
        return if kind.is_file() { kind.len() } else { 0 };
    }
    fs::read_dir(path)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| size(&entry.path()))
        .sum()
}

/// The size of the databases a backup copies, with their write-ahead logs.
pub(super) fn state_size() -> u64 {
    let Ok(config) = config::load(&Path::new(CONFIG).join("garrison.toml")) else {
        // check-config reports a configuration it cannot load; estimate from the default.
        return size(Path::new("/var/lib/garrison"));
    };
    Database::ALL
        .into_iter()
        .map(|database| {
            let path = config.database(database);
            let journal = PathBuf::from(format!("{}-wal", path.display()));
            size(&path) + size(&journal)
        })
        .sum()
}

/// The closest existing directory of `path`.
fn existing(path: &Path) -> &Path {
    path.ancestors()
        .find(|ancestor| ancestor.is_dir())
        .unwrap_or(Path::new("/"))
}

/// Every `(directory, bytes)` must fit on its filesystem, with a tenth more and
/// some space to spare; needs on one filesystem add up. `what` names what
/// needs the room, such as "the installation".
pub(super) fn room(needs: &[(&Path, u64)], what: &str) -> Step {
    match lacking(needs, true)? {
        Some((directory, free, wanted)) => Err(format!(
            "{} has {} MiB free and {what} needs {} MiB; nothing was changed.",
            directory.display(),
            free >> 20,
            wanted >> 20
        )),
        None => Ok(()),
    }
}

/// Every `(directory, bytes)` must fit on its filesystem as it is, for the
/// copies from before an upgrade that a switch back puts back: a way back
/// needs no room to spare.
pub(super) fn exact_room(needs: &[(&Path, u64)]) -> Step {
    match lacking(needs, false)? {
        Some((directory, free, wanted)) => Err(format!(
            "{} has {} MiB free and the copies from before the upgrade need {} MiB there; free \
             space there",
            directory.display(),
            free >> 20,
            wanted.div_ceil(1 << 20)
        )),
        None => Ok(()),
    }
}

/// The first filesystem that lacks room for what `needs` puts on it, with
/// what it has free and what it needs, with the margin of `room` or none.
fn lacking(needs: &[(&Path, u64)], spare: bool) -> Step<Option<(PathBuf, u64, u64)>> {
    let mut filesystems: Vec<(u64, &Path, u64)> = Vec::new();
    for (path, bytes) in needs {
        let directory = existing(path);
        let device = io(fs::metadata(directory), directory)?.dev();
        match filesystems.iter_mut().find(|(known, ..)| *known == device) {
            Some((_, _, total)) => *total += bytes,
            None => filesystems.push((device, directory, *bytes)),
        }
    }
    for (_, directory, bytes) in filesystems {
        let stat = rustix::fs::statvfs(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        let free = stat.f_bavail.saturating_mul(stat.f_frsize);
        let wanted = if spare {
            bytes + bytes / 10 + SPARE
        } else {
            bytes
        };
        if free < wanted {
            return Ok(Some((directory.to_owned(), free, wanted)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_read_from_the_tools_output() {
        assert_eq!(
            systemd_version("systemd 257 (257.13-1~deb13u1)\n+PAM +AUDIT"),
            Some(257)
        );
        assert_eq!(systemd_version("systemd 239 (239-82.el8)"), Some(239));
        assert_eq!(systemd_version("something else"), None);
        for version in ["126", "124", "0.106", "0.117"] {
            assert!(has_rules(version), "{version}");
        }
        assert!(!has_rules("0.105"));
    }

    #[test]
    fn random_tool_output_never_panics() {
        let mut noise = garrison_testing::noise::Noise::new(53);
        for _ in 0..20_000 {
            let text = format!(
                "{}{}",
                ["systemd ", "pkaction version ", ""][noise.below(3)],
                noise.text("0123456789. (abc)\n", 16)
            );
            let _ = systemd_version(&text);
            let _ = has_rules(&text);
            let _ = crate::nginx::version_of(&text);
        }
    }

    #[test]
    fn sizes_count_files_without_following_links() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("a")).unwrap();
        fs::write(root.join("a/one"), [0; 100]).unwrap();
        fs::write(root.join("two"), [0; 20]).unwrap();
        std::os::unix::fs::symlink("/usr", root.join("link")).unwrap();
        assert_eq!(size(root), 120);
        assert_eq!(size(&root.join("absent")), 0);
    }

    #[test]
    fn room_is_measured_on_the_filesystem_that_takes_the_files() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("not/yet/created");
        room(&[(&missing, 1)], "the installation").unwrap();
        let refused = room(&[(&missing, u64::MAX / 4)], "the installation").unwrap_err();
        assert!(refused.ends_with("; nothing was changed."), "{refused}");
        assert!(
            refused.contains(" MiB free and the installation needs "),
            "{refused}"
        );
        // Two needs on one filesystem add up.
        let stat = rustix::fs::statvfs(directory.path()).unwrap();
        let half = stat.f_bavail * stat.f_frsize / 2;
        assert!(room(&[(directory.path(), half), (&missing, half)], "the restore").is_err());
    }
}
