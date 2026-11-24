//! The system files of a release: users, units, nginx snippets, the polkit
//! rule, their SELinux labels and the SELinux module for nginx.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::files::{Step, announce, io, must, put, relabel, run};
use super::{CONFIG, SYSTEMCTL, UNITS, cli, command, states};

/// Garrison's nginx snippets below `root` (`/` outside tests), in order.
pub(super) fn snippets(root: &Path) -> Vec<PathBuf> {
    let folder = root.join("etc/nginx/snippets");
    // nginx reads `.conf` exactly; other cases are not snippets.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    let ours = |name: &str| name.starts_with("garrison") && name.ends_with(".conf");
    let mut found: Vec<PathBuf> = fs::read_dir(&folder)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(ours)
        })
        .collect();
    found.sort();
    found
}

/// The snippets with what they hold, to tell whether a run changed them.
fn nginx_files() -> Vec<(PathBuf, Vec<u8>)> {
    let read = |path: PathBuf| {
        let held = fs::read(&path).unwrap_or_default();
        (path, held)
    };
    snippets(Path::new("/")).into_iter().map(read).collect()
}

/// Apply changed snippets (a new script hash, for example) if nginx accepts them.
fn reload_nginx() -> Step {
    if !run(SYSTEMCTL, &["is-active", "--quiet", "nginx"])?
        .status
        .success()
    {
        return Ok(());
    }
    let test = run("/usr/sbin/nginx", &["-t"])?;
    if !test.status.success() {
        let said = String::from_utf8_lossy(&test.stderr);
        announce(&states::nginx_not_reloaded(said.trim()).to_string());
        return Ok(());
    }
    must(SYSTEMCTL, &["reload", "nginx"])?;
    announce("nginx reloaded with the updated Garrison snippets");
    Ok(())
}

/// Write what a command of `release` prints where it succeeds, and say
/// whether that changed the file; where it fails, why, in the command's own
/// words, which a state then carries.
fn write_output(
    release: &Path,
    command: &[&str],
    target: &Path,
    installed: &mut Vec<PathBuf>,
) -> Step<Result<bool, String>> {
    let output = cli(release, command)?;
    if !output.status.success() {
        return Ok(Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_owned()));
    }
    let wrote = put(target, &output.stdout, 0o644)?;
    installed.push(target.to_owned());
    Ok(Ok(wrote))
}

/// Write what a command of `release` prints, or say why not. Before a
/// configuration exists the installer's next steps ask for one, so only a
/// configuration that does not load is named.
fn write_or_say(
    release: &Path,
    command: &[&str],
    target: &Path,
    installed: &mut Vec<PathBuf>,
) -> Step<bool> {
    match write_output(release, command, target, installed)? {
        Ok(wrote) => Ok(wrote),
        Err(reason) => {
            if Path::new(CONFIG).join("garrison.toml").exists() {
                announce(&states::unwritten(target, command, &reason).to_string());
            }
            Ok(false)
        }
    }
}

/// A file of the release as a system file, where it differs.
fn copy_to(source: &Path, target: &Path) -> Step<bool> {
    put(target, &io(fs::read(source), source)?, 0o644)
}

/// Where a unit of Garrison's is installed.
pub(super) fn unit_file(unit: &str) -> PathBuf {
    Path::new("/etc/systemd/system").join(unit)
}

/// Install the system files of `release` where they differ from what it
/// writes, and say whether any did.
pub(super) fn install_system_files(release: &Path) -> Step<bool> {
    let share = release.join("share/deploy");
    let sysusers = PathBuf::from("/etc/sysusers.d/garrison.conf");
    io(
        fs::create_dir_all("/etc/sysusers.d"),
        Path::new("/etc/sysusers.d"),
    )?;
    let mut changed = copy_to(&share.join("sysusers/garrison.conf"), &sysusers)?;
    must(
        "/usr/bin/systemd-sysusers",
        &[&sysusers.display().to_string()],
    )?;
    let mut installed = vec![sysusers];
    for unit in UNITS {
        let (source, target) = (share.join("systemd").join(unit), unit_file(unit));
        if source.exists() {
            changed |= copy_to(&source, &target)?;
            installed.push(target);
        } else if target.exists() {
            // A rollback to a release from before this unit: it must not go
            // on starting a command that release does not have.
            let _ = run(SYSTEMCTL, &["disable", "--now", unit]);
            io(fs::remove_file(&target), &target)?;
            changed = true;
        }
    }
    match command::link(Path::new(command::LINK)) {
        Ok(made) => changed |= made,
        Err(reason) => announce(&reason.to_string()),
    }
    if Path::new("/etc/nginx").is_dir() {
        io(
            fs::create_dir_all("/etc/nginx/snippets"),
            Path::new("/etc/nginx/snippets"),
        )?;
        let before = nginx_files();
        // For the configured web port. Before a configuration exists, and
        // for a release that cannot write it, the include as shipped.
        let target = PathBuf::from(crate::nginx::SNIPPET);
        if write_output(release, &["nginx", "--snippet"], &target, &mut installed)?.is_err() {
            copy_to(&share.join("nginx/garrison.conf"), &target)?;
            installed.push(target);
        }
        // Keeps the exporter that `stalwart setup` enables off Stalwart's public hosts.
        let private = PathBuf::from("/etc/nginx/snippets/garrison-stalwart-server.conf");
        copy_to(&share.join("nginx/garrison-stalwart-server.conf"), &private)?;
        installed.push(private);
        // The optional "Switch to Garrison WebUI" row in the Stalwart WebUI; the
        // operator includes this file where the Stalwart WebUI is served.
        let switch = PathBuf::from("/etc/nginx/snippets/garrison-stalwart-switch.conf");
        write_or_say(release, &["stalwart-switch"], &switch, &mut installed)?;
        if nginx_files() != before {
            reload_nginx()?;
            changed = true;
        }
    }
    let rule = PathBuf::from("/etc/polkit-1/rules.d/50-garrison.rules");
    changed |= write_or_say(release, &["polkit-rule"], &rule, &mut installed)?;
    relabel(&installed);
    changed |= super::selinux::install()?;
    changed |= protect_policy()?;
    must(SYSTEMCTL, &["daemon-reload"])?;
    Ok(changed)
}

/// The access policy belongs to root and only the broker's group may read
/// it; whether its owner or mode had to change.
pub(super) fn protect_policy() -> Step<bool> {
    protect(&super::policy())
}

/// Only a regular file reached without a link, which is all the broker reads:
/// a link, a folder or a device that `broker.policy` names is left as it is,
/// and check-config refuses it then. Owner and mode are set on the file that
/// was opened, so that nothing put in its place meanwhile is changed. Only
/// root's own file is made the broker's: one of another user, who may write
/// a folder outside /etc/garrison, would become the policy the broker grants
/// by, and is refused as the broker refuses it.
fn protect(policy: &Path) -> Step<bool> {
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let Ok(file) = rustix::fs::open(policy, flags, Mode::empty()).map(fs::File::from) else {
        return Ok(false);
    };
    let metadata = io(file.metadata(), policy)?;
    if !metadata.is_file() {
        return Ok(false);
    }
    if metadata.uid() != 0 {
        return Err(states::policy_foreign(policy, metadata.uid()));
    }
    let group = crate::access::group_id("garrison-broker");
    if group.is_none_or(|group| metadata.gid() == group) && metadata.mode() & 0o7777 == 0o640 {
        return Ok(false);
    }
    rustix::fs::fchown(
        &file,
        Some(rustix::fs::Uid::ROOT),
        group.map(rustix::fs::Gid::from_raw),
    )
    .map_err(|error| states::io(policy.display(), error))?;
    io(
        file.set_permissions(fs::Permissions::from_mode(0o640)),
        policy,
    )?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::install::stand_in::release;

    #[test]
    fn what_a_command_prints_is_written_and_why_it_failed_is_said() {
        let output = tempfile::tempdir().unwrap();
        let target = output.path().join("50-garrison.rules");
        let mut installed = Vec::new();
        let printing = release("echo 'polkit.addRule(rule);'");
        assert_eq!(
            write_output(printing.path(), &["polkit-rule"], &target, &mut installed),
            Ok(Ok(true))
        );
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "polkit.addRule(rule);\n"
        );
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(installed, std::slice::from_ref(&target));
        // The same output again changes nothing.
        assert_eq!(
            write_output(printing.path(), &["polkit-rule"], &target, &mut Vec::new()),
            Ok(Ok(false))
        );
        let failing = release(
            "echo 'Cannot load /etc/garrison/garrison.toml: unknown key nonsense' >&2; exit 2",
        );
        let reason = write_output(failing.path(), &["polkit-rule"], &target, &mut installed)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            reason,
            "Cannot load /etc/garrison/garrison.toml: unknown key nonsense"
        );
        // What was there stays, and nothing more counts as installed.
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "polkit.addRule(rule);\n"
        );
        assert_eq!(installed.len(), 1);
    }

    /// Only a regular file that `broker.policy` names, reached without a
    /// link, is made the broker's: that is all the broker reads. A link, a
    /// folder or nothing at all there is left as it is.
    #[test]
    fn only_a_policy_that_is_a_file_of_its_own_is_made_private() {
        let directory = tempfile::tempdir().unwrap();
        let elsewhere = directory.path().join("passwd");
        fs::write(&elsewhere, "root:x:0:0::/root:/bin/sh\n").unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o644)).unwrap();
        let link = directory.path().join("access.json");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        let folder = directory.path().join("policies");
        fs::create_dir(&folder).unwrap();
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();
        for named in [&link, &folder, &directory.path().join("missing.json")] {
            assert_eq!(protect(named), Ok(false), "{}", named.display());
        }
        let mode = |path: &Path| fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&elsewhere), mode(&folder)), (0o644, 0o755));
    }

    /// A policy file of another user than root, as one who may write a
    /// folder outside /etc/garrison puts there, stays as it is and is
    /// refused; the test's own user stands in for that other one.
    #[test]
    fn a_policy_of_another_user_is_refused_and_left_as_it_is() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("access.json");
        fs::write(&policy, "{}").unwrap();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).unwrap();
        let refused = protect(&policy).unwrap_err();
        let owner = rustix::process::getuid().as_raw();
        assert_eq!(refused, states::policy_foreign(&policy, owner));
        assert_eq!(
            fs::metadata(&policy).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}
