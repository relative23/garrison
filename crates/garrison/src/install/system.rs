//! The system files of a release: users, units, nginx snippets, the polkit
//! rule, their SELinux labels and the SELinux module for nginx.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::files::{Step, announce, io, must, place, relabel, run};
use super::{CONFIG, SYSTEMCTL, UNITS, cli, command};

fn nginx_files() -> Vec<(String, Vec<u8>)> {
    let mut found: Vec<(String, Vec<u8>)> = fs::read_dir("/etc/nginx/snippets")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            // nginx reads `.conf` exactly; other cases are not snippets.
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            let snippet = name.starts_with("garrison") && name.ends_with(".conf");
            snippet.then(|| (name, fs::read(entry.path()).unwrap_or_default()))
        })
        .collect();
    found.sort();
    found
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
        announce(&format!(
            "nginx -t failed; snippets updated but nginx was not reloaded:\n{}",
            String::from_utf8_lossy(&test.stderr)
        ));
        return Ok(());
    }
    must(SYSTEMCTL, &["reload", "nginx"])?;
    announce("nginx reloaded with the updated Garrison snippets");
    Ok(())
}

/// Write what a command of `release` prints, where it succeeds; where it
/// fails, why, in the command's own words.
fn write_output(
    release: &Path,
    command: &[&str],
    target: &Path,
    installed: &mut Vec<PathBuf>,
) -> Step<Result<(), String>> {
    let output = cli(release, command)?;
    if !output.status.success() {
        return Ok(Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_owned()));
    }
    io(fs::write(target, &output.stdout), target)?;
    io(
        fs::set_permissions(target, fs::Permissions::from_mode(0o644)),
        target,
    )?;
    installed.push(target.to_owned());
    Ok(Ok(()))
}

/// Write what a command of `release` prints, or say why not. Before a
/// configuration exists the installer's next steps ask for one, so only a
/// configuration that does not load is named.
fn write_or_say(
    release: &Path,
    command: &[&str],
    target: &Path,
    installed: &mut Vec<PathBuf>,
) -> Step {
    if let Err(reason) = write_output(release, command, target, installed)?
        && Path::new(CONFIG).join("garrison.toml").exists()
    {
        announce(&unwritten(target, command, &reason));
    }
    Ok(())
}

fn unwritten(target: &Path, command: &[&str], reason: &str) -> String {
    format!(
        "{} was not written, since `garrison {}` failed: {reason}",
        target.display(),
        command.join(" ")
    )
}

/// Where a unit of Garrison's is installed.
pub(super) fn unit_file(unit: &str) -> PathBuf {
    Path::new("/etc/systemd/system").join(unit)
}

pub(super) fn install_system_files(release: &Path) -> Step {
    let share = release.join("share/deploy");
    let sysusers = PathBuf::from("/etc/sysusers.d/garrison.conf");
    io(
        fs::create_dir_all("/etc/sysusers.d"),
        Path::new("/etc/sysusers.d"),
    )?;
    place(&share.join("sysusers/garrison.conf"), &sysusers, 0o644)?;
    must(
        "/usr/bin/systemd-sysusers",
        &[&sysusers.display().to_string()],
    )?;
    let mut installed = vec![sysusers];
    for unit in UNITS {
        let (source, target) = (share.join("systemd").join(unit), unit_file(unit));
        if source.exists() {
            place(&source, &target, 0o644)?;
            installed.push(target);
        } else if target.exists() {
            // A rollback to a release from before this unit: it must not go
            // on starting a command that release does not have.
            let _ = run(SYSTEMCTL, &["disable", "--now", unit]);
            io(fs::remove_file(&target), &target)?;
        }
    }
    if let Err(reason) = command::link(Path::new(command::LINK)) {
        announce(&reason);
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
            place(&share.join("nginx/garrison.conf"), &target, 0o644)?;
            installed.push(target);
        }
        // Keeps the exporter that `stalwart setup` enables off Stalwart's public hosts.
        let private = PathBuf::from("/etc/nginx/snippets/garrison-stalwart-server.conf");
        place(
            &share.join("nginx/garrison-stalwart-server.conf"),
            &private,
            0o644,
        )?;
        installed.push(private);
        // The optional "Switch to Garrison WebUI" row in the Stalwart WebUI; the
        // operator includes this file where the Stalwart WebUI is served.
        let switch = PathBuf::from("/etc/nginx/snippets/garrison-stalwart-switch.conf");
        write_or_say(release, &["stalwart-switch"], &switch, &mut installed)?;
        if nginx_files() != before {
            reload_nginx()?;
        }
    }
    let rule = PathBuf::from("/etc/polkit-1/rules.d/50-garrison.rules");
    write_or_say(release, &["polkit-rule"], &rule, &mut installed)?;
    relabel(&installed);
    super::selinux::install()?;
    protect_policy()?;
    must(SYSTEMCTL, &["daemon-reload"])
}

/// The access policy belongs to root and only the broker's group may read it.
pub(super) fn protect_policy() -> Step {
    let policy = super::policy();
    if !policy.exists() {
        return Ok(());
    }
    let group = crate::access::group_id("garrison-broker").map(rustix::fs::Gid::from_raw);
    rustix::fs::chown(&policy, Some(rustix::fs::Uid::ROOT), group)
        .map_err(|error| format!("{}: {error}", policy.display()))?;
    io(
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o640)),
        &policy,
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// A release whose command prints `stdout`, or fails saying `stderr`.
    fn release(script: &str) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("bin")).unwrap();
        let binary = directory.path().join("bin/garrison");
        fs::write(&binary, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        directory
    }

    #[test]
    fn what_a_command_prints_is_written_and_why_it_failed_is_said() {
        let output = tempfile::tempdir().unwrap();
        let target = output.path().join("50-garrison.rules");
        let mut installed = Vec::new();
        let printing = release("echo 'polkit.addRule(rule);'");
        assert_eq!(
            write_output(printing.path(), &["polkit-rule"], &target, &mut installed),
            Ok(Ok(()))
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
        assert_eq!(
            unwritten(&target, &["polkit-rule"], &reason),
            format!(
                "{} was not written, since `garrison polkit-rule` failed: Cannot load \
                 /etc/garrison/garrison.toml: unknown key nonsense",
                target.display()
            )
        );
    }
}
