//! `garrison install`: install, upgrade or roll back from an extracted release.
//!
//! ```text
//! sudo ./garrison-<version>-<arch>/bin/garrison install
//! sudo /opt/garrison/current/bin/garrison install --rollback [--restore-state]
//! ```
//!
//! Every release lives in `/opt/garrison/releases/<version>`.
//! /opt/garrison/current and .../previous are symlinks; switching them is
//! the upgrade and the rollback. Before an upgrade the running state is
//! copied with the running release's `backup`. Nothing here touches Stalwart,
//! mail data or unrelated services.

mod command;
mod files;
mod housekeeping;
mod milter;
mod requirements;
mod rollback;
mod selinux;
mod system;
mod uninstall;
mod verify;

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Output;

use garrison_core::time;

use crate::{say, units};
use files::{Step, announce, copy_tree, exchange, io, lock, must, place, run, switch};
use requirements::{preflight, room, size, state_size};
use system::{install_system_files, protect_policy, unit_file};
pub(crate) use uninstall::run_uninstall;

pub(crate) const BASE: &str = "/opt/garrison";
pub(super) const CONFIG: &str = "/etc/garrison";
const BACKUPS: &str = "/var/backups/garrison";
/// The backup `--rollback --restore-state` returns to, under BACKUPS.
const LAST: &str = "last-pre-upgrade";
const LOCK: &str = "/run/garrison-install.lock";
pub(super) const UNITS: [&str; 9] = [
    units::BROKER_SOCKET,
    units::BROKER,
    units::WEB,
    units::INGEST,
    units::COLLECT,
    units::COLLECT_TIMER,
    units::WATCH,
    units::WATCH_TIMER,
    units::MILTER,
];
const ENABLE: [&str; 5] = [
    units::BROKER_SOCKET,
    units::WEB,
    units::INGEST,
    units::COLLECT_TIMER,
    units::WATCH_TIMER,
];
// The macro milter is not among them: it keeps nothing, and while it is
// down Stalwart defers mail. It starts anew with the others.
const STOP: [&str; 6] = [
    units::WEB,
    units::INGEST,
    units::COLLECT_TIMER,
    units::WATCH_TIMER,
    units::BROKER,
    units::BROKER_SOCKET,
];
pub(super) use garrison_core::systemd::SYSTEMCTL;

/// The extracted release this binary belongs to: `<release>/bin/garrison`.
fn here() -> Step<PathBuf> {
    let binary = std::env::current_exe().map_err(|error| error.to_string())?;
    binary
        .parent()
        .and_then(Path::parent)
        .map(Path::to_owned)
        .ok_or_else(|| "cannot locate the release".into())
}

/// A command of an installed release, with the system configuration.
pub(super) fn cli(release: &Path, arguments: &[&str]) -> Step<Output> {
    let config = format!("{CONFIG}/garrison.toml");
    let mut all = vec!["--config", config.as_str()];
    all.extend_from_slice(arguments);
    run(&release.join("bin/garrison").display().to_string(), &all)
}

/// Unpack next to the target, then rename it into place: the release's name
/// only ever holds a complete tree, also the running one's on a reinstall.
fn install_release(here: &Path, version: &str) -> Step<PathBuf> {
    let releases = Path::new(BASE).join("releases");
    io(fs::create_dir_all(&releases), &releases)?;
    // Hidden entries are trees an interrupted run left behind.
    for entry in io(fs::read_dir(&releases), &releases)?.flatten() {
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            let path = entry.path();
            let removed = if path.is_dir() && !path.is_symlink() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            io(removed, &path)?;
        }
    }
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

/// Back up the running state. Only a change of release moves `last-pre-upgrade`,
/// the state `--rollback --restore-state` returns to: a reinstall of the running
/// release would otherwise replace it with data the previous release cannot read.
fn backup_state(current: &Path, upgrade: bool) -> Step {
    let stamp = time::now().strftime("%Y%m%dT%H%M%S").to_string();
    let kind = if upgrade {
        "pre-upgrade"
    } else {
        "pre-reinstall"
    };
    let target = Path::new(BACKUPS).join(format!("{kind}-{stamp}"));
    announce(&format!(
        "Backing up the running state to {}",
        target.display()
    ));
    let output = cli(current, &["backup", "--to", &target.display().to_string()])?;
    if !output.status.success() {
        return Err(format!(
            "backup failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    copy_config(Path::new(CONFIG), &target.join("etc"))?;
    if !upgrade {
        return Ok(());
    }
    switch(&Path::new(BACKUPS).join(LAST), &target)
}

/// The configuration without credentials, which have their own protected backup.
fn copy_config(source: &Path, target: &Path) -> Step {
    io(fs::create_dir_all(target), target)?;
    for entry in io(fs::read_dir(source), source)?.flatten() {
        if entry.file_name() == "credentials" {
            continue;
        }
        let (from, to) = (entry.path(), target.join(entry.file_name()));
        if from.is_dir() {
            copy_config(&from, &to)?;
        } else {
            place(&from, &to, 0o600)?;
        }
    }
    Ok(())
}

fn first_install_help() -> Step {
    let config = Path::new(CONFIG);
    io(fs::create_dir_all(config.join("credentials")), config)?;
    io(
        fs::set_permissions(
            config.join("credentials"),
            fs::Permissions::from_mode(0o700),
        ),
        config,
    )?;
    let target = config.join("garrison.toml");
    if !target.exists() {
        place(
            &Path::new(BASE).join("current/share/deploy/config/garrison.example.toml"),
            &target,
            0o644,
        )?;
        // At a terminal the modules are chosen now; otherwise with `modules`.
        if crate::at_terminal() {
            crate::selection::first(&target);
        }
    }
    say(&format!(
        "
The release is installed, but Garrison is not configured yet.

  1. Edit {target} (origins, providers, actions).
     `garrison detect` shows what this host runs, and
     `garrison modules` chooses the modules this installation offers.
  2. Create the Stalwart objects (webhook, API keys, metrics):
       garrison stalwart setup        (asks for a Stalwart administrator)
  3. Create the access policy:   garrison access init
  4. Check everything:           garrison check-config
  5. Run the installer again to start the services.
  6. Give Garrison a host name of its own (never Stalwart's) and include
     /etc/nginx/snippets/garrison.conf in that HTTPS server block.
     Optional, for a \"Switch to Garrison WebUI\" row in the Stalwart WebUI: add
     include /etc/nginx/snippets/garrison-stalwart-switch*.conf;
     inside the location that serves the Stalwart WebUI (/admin/).

The command is available as {command}.",
        target = target.display(),
        command = command::name()
    ));
    Ok(())
}

/// The release's own `check-config` against the system configuration.
fn check_config(release: &Path) -> Step {
    let check = cli(release, &["check-config"])?;
    if !check.status.success() {
        say(&format!(
            "{}\n{}",
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr)
        ));
        return Err("check-config failed".into());
    }
    Ok(())
}

/// The collector's units load the notification channels' secrets. systemd
/// refuses to start a unit whose credential file is missing, so an
/// installation that has none gets empty ones, which mean: no secret.
fn keep_secret_files() -> Step {
    for name in ["ntfy-token", "notify-webhook-token", "notify-mail-password"] {
        let secret = Path::new(CONFIG).join("credentials").join(name);
        if secret.symlink_metadata().is_ok() {
            continue;
        }
        let created = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&secret);
        io(created.map(drop), &secret)?;
    }
    Ok(())
}

fn start(release: &Path) -> Step {
    check_config(release)?;
    keep_secret_files()?;
    reset_failed();
    // Only what this release ships: an older one has fewer units.
    let shipped = ENABLE.into_iter().filter(|unit| unit_file(unit).exists());
    let mut shipped: Vec<&str> = shipped.collect();
    if milter::runs() {
        shipped.push(units::MILTER);
    }
    let mut enable = vec!["enable"];
    enable.extend(&shipped);
    must(SYSTEMCTL, &enable)?;
    // One start per unit: `restart` also starts a stopped unit. The units are
    // ready only once they serve, so a release that cannot come up fails here,
    // its broker too, which otherwise its first client would start.
    let mut restart = vec!["restart"];
    restart.extend(&shipped);
    must(SYSTEMCTL, &restart)?;
    must(SYSTEMCTL, &["start", units::BROKER])?;
    settle()
}

/// The services must also stay up: one that reports ready and falls over at
/// once would otherwise pass as started and restart forever.
const SETTLE: std::time::Duration = std::time::Duration::from_secs(8);
const WATCHED: [&str; 3] = [units::WEB, units::INGEST, units::BROKER];

fn settle() -> Step {
    std::thread::sleep(SETTLE);
    for unit in WATCHED {
        let output = run(
            SYSTEMCTL,
            &["show", "-p", "ActiveState", "-p", "NRestarts", unit],
        )?;
        if let Some(reason) = unsettled(&String::from_utf8_lossy(&output.stdout)) {
            return Err(format!(
                "{unit} {reason} within {} s of starting",
                SETTLE.as_secs()
            ));
        }
    }
    Ok(())
}

/// Why `systemctl show -p ActiveState -p NRestarts` describes a unit that did not stay up.
fn unsettled(properties: &str) -> Option<String> {
    let value = |key: &str| {
        properties
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_default()
    };
    match (value("ActiveState"), value("NRestarts")) {
        ("active", "0") => None,
        ("active", restarts) => Some(format!("restarted {restarts} times")),
        (state, _) => Some(format!(
            "is {}",
            if state.is_empty() { "unknown" } else { state }
        )),
    }
}

/// Forget failures and systemd's start limit (5 starts in 10 s) left by a
/// crash loop, so that a rollback right after a broken upgrade can start.
fn reset_failed() {
    let mut reset = vec!["reset-failed"];
    reset.extend(UNITS);
    let _ = run(SYSTEMCTL, &reset);
}

fn stop_services() {
    let mut stop = vec!["stop"];
    stop.extend(STOP);
    let _ = run(SYSTEMCTL, &stop);
}

/// Switch back after a failed upgrade, with `previous` as it was before, and
/// report whether the previous release runs again, rather than assume it.
fn start_previous(old: &Path, earlier: Option<&Path>) -> Step<&'static str> {
    announce("Start failed; switching back to the previous release.");
    let base = Path::new(BASE);
    switch(&base.join("current"), old)?;
    let previous = base.join("previous");
    match earlier {
        Some(earlier) => switch(&previous, earlier)?,
        None => {
            let _ = fs::remove_file(&previous);
        }
    }
    install_system_files(old)?;
    Ok(if start(old).is_ok() {
        "the previous release is running"
    } else {
        "the previous release did not start either"
    })
}

/// Make `release` current, install its system files and, once configured,
/// start it; `old`, the release that ran, becomes `previous`.
fn switch_to(release: &Path, old: Option<&Path>, configured: bool) -> Step {
    let base = Path::new(BASE);
    if let Some(old) = old {
        switch(&base.join("previous"), old)?;
    }
    switch(&base.join("current"), release)?;
    install_system_files(release)?;
    if configured { start(release) } else { Ok(()) }
}

fn install() -> Step {
    // Root first: without it the release may not even be readable.
    preflight()?;
    let here = here()?;
    let version = verify::verify(&here)?;
    let _held = lock(Path::new(LOCK))?;
    let base = Path::new(BASE);
    let current = base.join("current");
    let old = fs::canonicalize(&current).ok();
    let earlier = fs::canonicalize(base.join("previous")).ok();
    let configured = Path::new(CONFIG).join("garrison.toml").exists()
        && Path::new(CONFIG).join("access-policy.json").exists();
    // Room for the release and, before an upgrade, the backup of the state.
    let mut needs = vec![(base, size(&here))];
    if old.is_some() && configured {
        needs.push((Path::new(BACKUPS), state_size()));
    }
    room(&needs)?;
    let release = install_release(&here, &version)?;
    if old.is_some() && configured {
        // The installer sets the policy's owner and mode anyway; the check must
        // not refuse what it is about to correct.
        protect_policy()?;
        // A configuration the new release refuses leaves the running one alone.
        check_config(&release)
            .map_err(|error| format!("{error}; the running release was not touched"))?;
        backup_state(&current, old.as_ref() != Some(&release))?;
        stop_services();
    }
    let changed = old.as_deref().filter(|old| *old != release);
    if let Err(error) = switch_to(&release, changed, configured) {
        if !configured {
            return Err(error);
        }
        // Garrison is stopped now: whatever failed, the release that ran goes back.
        let outcome = match changed {
            Some(old) => start_previous(old, earlier.as_deref())?,
            None => "no other release was started",
        };
        return Err(format!(
            "The new release did not start ({error}); {outcome}. See the journal."
        ));
    }
    if !configured {
        return first_install_help();
    }
    let backups = Path::new(BACKUPS);
    for line in housekeeping::prune(base, backups, &backups.join(LAST)) {
        announce(&line);
    }
    announce(&format!(
        "Garrison {version} is running. Roll back with: {} install --rollback",
        command::name()
    ));
    Ok(())
}

/// Start the installed release once it is configured: what the second run of
/// the installer does, without unpacking a release again. `garrison setup`
/// runs from the installed release, which holds no archive to install from.
pub(crate) fn start_installed() -> Step {
    preflight()?;
    let _held = lock(Path::new(LOCK))?;
    let current = io(
        fs::canonicalize(Path::new(BASE).join("current")),
        &Path::new(BASE).join("current"),
    )?;
    protect_policy()?;
    install_system_files(&current)?;
    start(&current)?;
    announce(&format!(
        "Garrison {} is running.",
        current.file_name().unwrap_or_default().to_string_lossy()
    ));
    Ok(())
}

pub(crate) fn run_installer(rollback_requested: bool, with_state: bool) -> u8 {
    // The service users read the releases and /etc/garrison whatever the
    // operator's umask; credentials, backups and the policy set their own modes.
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
    let result = if rollback_requested {
        rollback::rollback(with_state)
    } else {
        install()
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            crate::complain(&error);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::unsettled;

    #[test]
    fn a_service_must_stay_active_without_restarts() {
        assert_eq!(unsettled("NRestarts=0\nActiveState=active\n"), None);
        assert_eq!(
            unsettled("ActiveState=active\nNRestarts=2\n").unwrap(),
            "restarted 2 times"
        );
        assert_eq!(
            unsettled("ActiveState=activating\nNRestarts=1\n").unwrap(),
            "is activating"
        );
        assert_eq!(unsettled("").unwrap(), "is unknown");
    }
}
