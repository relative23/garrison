//! `garrison install`: install, upgrade or roll back from an extracted release.
//!
//! ```text
//! sudo ./garrison-<version>-<arch>/bin/garrison install
//! sudo /opt/garrison/current/bin/garrison install --rollback [--restore-state]
//! ```
//!
//! `garrison restore --from DIR` puts back what `garrison backup` wrote
//! (`restore.rs`).
//!
//! Every release lives in `/opt/garrison/releases/<version>`.
//! /opt/garrison/current and .../previous are symlinks; switching them is
//! the upgrade and the rollback. Before an upgrade the running state is
//! copied with the running release's `backup`. Nothing here touches Stalwart,
//! mail data or unrelated services.

mod command;
mod fallback;
mod files;
mod housekeeping;
mod milter;
mod precheck;
mod requirements;
mod restore;
mod rollback;
mod selinux;
mod services;
mod settle;
mod stale;
#[cfg(test)]
mod stand_in;
mod state;
mod system;
mod toml_text;
mod unfinished;
mod uninstall;
mod verify;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

use crate::{say, units};
use files::{Step, announce, copy_tree, exchange, fresh_folder, io, lock, place, run, switch};
use requirements::{preflight, room, size, state_size};
pub(crate) use restore::run_restore;
use services::{check_config, start, stop_services};
use system::{install_system_files, protect_policy};
use unfinished::{Seen, Unfinished};
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
pub(super) use garrison_core::systemd::SYSTEMCTL;

/// The access policy where the configuration names it, as the broker reads
/// it; the default place where the configuration does not load, which the
/// release's check of it then refuses.
pub(super) fn policy() -> PathBuf {
    policy_in(Path::new(CONFIG))
}

fn policy_in(config: &Path) -> PathBuf {
    garrison_core::config::load(&config.join("garrison.toml")).map_or_else(
        |_| config.join("access-policy.json"),
        |loaded| loaded.broker.policy,
    )
}

/// Whether Garrison is configured here: once its access policy is there,
/// and also where the installer started the services before, which it
/// enables as it starts them and only an uninstallation disables. Such an
/// installation, whose configuration does not load or whose policy is
/// missing, is for check-config to refuse, not a first installation.
fn configured(installed: bool) -> bool {
    Path::new(CONFIG).join("garrison.toml").exists()
        && (policy().exists() || (installed && started_before()))
}

fn started_before() -> bool {
    run(SYSTEMCTL, &["is-enabled", "--quiet", units::WEB])
        .is_ok_and(|output| output.status.success())
}

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

/// Back up the running state, and say where to. Only a change of release moves
/// `last-pre-upgrade`, the state `--rollback --restore-state` returns to: a
/// reinstall of the running release would otherwise replace it with data the
/// previous release cannot read.
fn backup_state(current: &Path, upgrade: bool) -> Step<PathBuf> {
    let kind = if upgrade {
        "pre-upgrade"
    } else {
        "pre-reinstall"
    };
    let target = fresh_folder(Path::new(BACKUPS), kind)
        .map_err(|error| format!("backup failed: {error}"))?;
    announce(&format!(
        "Backing up the running state to {}",
        target.display()
    ));
    let output = cli(current, &["backup", "--to", &target.display().to_string()])?;
    if !output.status.success() {
        let _ = fs::remove_dir_all(&target);
        return Err(format!(
            "backup failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    copy_config(Path::new(CONFIG), &target.join("etc"))?;
    if upgrade {
        switch(&Path::new(BACKUPS).join(LAST), &target)?;
    }
    Ok(target)
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
    // An upgrade that an earlier run began goes on, or is switched back first.
    let resumed = fallback::before_install(&version)?;
    let (old, earlier) = match &resumed {
        Some(resumed) => (Some(resumed.from.clone()), resumed.previous.clone()),
        None => (
            fs::canonicalize(&current).ok(),
            fs::canonicalize(base.join("previous")).ok(),
        ),
    };
    let configured = resumed.is_some() || configured(old.is_some());
    // Room for the release and, before an upgrade, the backup of the state.
    let mut needs = vec![(base, size(&here))];
    if old.is_some() && configured && resumed.is_none() {
        needs.push((Path::new(BACKUPS), state_size()));
    }
    room(&needs, "the installation")?;
    let release = install_release(&here, &version)?;
    // As `old` is: where /opt is a link, the path under BASE and the one the
    // links resolve to differ, and a reinstall would pass for an upgrade.
    let release = fs::canonicalize(&release).unwrap_or(release);
    let changed = old.as_deref().filter(|old| *old != release);
    let mut restore = false;
    let mut backup = None;
    if old.is_some() && configured {
        // The installer sets the policy's owner and mode anyway; the check must
        // not refuse what it is about to correct.
        protect_policy()?;
        // A configuration the new release refuses leaves the running one
        // alone. Its warnings follow as it starts.
        check_config(&release, false).map_err(|error| match &resumed {
            Some(resumed) => format!(
                "{error}; the upgrade from {} is still unfinished: run this installer again once \
                 check-config passes",
                unfinished::name(&resumed.from)
            ),
            None => format!("{error}; the running release was not touched"),
        })?;
        backup = Some(match &resumed {
            // The state may be the new release's by now.
            Some(resumed) => resumed.backup.clone(),
            None => backup_state(&current, changed.is_some())?,
        });
        // Compared with the state --restore-state returns to, the one from
        // before the upgrade to this release: a reinstall keeps it, and the
        // previous release still cannot read what this one migrated.
        restore = fs::canonicalize(Path::new(BACKUPS).join(LAST))
            .is_ok_and(|last| rollback::schema_rises(&last));
        // From here on, a run that is killed leaves an upgrade that the
        // next run finishes.
        if let (Some(from), Some(backup)) = (changed, &backup) {
            unfinished::write(&Unfinished::Upgrade {
                from: from.to_owned(),
                to: release.clone(),
                previous: earlier.clone(),
                backup: backup.clone(),
            })?;
        }
        stop_services();
    }
    if let Err(error) = switch_to(&release, changed, configured) {
        if !configured {
            return Err(error);
        }
        // Garrison is stopped now: whatever failed, the release that ran goes
        // back, with the databases the new one migrated as they were before.
        let outcome = match changed {
            Some(old) => {
                announce("Start failed; switching back to the previous release.");
                match fallback::switch_back(old, earlier.as_deref(), &release, backup.as_deref()) {
                    Ok(()) => match unfinished::done() {
                        Ok(()) => "the previous release is running".to_owned(),
                        Err(error) => format!("the previous release is running, but {error}"),
                    },
                    Err(failure) => failure,
                }
            }
            None => "no other release was started".to_owned(),
        };
        return Err(format!(
            "The new release did not start ({error}); {outcome}. See the journal."
        ));
    }
    unfinished::done()?;
    if !configured {
        return first_install_help();
    }
    let backups = Path::new(BACKUPS);
    for line in housekeeping::prune(base, backups, &backups.join(LAST)) {
        announce(&line);
    }
    // The release before cannot read a database this one migrates. Name the
    // rollback that works now, not only when a plain `--rollback` refuses.
    announce(&format!(
        "Garrison {version} is running. Roll back with: {} install --rollback{}",
        command::name(),
        if restore { " --restore-state" } else { "" }
    ));
    if restore {
        announce(
            "This upgrade changes a database schema: a rollback returns to the data \
             from before it, and what was recorded since is lost.",
        );
    }
    Ok(())
}

/// Start the installed release once it is configured: what the second run of
/// the installer does, without unpacking a release again. `garrison setup`
/// runs from the installed release, which holds no archive to install from.
pub(crate) fn start_installed() -> Step {
    preflight()?;
    let _held = lock(Path::new(LOCK))?;
    if let Seen::Holds(record) | Seen::Failed(record) = unfinished::read()? {
        return Err(record.not_started());
    }
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

/// The release that an upgrade an earlier run did not finish began from,
/// for `garrison upgrade` to compare an archive with.
pub(crate) fn upgrading_from() -> Option<PathBuf> {
    unfinished::upgrading_from()
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
    use super::*;

    #[test]
    fn the_policy_is_where_the_configuration_names_it() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path();
        // No configuration, or one that does not load: the default place.
        assert_eq!(policy_in(config), config.join("access-policy.json"));
        fs::write(config.join("garrison.toml"), "schema = 1\n[nonsense]\n").unwrap();
        assert_eq!(policy_in(config), config.join("access-policy.json"));
        let named = garrison_testing::config_text(config, "http://127.0.0.1:9");
        fs::write(config.join("garrison.toml"), named).unwrap();
        assert_eq!(policy_in(config), config.join("policy.json"));
    }
}
