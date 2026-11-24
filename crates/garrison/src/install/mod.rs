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
mod release;
mod requirements;
mod restore;
mod rollback;
mod selinux;
mod services;
mod settle;
#[cfg(test)]
mod stand_in;
mod state;
mod system;
mod toml_text;
mod uninstall;
mod verify;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use crate::units;
use files::{Step, announce, io, lock, run};
use requirements::{base_shown, preflight};
pub(crate) use restore::run_restore;
use services::{start, stop_services};
use system::{install_system_files, protect_policy};
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
/// enables as it starts them and only an uninstallation disables, all of
/// them; any one still enabled counts, also where the operator disabled the
/// web service. Such an installation, whose configuration does not load or
/// whose policy is missing, is for check-config to refuse, not a first
/// installation.
fn configured(installed: bool) -> bool {
    Path::new(CONFIG).join("garrison.toml").exists()
        && (policy().exists() || (installed && started_before()))
}

fn started_before() -> bool {
    // `is-enabled` succeeds where any one of the units is enabled.
    let mut asked = vec!["is-enabled", "--quiet"];
    asked.extend(services::ENABLE);
    run(SYSTEMCTL, &asked).is_ok_and(|output| output.status.success())
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

/// Start the installed release once it is configured: what the second run of
/// the installer does, without unpacking a release again. `garrison setup`
/// runs from the installed release, which holds no archive to install from.
pub(crate) fn start_installed() -> Step {
    preflight()?;
    base_shown()?;
    let _held = lock(Path::new(LOCK))?;
    leftover()?;
    let current = io(
        fs::canonicalize(Path::new(BASE).join("current")),
        &Path::new(BASE).join("current"),
    )?;
    protect_policy()?;
    install_system_files(&current)?;
    start(&current)?;
    announce(&format!("Garrison {} is running.", name(&current)));
    Ok(())
}

/// A release's name: its folder's.
pub(super) fn name(release: &Path) -> String {
    release
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Installers built before 0.2.0 from the development branch left
/// `unfinished.json` for the next run. Nothing reads it any more: each run
/// that holds the lock names one it finds and removes it.
pub(super) fn leftover() -> Step {
    if let Some(line) = leftover_in(Path::new(BASE))? {
        announce(&line);
    }
    Ok(())
}

fn leftover_in(base: &Path) -> Step<Option<String>> {
    let path = base.join("unfinished.json");
    let Ok(text) = fs::read(&path) else {
        return Ok(None);
    };
    io(fs::remove_file(&path), &path)?;
    let record: serde_json::Value = serde_json::from_slice(&text).unwrap_or_default();
    let release = |key: &str| record[key].as_str().map(|path| name(Path::new(path)));
    let named = match (record["command"].as_str(), release("from"), release("to")) {
        (Some(command @ ("upgrade" | "rollback")), Some(from), Some(to)) => {
            format!("an unfinished {command} from {from} to {to}")
        }
        (Some("restore"), ..) => format!(
            "an unfinished restore from {}",
            record["source"].as_str().unwrap_or("a backup")
        ),
        _ => "a run it could not say".to_owned(),
    };
    Ok(Some(format!(
        "{} named {named}; nothing reads it any more: it was removed, and nothing was done on its \
         word.",
        path.display()
    )))
}

pub(crate) fn run_installer(rollback_requested: bool, with_state: bool) -> u8 {
    // The service users read the releases and /etc/garrison whatever the
    // operator's umask; credentials, backups and the policy set their own modes.
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
    let result = if rollback_requested {
        rollback::rollback(with_state)
    } else {
        release::install()
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

    /// A record as the development branch's installers wrote it, of each
    /// kind, and one that cannot be read: named once, removed, and then
    /// there is nothing more to say.
    #[test]
    fn a_record_an_earlier_installer_left_is_named_and_removed() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        assert_eq!(leftover_in(base), Ok(None));
        for (record, named) in [
            (
                r#"{"command": "upgrade", "from": "/opt/garrison/releases/0.1.2",
                    "to": "/opt/garrison/releases/0.2.0", "previous": null,
                    "backup": "/var/backups/garrison/pre-upgrade-20261124T080000",
                    "written": {"boot": "b", "starts": {}}}"#,
                "an unfinished upgrade from 0.1.2 to 0.2.0",
            ),
            (
                r#"{"command": "rollback", "from": "/opt/garrison/releases/0.2.0",
                    "to": "/opt/garrison/releases/0.1.2", "previous": null, "state": null}"#,
                "an unfinished rollback from 0.2.0 to 0.1.2",
            ),
            (
                r#"{"command": "restore", "source": "/root/kept",
                    "kept": "/var/backups/garrison/pre-restore-20261124T080000"}"#,
                "an unfinished restore from /root/kept",
            ),
            ("not a record", "a run it could not say"),
        ] {
            fs::write(base.join("unfinished.json"), record).unwrap();
            let said = leftover_in(base).unwrap().unwrap();
            assert!(said.contains(&format!(" named {named}; ")), "{said}");
            assert!(said.ends_with("nothing was done on its word."), "{said}");
            assert!(!base.join("unfinished.json").exists());
            assert_eq!(leftover_in(base), Ok(None));
        }
    }
}
