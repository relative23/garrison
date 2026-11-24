//! Starting and stopping Garrison's services, for the installer, the
//! rollback, the restore and the switch back after a failed start.

use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::files::{Step, io, must, run};
use super::system::unit_file;
use super::{CONFIG, SYSTEMCTL, UNITS, cli, milter, settle};
use crate::units;

pub(super) const ENABLE: [&str; 5] = [
    units::BROKER_SOCKET,
    units::WEB,
    units::INGEST,
    units::COLLECT_TIMER,
    units::WATCH_TIMER,
];
// Everything that writes Garrison's state: the services, the timers, and a
// collection run or a watch that a timer started, which stopping the timer
// alone would leave running. The macro milter is not among them: it keeps
// nothing, and while it is down Stalwart defers mail. It starts anew with
// the others.
const STOP: [&str; 8] = [
    units::WEB,
    units::INGEST,
    units::COLLECT_TIMER,
    units::WATCH_TIMER,
    units::COLLECT,
    units::WATCH,
    units::BROKER,
    units::BROKER_SOCKET,
];

/// The release's own `check-config` against the system configuration. What
/// it said goes to standard error with the installer's own reason, so that
/// a script that keeps only that stream learns which setting failed. Where
/// it passes, its warnings, such as a setting the units do not follow, are
/// passed on with `warnings`: the installer's output is where an operator
/// reads them during an upgrade.
pub(super) fn check_config(release: &Path, warnings: bool) -> Step {
    let check = cli(release, &["check-config"])?;
    if !check.status.success() {
        crate::complain(&format!(
            "{}\n{}",
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr)
        ));
        return Err("check-config failed".into());
    }
    let said = String::from_utf8_lossy(&check.stderr);
    if warnings && !said.trim().is_empty() {
        crate::complain(said.trim_end());
    }
    Ok(())
}

/// The collector's units load the notification channels' secrets and the
/// addresses kept as secrets, and the collector its metrics credential,
/// which setup writes only where Stalwart's exporter is Garrison's. systemd
/// refuses to start a unit whose credential file is missing, so an
/// installation that has none gets empty ones, which mean: no secret, no
/// address kept there. Whether any had to be made.
pub(super) fn keep_secret_files() -> Step<bool> {
    let mut made = false;
    for name in units::NOTIFICATION_FILES
        .iter()
        .chain(&units::COLLECTOR_FILES)
    {
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
        made = true;
    }
    Ok(made)
}

pub(super) fn start(release: &Path) -> Step {
    check_config(release, true)?;
    keep_secret_files()?;
    reset_failed();
    // Only what this release ships: an older one has fewer units.
    let shipped = ENABLE.into_iter().filter(|unit| unit_file(unit).exists());
    let mut shipped: Vec<&str> = shipped.collect();
    let milter = milter::runs();
    if milter {
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
    settle::settle(milter)
}

/// Forget failures and systemd's start limit (5 starts in 10 s) left by a
/// crash loop, so that a rollback right after a broken upgrade can start.
fn reset_failed() {
    let mut reset = vec!["reset-failed"];
    reset.extend(UNITS);
    let _ = run(SYSTEMCTL, &reset);
}

pub(super) fn stop_services() {
    let mut stop = vec!["stop"];
    stop.extend(STOP);
    let _ = run(SYSTEMCTL, &stop);
}

/// Whether a release runs here: its web service or its receiver is active.
pub(super) fn runs() -> bool {
    [units::WEB, units::INGEST].into_iter().any(|unit| {
        run(SYSTEMCTL, &["is-active", "--quiet", unit]).is_ok_and(|output| output.status.success())
    })
}

/// Whether the services run as `start` leaves them; `milter` whether the
/// macro filter is to run.
pub(super) fn as_installed(milter: bool) -> bool {
    let shipped: Vec<&str> = ENABLE
        .into_iter()
        .filter(|unit| unit_file(unit).exists())
        .collect();
    let mut asked = vec!["show", "-p", "Id", "-p", "ActiveState", "-p", "NRestarts"];
    asked.extend(["-p", "UnitFileState"]);
    asked.extend(&shipped);
    asked.extend([units::BROKER, units::MILTER]);
    run(SYSTEMCTL, &asked)
        .is_ok_and(|shown| installed(&String::from_utf8_lossy(&shown.stdout), &shipped, milter))
}

/// `shown`, what `systemctl show` says of the units, as `start` leaves them:
/// every unit in `shipped` enabled and active, the web service, the receiver
/// and the broker up without a restart, and the macro filter active exactly
/// where `milter` says.
fn installed(shown: &str, shipped: &[&str], milter: bool) -> bool {
    let unit = |id: &str| {
        shown
            .split("\n\n")
            .find(|block| {
                block
                    .lines()
                    .any(|line| line.strip_prefix("Id=") == Some(id))
            })
            .unwrap_or_default()
    };
    let value = |block: &str, key: &str| {
        block
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_default()
            .to_owned()
    };
    let enabled = shipped.iter().all(|id| {
        value(unit(id), "UnitFileState") == "enabled" && value(unit(id), "ActiveState") == "active"
    });
    let steady = [units::WEB, units::INGEST, units::BROKER]
        .into_iter()
        .all(|id| settle::unsettled(unit(id)).is_none());
    let filter = value(unit(units::MILTER), "ActiveState") == "active";
    enabled && steady && filter == milter
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(id: &str, file: &str, state: &str, restarts: u32) -> String {
        format!("Id={id}\nUnitFileState={file}\nActiveState={state}\nNRestarts={restarts}\n")
    }

    /// Every unit enabled and active, the long-running ones without a
    /// restart, the filter as the configuration has it: as installed. Any
    /// one otherwise, or a unit systemd did not name, is not.
    #[test]
    fn the_services_run_as_installed_only_where_every_unit_does() {
        let shown = |web: (&str, &str, u32), milter: &str| {
            let mut units: Vec<String> = ENABLE
                .into_iter()
                .filter(|unit| *unit != units::WEB)
                .map(|unit| block(unit, "enabled", "active", 0))
                .collect();
            units.push(block(units::WEB, web.0, web.1, web.2));
            units.push(block(units::BROKER, "static", "active", 0));
            units.push(block(units::MILTER, "disabled", milter, 0));
            units.join("\n")
        };
        let installed_as = |text: &str, milter: bool| installed(text, &ENABLE, milter);
        assert!(installed_as(
            &shown(("enabled", "active", 0), "inactive"),
            false
        ));
        assert!(installed_as(
            &shown(("enabled", "active", 0), "active"),
            true
        ));
        // The filter runs where the configuration no longer has it, or not
        // where it has.
        assert!(!installed_as(
            &shown(("enabled", "active", 0), "active"),
            false
        ));
        assert!(!installed_as(
            &shown(("enabled", "active", 0), "inactive"),
            true
        ));
        for web in [
            ("disabled", "active", 0),
            ("enabled", "activating", 0),
            ("enabled", "failed", 0),
            ("enabled", "active", 2),
        ] {
            assert!(!installed_as(&shown(web, "inactive"), false), "{web:?}");
        }
        assert!(!installed_as("", false));
        // Only what the release ships is asked of it.
        let without_watch: Vec<&str> = ENABLE
            .into_iter()
            .filter(|unit| *unit != units::WATCH_TIMER)
            .collect();
        let text = shown(("enabled", "active", 0), "inactive").replace(
            "Id=garrison-watch.timer\nUnitFileState=enabled",
            "Id=garrison-watch.timer\nUnitFileState=",
        );
        assert!(!installed_as(&text, false));
        assert!(installed(&text, &without_watch, false));
    }
}
