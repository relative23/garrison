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
/// address kept there.
fn keep_secret_files() -> Step {
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
    }
    Ok(())
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
