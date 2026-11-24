//! Starting and stopping Garrison's services, for the installer, the
//! rollback, the restore and the switch back after a failed start.

use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use garrison_core::config::{self, Config};
use garrison_core::credentials::Credentials;
use garrison_stalwart::jmap::JmapClient;

use super::files::{Step, announce, io, must, run};
use super::system::unit_file;
use super::{CONFIG, SYSTEMCTL, UNITS, cli, milter, settle};
use crate::doctor::milter::entries::{self, Entry};
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
    let held = milter && filter_held();
    // One start per unit: `restart` also starts a stopped unit. The units are
    // ready only once they serve, so a release that cannot come up fails here,
    // its broker too, which otherwise its first client would start.
    let mut restart = vec!["restart"];
    restart.extend(
        shipped
            .iter()
            .filter(|unit| !held || **unit != units::MILTER),
    );
    must(SYSTEMCTL, &restart)?;
    must(SYSTEMCTL, &["start", units::BROKER])?;
    settle::settle(milter)
}

/// Whether the macro filter is to stay where it runs, and says so: it listens
/// on a port `garrison.toml` no longer names, and a start would move it away
/// from an entry Stalwart asks there, which would then defer every message.
/// `garrison stalwart setup` moves the entry, then the filter.
fn filter_held() -> bool {
    let Ok(config) = config::load(&Path::new(CONFIG).join("garrison.toml")) else {
        return false;
    };
    let Some(filter) = &config.milter else {
        return false;
    };
    let Some(why) = held(filter.port, &entries::listening(), || {
        stalwart_milters(&config)
    }) else {
        return false;
    };
    announce(&format!(
        "The macro filter stays on the port it listens on, which garrison.toml no longer names: \
         {why}. `garrison stalwart setup` moves it to port {}.",
        filter.port
    ));
    true
}

/// Why the filter, listening on `listening`, is not to move to `port`: an
/// entry Stalwart asks at a port it would leave, or Stalwart's milters that
/// could not be asked; `None` where it may move.
fn held(
    port: u16,
    listening: &[u16],
    entries: impl FnOnce() -> Result<Vec<Entry>, String>,
) -> Option<String> {
    let left: Vec<u16> = listening
        .iter()
        .copied()
        .filter(|old| *old != port)
        .collect();
    if left.is_empty() {
        return None;
    }
    match entries() {
        Ok(entries) => entries
            .iter()
            .find(|entry| entry.asked() && left.iter().any(|old| entry.asks(*old)))
            .map(|entry| {
                format!(
                    "Stalwart asks its milter entry {} at {}",
                    entry.id,
                    entry.address()
                )
            }),
        Err(why) => Some(format!("Stalwart's milters could not be asked ({why})")),
    }
}

/// Stalwart's milters, as the collector's API key reads them.
fn stalwart_milters(config: &Config) -> Result<Vec<Entry>, String> {
    let key = Credentials::new(&config.credentials_directory)
        .read_secret(&config.collector.native_key)
        .map_err(|error| format!("the collector's API key: {error}"))?;
    JmapClient::new(&config.deployment.stalwart_url, &key)
        .with_timeout(Duration::from_secs(10))
        .get::<Entry>("MtaMilter", None, &["id", "host", "port", "enable"])
        .map_err(|error| error.to_string())
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

/// Whether the services run as `start` leaves them, on the configuration as
/// it is; `milter` whether the macro filter is to run.
pub(super) fn as_installed(milter: bool) -> bool {
    let shipped: Vec<&str> = ENABLE
        .into_iter()
        .filter(|unit| unit_file(unit).exists())
        .collect();
    let mut asked = vec!["show", "-p", "Id", "-p", "ActiveState", "-p", "NRestarts"];
    asked.extend([
        "-p",
        "UnitFileState",
        "-p",
        "ExecMainStartTimestampMonotonic",
    ]);
    asked.extend(&shipped);
    asked.extend([units::BROKER, units::MILTER]);
    let changed = changed_at(&Path::new(CONFIG).join("garrison.toml"));
    run(SYSTEMCTL, &asked).is_ok_and(|shown| {
        installed(
            &String::from_utf8_lossy(&shown.stdout),
            &shipped,
            milter,
            changed,
        )
    })
}

/// When `file` last changed, in microseconds of the clock systemd times a
/// start by (`CLOCK_MONOTONIC`): its age by the wall clock, back from now. A
/// file dated ahead of the wall clock changed now.
fn changed_at(file: &Path) -> Option<u64> {
    let modified = fs::metadata(file).ok()?.modified().ok()?;
    let age = u64::try_from(modified.elapsed().unwrap_or_default().as_micros()).ok()?;
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let now = u64::try_from(now.tv_sec)
        .ok()?
        .checked_mul(1_000_000)?
        .checked_add(u64::try_from(now.tv_nsec).ok()? / 1_000)?;
    Some(now.saturating_sub(age))
}

/// `shown`, what `systemctl show` says of the units, as `start` leaves them:
/// every unit in `shipped` enabled and active, the web service, the receiver
/// and the broker up without a restart, and the macro filter active exactly
/// where `milter` says; each of those that runs started since the
/// configuration `changed`, which it reads as it starts.
fn installed(shown: &str, shipped: &[&str], milter: bool, changed: Option<u64>) -> bool {
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
    let since = |id: &str| {
        let started = value(unit(id), "ExecMainStartTimestampMonotonic").parse::<u64>();
        started
            .ok()
            .zip(changed)
            .is_some_and(|(started, changed)| started >= changed)
    };
    let steady = [units::WEB, units::INGEST, units::BROKER]
        .into_iter()
        .all(|id| settle::unsettled(unit(id)).is_none() && since(id));
    let filter = value(unit(units::MILTER), "ActiveState") == "active";
    enabled && steady && filter == milter && (!milter || since(units::MILTER))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The filter stays on a port it would leave where Stalwart asks an
    /// entry there that is switched on, or where Stalwart cannot be asked;
    /// it moves where it does not run, runs on its port already, or nothing
    /// asks the port it leaves.
    #[test]
    fn the_filter_stays_where_stalwart_asks_it() {
        let read = |list: serde_json::Value| -> Result<Vec<Entry>, String> {
            Ok(serde_json::from_value(list).unwrap())
        };
        let unasked = || -> Result<Vec<Entry>, String> { panic!("asked Stalwart") };
        assert_eq!(held(8097, &[], unasked), None);
        assert_eq!(held(8097, &[8097], unasked), None);
        let said = held(8097, &[8096], || {
            read(json!([{"id": "m1", "host": "127.0.0.1", "port": 8096, "enable": true}]))
        });
        assert_eq!(
            said.as_deref(),
            Some("Stalwart asks its milter entry m1 at 127.0.0.1:8096")
        );
        for others in [
            json!([{"id": "m1", "host": "127.0.0.1", "port": 8096, "enable": {"match": {}, "else": "false"}}]),
            json!([{"id": "m1", "host": "10.0.0.5", "port": 8096}]),
            json!([{"id": "m1", "host": "127.0.0.1", "port": 8097}]),
            json!([]),
        ] {
            assert_eq!(
                held(8097, &[8096], || read(others.clone())),
                None,
                "{others}"
            );
        }
        let refused = held(8097, &[8096], || Err("Stalwart did not answer".to_owned()));
        assert_eq!(
            refused.as_deref(),
            Some("Stalwart's milters could not be asked (Stalwart did not answer)")
        );
    }

    fn block(id: &str, file: &str, state: &str, restarts: u32) -> String {
        format!(
            "Id={id}\nUnitFileState={file}\nActiveState={state}\nNRestarts={restarts}\n\
             ExecMainStartTimestampMonotonic=5000000\n"
        )
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
        let installed_as =
            |text: &str, milter: bool| installed(text, &ENABLE, milter, Some(4_000_000));
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
        assert!(installed(&text, &without_watch, false, Some(4_000_000)));
        // The configuration changed after the services started, or nobody
        // can tell when it changed: they run on what they read before.
        let steady = shown(("enabled", "active", 0), "inactive");
        assert!(installed(&steady, &ENABLE, false, Some(5_000_000)));
        assert!(!installed(&steady, &ENABLE, false, Some(5_000_001)));
        assert!(!installed(&steady, &ENABLE, false, None));
        // So does the filter, where it runs.
        let filter = shown(("enabled", "active", 0), "active");
        assert!(installed(&filter, &ENABLE, true, Some(5_000_000)));
        let older = filter.replace(
            "Id=garrison-milter.service\nUnitFileState=disabled\nActiveState=active\nNRestarts=0\n\
             ExecMainStartTimestampMonotonic=5000000",
            "Id=garrison-milter.service\nUnitFileState=disabled\nActiveState=active\nNRestarts=0\n\
             ExecMainStartTimestampMonotonic=1000000",
        );
        assert_ne!(older, filter);
        assert!(!installed(&older, &ENABLE, true, Some(4_000_000)));
    }

    /// A file changed just now is dated now on the clock systemd times a
    /// start by; one dated ahead of the wall clock counts as changed now;
    /// none, unknown.
    #[test]
    fn a_change_is_dated_on_the_clock_of_a_start() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("garrison.toml");
        assert_eq!(changed_at(&file), None);
        fs::write(&file, "schema = 1\n").unwrap();
        let clock = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        let now = u128::try_from(clock.tv_sec).unwrap() * 1_000_000
            + u128::try_from(clock.tv_nsec).unwrap() / 1_000;
        let changed = changed_at(&file).unwrap();
        assert!(u128::from(changed) <= now + 1_000_000, "{changed} {now}");
        assert!(u128::from(changed) + 2_000_000 >= now, "{changed} {now}");
        let ahead = std::time::SystemTime::now() + Duration::from_hours(1);
        fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(ahead)
            .unwrap();
        let now_again = changed_at(&file).unwrap();
        assert!(now_again >= changed, "{now_again} {changed}");
    }
}
