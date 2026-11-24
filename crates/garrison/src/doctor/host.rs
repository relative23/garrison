//! What this host shows about Garrison: the release, the services, the last
//! collection run, the access policy, files that must stay private, the
//! clock, free space, SELinux and recent events.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use garrison_collector::watch;
use garrison_core::config::{Config, Database};
use garrison_core::systemd::SYSTEMCTL;
use garrison_core::{sqlite, time};
use rusqlite::OptionalExtension;

use super::{Finding, counted};
use crate::units;

const SERVICES: [&str; 5] = units::RUNNING;
/// No event for this long on a mail server usually means no webhook.
const QUIET: i64 = 24 * 3600;
/// A snapshot or an event dated further ahead than this was written before
/// the clock went back, so its age is not known; within it, its age is none.
const AHEAD: i64 = 300;

fn output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn release() -> Finding {
    release_in(Path::new("/opt/garrison"))
}

/// The release installed under `base`, as the installer links it.
pub(super) fn release_in(base: &Path) -> Finding {
    let version = |link: &str| {
        fs::read_to_string(base.join(link).join("VERSION")).map(|text| text.trim().to_owned())
    };
    match (version("current"), version("previous")) {
        (Ok(current), Ok(previous)) => {
            Finding::ok(format!("release {current}, previous {previous}"))
        }
        (Ok(current), Err(_)) => Finding::ok(format!("release {current}, no previous release")),
        (Err(_), _) => Finding::fail(
            format!("no installed release in {}", base.join("current").display()),
            "Run the installer from the release archive.",
        ),
    }
}

/// What systemd's answer says of `unit`.
pub(super) fn service(unit: &str, answer: Option<&str>) -> Finding {
    match answer {
        Some("active") => Finding::ok(format!("{unit} is active")),
        Some(state) => Finding::fail(
            format!("{unit} is {state}"),
            format!("journalctl -u {unit} -n 50 shows why."),
        ),
        None => Finding::unknown(format!("{unit}: systemctl gave no answer")),
    }
}

fn services() -> Vec<Finding> {
    SERVICES
        .iter()
        .map(|unit| service(unit, output(SYSTEMCTL, &["is-active", unit]).as_deref()))
        .collect()
}

/// `1 minute ago` for a number of seconds; less than a minute is 0.
fn ago(seconds: i64) -> String {
    let minutes = usize::try_from(seconds / 60).unwrap_or(0);
    format!("{} ago", counted(minutes, "minute", "minutes"))
}

/// What the newest snapshot says of the collector, judged as the watch
/// judges it: stopped after ten minutes without a finished run.
pub(super) fn finished(last: Result<Option<i64>, String>, now: time::Timestamp) -> Finding {
    let why = format!(
        "`systemctl status {} {}` and `garrison check-config` say why.",
        units::COLLECT,
        units::COLLECT_TIMER
    );
    let seconds = |last: i64| now.as_second() - last;
    match last {
        Err(error) => Finding::unknown(format!(
            "when the collector last finished a run: the status database cannot be read ({error})"
        )),
        Ok(None) => Finding::warn(
            "no collection run has finished yet",
            format!("The collector runs every minute; if this stays, {why}"),
        ),
        // A damaged or hand-edited database: no age, and no stop either.
        Ok(Some(last)) if watch::stopped(last, now).is_none() => Finding::unknown(format!(
            "when the collector last finished a run: the newest status snapshot is dated \
             {last}, which is no time"
        )),
        Ok(Some(last)) if watch::stopped(last, now) == Some(true) => Finding::fail(
            format!(
                "no collection run has finished since {}, {}",
                time::Timestamp::from_second(last)
                    .map_or_else(|_| last.to_string(), time::isoformat),
                ago(seconds(last))
            ),
            format!("Until one does, Garrison checks nothing and reports nothing: {why}"),
        ),
        Ok(Some(last)) if -seconds(last) > AHEAD => Finding::warn(
            format!(
                "the newest status snapshot is dated {} minutes ahead of this host's clock, so its \
                 age is not known",
                -seconds(last) / 60
            ),
            "The clock went back after it was written; `timedatectl` shows whether it is \
             synchronized.",
        ),
        Ok(Some(last)) => Finding::ok(format!(
            "the last collection run finished {}",
            ago(seconds(last))
        )),
    }
}

/// What systemd says of the last run, where that is something. Its result
/// is "success" also for a unit that never ran, so that says nothing.
fn last_result(answer: Option<&str>) -> Option<Finding> {
    match answer {
        Some("success") => None,
        Some(result) if !result.is_empty() => Some(Finding::warn(
            format!("the last collection run ended with {result}"),
            format!("journalctl -u {} -n 50 shows why.", units::COLLECT),
        )),
        _ => Some(Finding::unknown(format!(
            "{}: systemctl gave no answer about its last run",
            units::COLLECT
        ))),
    }
}

/// When the collector last finished a run, and how its last run ended.
fn collection(config: &Config) -> Vec<Finding> {
    let database = config.database(Database::Status);
    let mut findings = vec![finished(watch::last_run(&database), time::now())];
    let result = output(
        SYSTEMCTL,
        &["show", "-p", "Result", "--value", units::COLLECT],
    );
    findings.extend(last_result(result.as_deref()));
    findings
}

fn clock() -> Finding {
    synchronized(
        output(
            "/usr/bin/timedatectl",
            &["show", "-p", "NTPSynchronized", "--value"],
        )
        .as_deref(),
    )
}

/// What timedatectl's answer says of the clock.
pub(super) fn synchronized(answer: Option<&str>) -> Finding {
    match answer {
        Some("yes") => Finding::ok("the clock is synchronized"),
        Some("no") => Finding::warn(
            "the clock is not synchronized",
            "Sign-in tokens and certificates depend on the time: enable a time service (timedatectl set-ntp true).",
        ),
        _ => Finding::unknown("clock synchronization: timedatectl gave no answer"),
    }
}

/// The room left on the disk of `path`, or, where it is not made yet, of
/// the nearest folder of it that exists, where it will be made: the
/// installer's room check judges it so.
pub(super) fn room(path: &str) -> Finding {
    let mut at = Path::new(path);
    let stat = loop {
        match rustix::fs::statvfs(at) {
            Ok(stat) => break stat,
            Err(rustix::io::Errno::NOENT) if at.parent().is_some() => {
                at = at.parent().unwrap_or(at);
            }
            Err(error) => return Finding::unknown(format!("free space of {path}: {error}")),
        }
    };
    let free = stat.f_bavail.saturating_mul(stat.f_frsize) >> 20;
    let shown = if at == Path::new(path) {
        path.to_owned()
    } else {
        format!(
            "{path} does not exist yet; {}, where it will be made,",
            at.display()
        )
    };
    if free >= 1024 {
        Finding::ok(format!("{shown} has {free} MiB free"))
    } else {
        Finding::warn(
            format!("{shown} has only {free} MiB free"),
            "Databases and backups grow; make room before the next upgrade.",
        )
    }
}

fn space() -> Vec<Finding> {
    ["/var/lib/garrison", "/var/backups"]
        .into_iter()
        .map(room)
        .collect()
}

/// Where SELinux says what it does, and where the installer writes the
/// module it loads (install/selinux.rs); a test names other places.
pub(super) struct SeLinux<'a> {
    /// `1` where SELinux enforces.
    pub(super) enforce: &'a str,
    /// The boolean that lets nginx connect to every port.
    pub(super) everywhere: &'a str,
    /// The module's text as the installer last wrote it, before it loads it.
    pub(super) module: &'a str,
}

const SELINUX: SeLinux<'static> = SeLinux {
    enforce: "/sys/fs/selinux/enforce",
    everywhere: "/sys/fs/selinux/booleans/httpd_can_network_connect",
    module: "/opt/garrison/selinux/garrison.cil",
};

/// The port the module's text lets nginx reach, as the installer writes it:
/// `(portcon tcp PORT …)`.
fn module_port(text: &str) -> Option<u16> {
    text.lines().find_map(|line| {
        line.strip_prefix("(portcon tcp ")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

const SEMODULE: &str = "/usr/sbin/semodule";

/// The module SELinux has loaded, as `semodule` extracts it into a folder
/// of doctor's own, or why there is none to read. The installer's file is
/// written before the module is loaded, so it names the port of a load that
/// may have failed.
fn loaded_module() -> Result<String, String> {
    let folder = std::env::temp_dir().join(format!("garrison-doctor-{}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&folder)
        .map_err(|error| format!("{}: {error}", folder.display()))?;
    let extracted = Command::new(SEMODULE)
        .args(["-c", "-E", "garrison"])
        .current_dir(&folder)
        .output();
    let text = fs::read_to_string(folder.join("garrison.cil"));
    let _ = fs::remove_dir_all(&folder);
    match (text, extracted) {
        (Ok(text), _) => Ok(text),
        (Err(_), Ok(output)) => Err(format!(
            "`semodule -c -E garrison` extracted no module ({})",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        (Err(_), Err(error)) => Err(format!("`semodule` did not run ({error})")),
    }
}

fn selinux(config: &Config) -> Option<Finding> {
    let listed = output(SEMODULE, &["-l"]).is_some_and(|list| {
        list.lines()
            .any(|line| line.split_whitespace().next() == Some("garrison"))
    });
    selinux_at(&SELINUX, listed.then(loaded_module), config.web.port)
}

/// Whether SELinux, where it is in use, lets nginx (`httpd_t`) reach the
/// web service on `port`: only a port of a type it may connect to, as the
/// module SELinux has loaded gives it. `loaded`: that module's text, or why
/// it could not be read, where `semodule -l` lists it.
pub(super) fn selinux_at(
    places: &SeLinux<'_>,
    loaded: Option<Result<String, String>>,
    port: u16,
) -> Option<Finding> {
    let enforcing = fs::read_to_string(places.enforce).ok()?.trim() == "1";
    let everywhere = fs::read_to_string(places.everywhere)
        .is_ok_and(|value| value.split_whitespace().next() == Some("1"));
    if everywhere {
        return Some(Finding::ok(
            "SELinux lets nginx connect to every port (httpd_can_network_connect)",
        ));
    }
    let Some(loaded) = loaded else {
        return Some(if enforcing {
            Finding::fail(
                "SELinux is enforcing and the module garrison is not loaded, so nginx cannot reach \
                 Garrison",
                "Run the installer again; it loads the module.",
            )
        } else {
            Finding::warn(
                "SELinux is permissive and the module garrison is not loaded",
                "Run the installer again.",
            )
        });
    };
    let labelled = loaded.and_then(|text| {
        module_port(&text).ok_or_else(|| "the loaded module names no port".to_owned())
    });
    Some(match labelled {
        Ok(labelled) if labelled == port => Finding::ok(format!(
            "the SELinux module garrison is loaded and lets nginx reach the web service on port \
             {port}"
        )),
        Ok(labelled) => {
            let what = format!(
                "the SELinux module garrison lets nginx reach port {labelled}, not {port} \
                 (web.port)"
            );
            // The installer loads nothing while its file is the one it
            // would write: after a load that failed, only a load by hand.
            let written = fs::read_to_string(places.module)
                .ok()
                .and_then(|text| module_port(&text));
            let fix = if written == Some(port) {
                format!(
                    "Load the module the installer wrote for web.port: semodule -i {}",
                    places.module
                )
            } else {
                "Run the installer again; it loads the module for web.port.".to_owned()
            };
            if enforcing {
                Finding::fail(format!("{what}, so nginx answers 502"), fix)
            } else {
                Finding::warn(
                    format!("{what}; SELinux is permissive and only logs the denial"),
                    fix,
                )
            }
        }
        Err(why) => Finding::unknown(format!(
            "which port the SELinux module garrison lets nginx reach: {why}"
        )),
    })
}

/// When the newest event arrived, as the history holds it: `None` where it
/// holds none, and why where it cannot be read, which is no answer that
/// none arrived.
fn newest_event(path: &Path) -> Result<Option<i64>, String> {
    let Some(reader) =
        sqlite::reading(path, Duration::from_secs(5)).map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    // The event stored last: after the clock went back, one received since
    // is dated before those it dated ahead.
    reader
        .query_row(
            "SELECT received_at FROM events ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| error.to_string())
}

pub(super) fn events(config: &Config) -> Finding {
    let path = config.database(Database::Events);
    let newest = match newest_event(&path) {
        Ok(newest) => newest,
        Err(error) => {
            return Finding::unknown(format!(
                "when the last Stalwart event arrived: the events database {} cannot be read \
                 ({error})",
                path.display()
            ));
        }
    };
    let now = time::now().as_second();
    match newest {
        // A damaged or hand-edited history: no age, neither recent nor old.
        Some(seconds) if time::Timestamp::from_second(seconds).is_err() => {
            Finding::unknown(format!(
                "when the last Stalwart event arrived: the newest event is recorded at \
                 {seconds}, which is no time"
            ))
        }
        // As for the newest snapshot: it arrived before the clock went back.
        Some(at) if at - now > AHEAD => Finding::warn(
            format!(
                "the last Stalwart event is recorded {} minutes ahead of this host's clock, so \
                 when it arrived is not known",
                (at - now) / 60
            ),
            "The clock went back after it arrived; `timedatectl` shows whether it is \
             synchronized.",
        ),
        Some(at) if now - at <= QUIET => {
            Finding::ok(format!("the last Stalwart event arrived {}", ago(now - at)))
        }
        Some(at) => Finding::warn(
            format!("no Stalwart event for {} hours", (now - at) / 3600),
            "Check the webhook in the Stalwart WebUI, or run `garrison stalwart setup` again.",
        ),
        None => Finding::warn(
            "no Stalwart event recorded yet",
            "Stalwart sends events through the webhook that `garrison stalwart setup` creates.",
        ),
    }
}

pub(super) fn checks(config: &Config) -> Vec<Finding> {
    let mut findings = vec![release()];
    findings.extend(services());
    findings.extend(collection(config));
    findings.extend(super::policy::checks(config));
    findings.extend(super::files::files(config));
    findings.push(clock());
    findings.extend(space());
    findings.extend(selinux(config));
    findings.push(events(config));
    findings
}

#[cfg(test)]
mod tests;
