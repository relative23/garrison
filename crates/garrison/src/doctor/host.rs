//! What this host shows about Garrison: the release, the services, the last
//! collection run, the access policy, files that must stay private, the
//! clock, free space, SELinux and recent events.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use garrison_collector::watch;
use garrison_core::config::{Config, Database};
use garrison_core::systemd::SYSTEMCTL;
use garrison_core::{sqlite, time};
use rusqlite::OptionalExtension;

use super::Finding;
use super::states::host as states;
use super::states::selinux as selinux_states;
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
        (Ok(current), previous) => Finding::ok(states::release(&current, previous.ok().as_deref())),
        (Err(_), _) => Finding::fail(states::no_release(&base.join("current"))),
    }
}

/// What systemd's answer says of `unit`.
pub(super) fn service(unit: &str, answer: Option<&str>) -> Finding {
    match answer {
        Some("active") => Finding::ok(states::active(unit)),
        Some(state) => Finding::fail(states::inactive(unit, state)),
        None => Finding::unknown(states::unanswered_service(unit)),
    }
}

fn services() -> Vec<Finding> {
    SERVICES
        .iter()
        .map(|unit| service(unit, output(SYSTEMCTL, &["is-active", unit]).as_deref()))
        .collect()
}

/// What the newest snapshot says of the collector, judged as the watch
/// judges it: stopped after ten minutes without a finished run.
pub(super) fn finished(last: Result<Option<i64>, String>, now: time::Timestamp) -> Finding {
    let seconds = |last: i64| now.as_second() - last;
    match last {
        Err(error) => Finding::unknown(states::collection_unreadable(&error)),
        Ok(None) => Finding::warn(states::no_collection()),
        // A damaged or hand-edited database: no age, and no stop either.
        Ok(Some(last)) if watch::stopped(last, now).is_none() => {
            Finding::unknown(states::collection_undated(last))
        }
        Ok(Some(last)) if watch::stopped(last, now) == Some(true) => {
            Finding::fail(states::collection_stopped(last, seconds(last)))
        }
        Ok(Some(last)) if -seconds(last) > AHEAD => {
            Finding::warn(states::snapshot_ahead(-seconds(last)))
        }
        Ok(Some(last)) => Finding::ok(states::collection_recent(seconds(last))),
    }
}

/// What systemd says of the last run, where that is something. Its result
/// is "success" also for a unit that never ran, so that says nothing.
fn last_result(answer: Option<&str>) -> Option<Finding> {
    match answer {
        Some("success") => None,
        Some(result) if !result.is_empty() => Some(Finding::warn(states::run_failed(result))),
        _ => Some(Finding::unknown(states::run_unknown())),
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
        Some("yes") => Finding::ok(states::synchronized()),
        Some("no") => Finding::warn(states::unsynchronized()),
        _ => Finding::unknown(states::clock_unknown()),
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
            Err(error) => return Finding::unknown(states::space_unknown(path, error)),
        }
    };
    let free = stat.f_bavail.saturating_mul(stat.f_frsize) >> 20;
    if free >= 1024 {
        Finding::ok(states::room(path, at, free))
    } else {
        Finding::warn(states::little_room(path, at, free))
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

/// Why the module SELinux has loaded could not be read.
#[derive(Debug)]
pub(super) enum Unread {
    /// No name could be drawn for the folder to extract it into.
    Unnamed(getrandom::Error),
    /// That folder could not be made.
    Folder(PathBuf, std::io::Error),
    /// `semodule` extracted no module, with what it said.
    Unextracted(String),
    /// `semodule` did not run.
    Unrun(std::io::Error),
    /// The module names no port.
    NoPort,
}

/// The module SELinux has loaded, as `semodule` extracts it into a folder
/// of doctor's own, or why there is none to read. The installer's file
/// names the port of its last load that succeeded, or, where an earlier
/// release wrote it before loading, of a load that may have failed.
fn loaded_module() -> Result<String, Unread> {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(Unread::Unnamed)?;
    let name = garrison_core::hex::encode(&random);
    let folder = std::env::temp_dir().join(format!("garrison-doctor-{name}"));
    if let Err(error) = fs::DirBuilder::new().mode(0o700).create(&folder) {
        return Err(Unread::Folder(folder, error));
    }
    let extracted = Command::new(SEMODULE)
        .args(["-c", "-E", "garrison"])
        .current_dir(&folder)
        .output();
    let text = fs::read_to_string(folder.join("garrison.cil"));
    let _ = fs::remove_dir_all(&folder);
    match (text, extracted) {
        (Ok(text), _) => Ok(text),
        (Err(_), Ok(output)) => Err(Unread::Unextracted(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        )),
        (Err(_), Err(error)) => Err(Unread::Unrun(error)),
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
    loaded: Option<Result<String, Unread>>,
    port: u16,
) -> Option<Finding> {
    let enforcing = fs::read_to_string(places.enforce).ok()?.trim() == "1";
    let everywhere = fs::read_to_string(places.everywhere)
        .is_ok_and(|value| value.split_whitespace().next() == Some("1"));
    if everywhere {
        return Some(Finding::ok(selinux_states::everywhere()));
    }
    let Some(loaded) = loaded else {
        return Some(if enforcing {
            Finding::fail(selinux_states::unloaded())
        } else {
            Finding::warn(selinux_states::unloaded_permissive())
        });
    };
    let labelled = loaded.and_then(|text| module_port(&text).ok_or(Unread::NoPort));
    Some(match labelled {
        Ok(labelled) if labelled == port => Finding::ok(selinux_states::port_reached(port)),
        Ok(labelled) => {
            // The installer loads nothing while its file is the one it
            // would write, as an earlier release left it after a load that
            // failed: then only a load by hand does.
            let written = fs::read_to_string(places.module)
                .ok()
                .and_then(|text| module_port(&text));
            match (written == Some(port), enforcing) {
                (true, true) => {
                    Finding::fail(selinux_states::load_failed(labelled, port, places.module))
                }
                (true, false) => Finding::warn(selinux_states::load_failed_permissive(
                    labelled,
                    port,
                    places.module,
                )),
                (false, true) => Finding::fail(selinux_states::other_port(labelled, port)),
                (false, false) => {
                    Finding::warn(selinux_states::other_port_permissive(labelled, port))
                }
            }
        }
        Err(why) => Finding::unknown(selinux_states::port_unknown(&why)),
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
        Err(error) => return Finding::unknown(states::events_unreadable(&path, &error)),
    };
    let now = time::now().as_second();
    match newest {
        // A damaged or hand-edited history: no age, neither recent nor old.
        Some(seconds) if time::Timestamp::from_second(seconds).is_err() => {
            Finding::unknown(states::event_undated(seconds))
        }
        // As for the newest snapshot: it arrived before the clock went back.
        Some(at) if at - now > AHEAD => Finding::warn(states::event_ahead(at - now)),
        Some(at) if now - at <= QUIET => Finding::ok(states::event_recent(now - at)),
        Some(at) => Finding::warn(states::quiet(now - at)),
        None => Finding::warn(states::no_event()),
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
