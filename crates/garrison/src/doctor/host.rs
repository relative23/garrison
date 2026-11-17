//! What this host shows about Garrison: the release, the services, the last
//! collection run, files that must stay private, the clock, free space,
//! SELinux and recent events.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use garrison_collector::watch;
use garrison_core::config::{Config, Database};
use garrison_core::systemd::SYSTEMCTL;
use garrison_core::{sqlite, time};

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
    let version = |link: &str| {
        fs::read_to_string(Path::new("/opt/garrison").join(link).join("VERSION"))
            .map(|text| text.trim().to_owned())
    };
    match (version("current"), version("previous")) {
        (Ok(current), Ok(previous)) => {
            Finding::ok(format!("release {current}, previous {previous}"))
        }
        (Ok(current), Err(_)) => Finding::ok(format!("release {current}, no previous release")),
        (Err(_), _) => Finding::fail(
            "no installed release in /opt/garrison/current",
            "Run the installer from the release archive.",
        ),
    }
}

fn services() -> Vec<Finding> {
    SERVICES
        .iter()
        .map(
            |unit| match output(SYSTEMCTL, &["is-active", unit]).as_deref() {
                Some("active") => Finding::ok(format!("{unit} is active")),
                Some(state) => Finding::fail(
                    format!("{unit} is {state}"),
                    format!("journalctl -u {unit} -n 50 shows why."),
                ),
                None => Finding::unknown(format!("{unit}: systemctl gave no answer")),
            },
        )
        .collect()
}

/// `1 minute ago` for a number of seconds; less than a minute is 0.
fn ago(seconds: i64) -> String {
    let minutes = usize::try_from(seconds / 60).unwrap_or(0);
    format!("{} ago", counted(minutes, "minute", "minutes"))
}

/// What the newest snapshot says of the collector, judged as the watch
/// judges it: stopped after ten minutes without a finished run.
fn finished(last: Result<Option<i64>, String>, now: time::Timestamp) -> Finding {
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
    match output(
        "/usr/bin/timedatectl",
        &["show", "-p", "NTPSynchronized", "--value"],
    )
    .as_deref()
    {
        Some("yes") => Finding::ok("the clock is synchronized"),
        Some("no") => Finding::warn(
            "the clock is not synchronized",
            "Sign-in tokens and certificates depend on the time: enable a time service (timedatectl set-ntp true).",
        ),
        _ => Finding::unknown("clock synchronization: timedatectl gave no answer"),
    }
}

fn space() -> Vec<Finding> {
    ["/var/lib/garrison", "/var/backups"]
        .iter()
        .map(|path| match rustix::fs::statvfs(*path) {
            Ok(stat) => {
                let free = stat.f_bavail.saturating_mul(stat.f_frsize) >> 20;
                if free >= 1024 {
                    Finding::ok(format!("{path} has {free} MiB free"))
                } else {
                    Finding::warn(
                        format!("{path} has only {free} MiB free"),
                        "Databases and backups grow; make room before the next upgrade.",
                    )
                }
            }
            Err(_) => Finding::unknown(format!("free space of {path}")),
        })
        .collect()
}

fn selinux() -> Option<Finding> {
    let enforcing = fs::read_to_string("/sys/fs/selinux/enforce").ok()?;
    let loaded = output("/usr/sbin/semodule", &["-l"]).is_some_and(|list| {
        list.lines()
            .any(|line| line.split_whitespace().next() == Some("garrison"))
    });
    Some(if loaded {
        Finding::ok("the SELinux module garrison lets nginx reach the web service")
    } else if enforcing.trim() == "1" {
        Finding::fail(
            "SELinux is enforcing and the module garrison is not loaded, so nginx cannot reach Garrison",
            "Run the installer again; it loads the module.",
        )
    } else {
        Finding::warn(
            "SELinux is permissive and the module garrison is not loaded",
            "Run the installer again.",
        )
    })
}

fn events(config: &Config) -> Finding {
    let path = config.database(Database::Events);
    // The event stored last: after the clock went back, one received since
    // is dated before those it dated ahead.
    let newest = sqlite::reading(&path, Duration::from_secs(5))
        .ok()
        .flatten()
        .and_then(|reader| {
            reader
                .query_row(
                    "SELECT received_at FROM events ORDER BY rowid DESC LIMIT 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .ok()
        });
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
    findings.extend(super::files::files(config));
    findings.push(clock());
    findings.extend(space());
    findings.extend(selinux());
    findings.push(events(config));
    findings
}

#[cfg(test)]
mod tests;
