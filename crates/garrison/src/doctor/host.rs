//! What this host shows about Garrison: the release, the services, the last
//! collection run, files that must stay private, the clock, free space,
//! SELinux and recent events.

use std::fs;
use std::os::unix::fs::MetadataExt;
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
const CREDENTIALS: [&str; 4] = [
    "webhook-signature-key",
    "collector-native-key",
    "broker-native-key",
    "metrics-credential",
];
/// No event for this long on a mail server usually means no webhook.
const QUIET_HOURS: f64 = 24.0;
/// A snapshot dated further ahead than this was written before the clock
/// went back, so its age is not known.
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

/// Root-owned and readable by nobody else (`group` may read the policy).
fn private(path: &Path, what: &str, group_read: bool) -> Finding {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Finding::fail(
            format!("{what} is missing: {}", path.display()),
            "Run `garrison stalwart setup` or the installer again.",
        );
    };
    let allowed = if group_read { 0o640 } else { 0o600 };
    let mode = metadata.mode() & 0o777;
    if metadata.is_file() && metadata.uid() == 0 && mode & !allowed == 0 {
        Finding::ok(format!("{what} is private ({mode:o})"))
    } else {
        Finding::fail(
            format!(
                "{} is not root-owned with mode {allowed:o} or less (mode {mode:o})",
                path.display()
            ),
            "Run the installer again; it sets owner and mode.",
        )
    }
}

fn files(config: &Config) -> Vec<Finding> {
    // Where the broker reads it.
    let mut findings = vec![private(&config.broker.policy, "the access policy", true)];
    // Root reads it; the broker, in its unit's sandbox, may not.
    if let Some((what, fix)) = units::hidden_policy(&config.broker.policy) {
        findings.push(Finding::fail(what, format!("{fix}.")));
    }
    for name in CREDENTIALS {
        findings.push(private(
            &config.credentials_directory.join(name),
            name,
            false,
        ));
    }
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
    let newest = sqlite::reading(&path, Duration::from_secs(5))
        .ok()
        .flatten()
        .and_then(|reader| {
            reader
                .query_row("SELECT max(received_at) FROM events", [], |row| {
                    row.get::<_, Option<i64>>(0)
                })
                .ok()
                .flatten()
        });
    match newest {
        #[allow(clippy::cast_precision_loss)]
        Some(seconds) => {
            let hours = (time::unix(time::now()) - seconds as f64) / 3600.0;
            if hours <= QUIET_HOURS {
                Finding::ok(format!(
                    "the last Stalwart event arrived {} minutes ago",
                    (hours * 60.0).round()
                ))
            } else {
                Finding::warn(
                    format!("no Stalwart event for {} hours", hours.round()),
                    "Check the webhook in the Stalwart WebUI, or run `garrison stalwart setup` again.",
                )
            }
        }
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
    findings.extend(files(config));
    findings.push(clock());
    findings.extend(space());
    findings.extend(selinux());
    findings.push(events(config));
    findings
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use garrison_collector::snapshot::{SCHEMA, Snapshot};
    use garrison_collector::store::StatusStore;

    use super::super::Level;
    use super::*;

    const NOW: i64 = 1_794_000_000;

    fn judged(last: Result<Option<i64>, String>) -> Finding {
        finished(last, time::Timestamp::from_second(NOW).unwrap())
    }

    #[test]
    fn the_collector_is_judged_by_its_newest_snapshot_as_the_watch_judges_it() {
        let fresh = judged(Ok(Some(NOW - 90)));
        assert_eq!(
            (fresh.level, fresh.what.as_str()),
            (Level::Ok, "the last collection run finished 1 minute ago")
        );
        assert_eq!(judged(Ok(Some(NOW - watch::LIMIT))).level, Level::Ok);
        // A run that never was is not a success, and not yet a failure.
        let never = judged(Ok(None));
        assert_eq!(
            (never.level, never.what.as_str()),
            (Level::Warn, "no collection run has finished yet")
        );
        // Stopped, failed and unknown stay three answers.
        let stopped = judged(Ok(Some(NOW - watch::LIMIT - 1)));
        assert_eq!(stopped.level, Level::Fail);
        assert_eq!(
            stopped.what,
            "no collection run has finished since 2026-11-06T21:09:59+00:00, 10 minutes ago"
        );
        assert!(
            stopped.line().contains(
                "`systemctl status garrison-collect.service garrison-collect.timer` and \
                 `garrison check-config` say why."
            ),
            "{}",
            stopped.line()
        );
        let unreadable = judged(Err("file is not a database".to_owned()));
        assert_eq!(unreadable.level, Level::Unknown);
        assert!(unreadable.what.ends_with("(file is not a database)"));
        // A date from the future gives no age; a few minutes are the clock's
        // own small corrections.
        let ahead = judged(Ok(Some(NOW + 3600)));
        assert_eq!(ahead.level, Level::Warn);
        assert!(ahead.what.contains("60 minutes ahead"), "{}", ahead.what);
        assert_eq!(
            judged(Ok(Some(NOW + 120))).what,
            "the last collection run finished 0 minutes ago"
        );
    }

    /// A damaged or hand-edited status database may date its newest snapshot
    /// at a time that is none: it gives no age, and no stop either.
    #[test]
    fn a_snapshot_dated_at_no_time_gives_no_age() {
        for when in [i64::MIN, i64::MAX] {
            let found = judged(Ok(Some(when)));
            assert_eq!(
                (found.level, found.what),
                (
                    Level::Unknown,
                    format!(
                        "when the collector last finished a run: the newest status snapshot \
                         is dated {when}, which is no time"
                    )
                )
            );
        }
    }

    #[test]
    fn systemd_names_only_a_last_run_that_did_not_succeed() {
        assert!(last_result(Some("success")).is_none());
        let failed = last_result(Some("exit-code")).unwrap();
        assert_eq!(
            (failed.level, failed.what.as_str()),
            (Level::Warn, "the last collection run ended with exit-code")
        );
        for silent in [None, Some("")] {
            assert_eq!(last_result(silent).unwrap().level, Level::Unknown);
        }
    }

    /// The access policy is looked at where the configuration names it,
    /// which is where the broker reads it.
    #[test]
    fn the_policy_is_judged_where_the_configuration_names_it() {
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let policy = &files(&config)[0];
        assert_eq!(
            policy.what,
            format!(
                "the access policy is missing: {}",
                config.broker.policy.display()
            )
        );
        // Root may read a policy that the broker's unit hides from it.
        let mut hidden = config.clone();
        hidden.broker.policy = "/home/doctor-test/policy.json".into();
        let found = files(&hidden);
        let named = found
            .iter()
            .find(|finding| finding.what.contains("(ProtectHome=true)"))
            .unwrap();
        assert_eq!(named.level, Level::Fail, "{}", named.line());
    }

    #[test]
    fn the_newest_snapshot_is_read_from_the_status_database() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("status.sqlite");
        assert_eq!(
            finished(watch::last_run(&database), time::now()).level,
            Level::Warn
        );
        let mut store = StatusStore::open(&database, 90).unwrap();
        let snapshot = Snapshot {
            schema_version: SCHEMA,
            collected_at: time::now_isoformat(),
            observations: Vec::new(),
            provider_errors: Vec::new(),
        };
        let written = time::now().as_second() - 120;
        store
            .write(written, &snapshot, &BTreeMap::new(), &BTreeMap::new())
            .unwrap();
        drop(store);
        let fresh = finished(watch::last_run(&database), time::now());
        assert_eq!(fresh.level, Level::Ok, "{}", fresh.line());
        // Doctor reads as root and follows no link to a database.
        let linked = directory.path().join("linked.sqlite");
        std::os::unix::fs::symlink(&database, &linked).unwrap();
        assert_eq!(
            finished(watch::last_run(&linked), time::now()).level,
            Level::Unknown
        );
    }
}
