//! What this host shows about Garrison: the release, the services, files
//! that must stay private, the clock, free space, SELinux and recent events.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use garrison_core::config::{Config, Database};
use garrison_core::systemd::SYSTEMCTL;
use garrison_core::{sqlite, time};

use super::Finding;
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
    let mut findings: Vec<Finding> = SERVICES
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
        .collect();
    match output(
        SYSTEMCTL,
        &["show", "-p", "Result", "--value", units::COLLECT],
    )
    .as_deref()
    {
        Some("success") => findings.push(Finding::ok("the last collection run succeeded")),
        Some(result) => findings.push(Finding::warn(
            format!("the last collection run ended with {result}"),
            "journalctl -u garrison-collect.service -n 50 shows why.",
        )),
        None => findings.push(Finding::unknown("the last collection run")),
    }
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
    let mut findings = vec![private(
        Path::new("/etc/garrison/access-policy.json"),
        "the access policy",
        true,
    )];
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
    findings.extend(files(config));
    findings.push(clock());
    findings.extend(space());
    findings.extend(selinux());
    findings.push(events(config));
    findings
}
