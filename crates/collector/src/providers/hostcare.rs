//! Host care: what the host itself needs from its operator. Pending security
//! updates, a restart that is due, a clock that is not synchronised, a disk
//! that fills up and a host without a firewall service.
//!
//! Each check reads what the host already knows and changes nothing. The
//! package manager is asked for its own list, from the metadata it has
//! fetched already, so the answer is as fresh as the host's own update job
//! keeps it. A check that cannot be made is Unknown, never in order.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use garrison_core::config::is_unit_name;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, State};
use garrison_core::time;
use serde::{Deserialize, Serialize};

mod packages;
mod reading;

use reading::{Pending, Sample};

use crate::context::{Collected, Context, Provider, ProviderError, Report};
use crate::options::{Checked, Options, fail};

const CHECKS: [&str; 5] = ["updates", "restart", "clock", "disk", "firewall"];
/// The package manager is asked every six hours, after a failure every hour.
const ASK_EVERY: i64 = 6 * 3600;
const ASK_AGAIN: i64 = 3600;
const UPDATES: &str = "hostcare.updates";
const DISK: &str = "hostcare.disk";
/// A disk that is full within this many days at its present rate is a warning.
const FULL_SOON: f64 = 14.0;
const FIREWALLS: [&str; 3] = ["firewalld.service", "nftables.service", "ufw.service"];

#[derive(Debug)]
pub struct HostCare {
    /// The host's root; the tests point it at a directory of their own.
    root: PathBuf,
    disk_path: PathBuf,
    modules: BTreeSet<ModuleId>,
    checks: BTreeSet<String>,
    /// The units that filter this host, where it is not one of [`FIREWALLS`].
    firewall_units: Option<Vec<String>>,
}

/// What the status database keeps of the last look at the pending updates.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
struct Asked {
    at: i64,
    source: String,
    pending: Option<Pending>,
    problem: Option<String>,
}

type Made = Result<Observation, ProviderError>;

/// A list option: not set, distinct names that are accepted, or anything else.
enum Listed {
    Absent,
    Names(Vec<String>),
    Wrong,
}

/// The option `key` as a list of distinct names that `accepted` takes.
fn names(raw: &toml::Table, key: &str, accepted: impl Fn(&str) -> bool) -> Listed {
    let Some(value) = raw.get(key) else {
        return Listed::Absent;
    };
    let Some(items) = value.as_array().filter(|items| !items.is_empty()) else {
        return Listed::Wrong;
    };
    let mut names: Vec<String> = Vec::new();
    for item in items {
        match item.as_str().filter(|name| accepted(name)) {
            Some(name) if !names.iter().any(|known| known == name) => names.push(name.to_owned()),
            _ => return Listed::Wrong,
        }
    }
    Listed::Names(names)
}

impl HostCare {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(
            raw,
            &["root", "disk_path", "modules", "checks", "firewall_units"],
        )?;
        let checks: BTreeSet<String> = match names(raw, "checks", |name| CHECKS.contains(&name)) {
            Listed::Absent => CHECKS.iter().map(ToString::to_string).collect(),
            Listed::Names(names) => names.into_iter().collect(),
            Listed::Wrong => {
                return fail(format!(
                    "providers[host-care].checks lists {}",
                    CHECKS.join(", ")
                ));
            }
        };
        let firewall_units = match names(raw, "firewall_units", is_unit_name) {
            Listed::Absent => None,
            Listed::Names(_) if !checks.contains("firewall") => {
                return fail("providers[host-care].firewall_units needs the firewall check");
            }
            Listed::Names(units) => Some(units),
            Listed::Wrong => {
                return fail("providers[host-care].firewall_units lists systemd units, each once");
            }
        };
        Ok(HostCare {
            root: options.path("root", Some("/"))?,
            disk_path: options.path("disk_path", Some("/"))?,
            modules: options.modules(&["services"])?,
            checks,
            firewall_units,
        })
    }

    fn observation(
        &self,
        context: &Context<'_>,
        id: &str,
        title: &str,
        state: State,
        source: &str,
    ) -> Made {
        Observation::new(
            format!("host.{id}"),
            self.name(),
            title,
            self.modules.iter().copied(),
            Evidence::Probe,
            state,
            context.checked_at(),
            source,
        )
        .map_err(ProviderError::from)
    }

    /// The pending updates, asking the package manager where that is due.
    fn asked(&self, context: &Context<'_>) -> Asked {
        let now = context.now.as_second();
        let kept: Option<Asked> = context
            .memory
            .recall(UPDATES)
            .and_then(|text| serde_json::from_str(&text).ok());
        if let Some(kept) = &kept {
            let wait = if kept.problem.is_some() {
                ASK_AGAIN
            } else {
                ASK_EVERY
            };
            if (0..wait).contains(&(now - kept.at)) {
                return kept.clone();
            }
        }
        let (source, outcome) = packages::pending(&self.root, context.runner);
        let asked = match outcome {
            Ok(pending) => Asked {
                at: now,
                source,
                pending: Some(pending),
                problem: None,
            },
            Err(problem) => Asked {
                at: now,
                source,
                pending: None,
                problem: Some(problem),
            },
        };
        if let Ok(text) = serde_json::to_string(&asked) {
            context.memory.keep(UPDATES, &text);
        }
        asked
    }

    fn updates(&self, context: &Context<'_>) -> Made {
        let asked = self.asked(context);
        let at = time::Timestamp::from_second(asked.at)
            .ok()
            .map(time::isoformat);
        let (state, finding) = match (&asked.pending, &asked.problem) {
            (Some(pending), _) if pending.security > 0 => (
                State::Warning,
                Some(format!(
                    "{} security {} pending.",
                    pending.security,
                    if pending.security == 1 {
                        "update is"
                    } else {
                        "updates are"
                    }
                )),
            ),
            (Some(_), _) => (State::Ok, None),
            (None, problem) => (
                State::Unknown,
                Some(format!(
                    "The pending updates are not known: {}.",
                    problem.as_deref().unwrap_or("not asked yet")
                )),
            ),
        };
        Ok(self
            .observation(context, "updates", "System updates", state, &asked.source)?
            .with_scope(
                "What the package manager would install, from the metadata the host has fetched; asked every six hours.",
            )
            .with_fields(vec![
                Field::new("Security updates", asked.pending.map(|pending| pending.security), Format::Number),
                Field::new("Other updates", asked.pending.map(|pending| pending.other), Format::Number),
                Field::new("Asked", at, Format::Datetime),
            ])
            .with_findings(finding.into_iter().collect())
            .with_max_age(180))
    }

    /// The distribution's own marker, or a kernel newer than the one that runs.
    fn restart(&self, context: &Context<'_>) -> Made {
        let text = |path: &str| fs::read_to_string(self.root.join(path)).ok();
        let running = text("proc/sys/kernel/osrelease").map(|release| release.trim().to_owned());
        let mut installed: Vec<String> = fs::read_dir(self.root.join("lib/modules"))
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.path().join("modules.dep").exists())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        installed.sort_by(|left, right| reading::by_version(left, right));
        let newest = installed.last().cloned();
        let marked = self.root.join("run/reboot-required").exists();
        let (state, finding) = match (&running, &newest) {
            _ if marked => {
                let packages = text("run/reboot-required.pkgs").unwrap_or_default();
                let mut names: Vec<&str> =
                    packages.lines().filter(|line| !line.is_empty()).collect();
                names.sort_unstable();
                names.dedup();
                let because = if names.is_empty() {
                    String::new()
                } else {
                    format!(
                        " ({})",
                        names.iter().take(5).copied().collect::<Vec<_>>().join(", ")
                    )
                };
                (
                    State::Warning,
                    Some(format!(
                        "Installed updates need a restart of the host{because}."
                    )),
                )
            }
            (Some(running), Some(newest)) if reading::by_version(newest, running).is_gt() => (
                State::Warning,
                Some(format!(
                    "Kernel {newest} is installed and {running} runs: a restart of the host is due."
                )),
            ),
            (Some(_), _) => (State::Ok, None),
            (None, _) => (
                State::Unknown,
                Some("The running kernel's release could not be read.".to_owned()),
            ),
        };
        Ok(self
            .observation(context, "restart", "Restart of the host", state, "/run/reboot-required, /lib/modules")?
            .with_scope("The distribution's own marker where it writes one, and the installed kernels against the running one.")
            .with_fields(vec![
                Field::text("Running kernel", running),
                Field::text("Newest installed kernel", newest),
            ])
            .with_findings(finding.into_iter().collect())
            .with_max_age(180))
    }

    fn clock(&self, context: &Context<'_>) -> Made {
        let answer = context.runner.run(&[
            "timedatectl",
            "show",
            "--property=NTPSynchronized",
            "--value",
        ]);
        let (state, finding) = match answer
            .as_ref()
            .map(|output| (output.code, output.stdout.trim()))
        {
            Ok((Some(0), "yes")) => (State::Ok, None),
            Ok((Some(0), "no")) => (
                State::Warning,
                Some("The clock is not synchronised with a time server.".to_owned()),
            ),
            _ => (
                State::Unknown,
                Some("timedatectl did not say whether the clock is synchronised.".to_owned()),
            ),
        };
        Ok(self
            .observation(context, "clock", "Clock synchronisation", state, "timedatectl show")?
            .with_scope("Whether the system clock follows a time server. Mail authentication and TLS depend on the time.")
            .with_fields(vec![Field::new("Synchronised", (state != State::Unknown).then_some(state == State::Ok), Format::Boolean)])
            .with_findings(finding.into_iter().collect())
            .with_max_age(180))
    }

    /// The free space now, and when it runs out at the rate of the last two weeks.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn disk(&self, context: &Context<'_>) -> Made {
        let source = self.disk_path.display().to_string();
        let Ok(filesystem) = rustix::fs::statvfs(&self.disk_path) else {
            return Ok(self
                .observation(
                    context,
                    "disk-forecast",
                    "Disk forecast",
                    State::Unknown,
                    &source,
                )?
                .with_findings(vec!["The file system could not be read.".to_owned()]));
        };
        let free = filesystem.f_bavail.saturating_mul(filesystem.f_frsize);
        let kept: Vec<Sample> = context
            .memory
            .recall(DISK)
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        let count = kept.len();
        let samples = reading::recorded(
            kept,
            Sample {
                at: context.now.as_second(),
                free,
            },
        );
        if samples.len() != count
            && let Ok(text) = serde_json::to_string(&samples)
        {
            context.memory.keep(DISK, &text);
        }
        let trend = reading::trend(&samples);
        let days = trend
            .filter(|change| *change < 0.0)
            .map(|change| free as f64 / -change);
        let (state, finding) = match (trend, days) {
            (None, _) => (
                State::Unknown,
                Some("A forecast needs a day of readings.".to_owned()),
            ),
            (_, Some(days)) if days < FULL_SOON => (
                State::Warning,
                Some(format!(
                    "At the rate of the last days the disk is full in {} days.",
                    days.ceil() as u64
                )),
            ),
            _ => (State::Ok, None),
        };
        Ok(self
            .observation(context, "disk-forecast", "Disk forecast", state, &source)?
            .with_scope("The free space of the last two weeks, read hourly, carried forward in a straight line.")
            .with_fields(vec![
                Field::new("Free now", free, Format::Bytes),
                Field::new("Change a day", trend.map(|change| change.round() as i64), Format::Bytes),
                Field::new("Full in", days.map(|days| (days * 86_400.0) as u64), Format::Duration),
            ])
            .with_findings(finding.into_iter().collect())
            .with_max_age(180))
    }

    fn firewall(&self, context: &Context<'_>) -> Made {
        let units: Vec<&str> = self.firewall_units.as_ref().map_or_else(
            || FIREWALLS.to_vec(),
            |units| units.iter().map(String::as_str).collect(),
        );
        let short = |unit: &&str| unit.trim_end_matches(".service").to_owned();
        let mut arguments = vec!["systemctl", "is-active"];
        arguments.extend(&units);
        // The exit code only says whether all are active; the lines say which.
        let active: Option<Vec<String>> = context.runner.run(&arguments).ok().map(|output| {
            let states: Vec<String> = output
                .stdout
                .lines()
                .map(|line| line.trim().to_owned())
                .collect();
            units
                .iter()
                .zip(&states)
                .filter(|(_, state)| *state == "active")
                .map(|(unit, _)| short(unit))
                .collect()
        });
        let (state, finding) = match &active {
            None => (State::Unknown, Some("systemctl did not answer.".to_owned())),
            Some(active) if active.is_empty() && self.firewall_units.is_none() => (
                State::Warning,
                Some(
                    "No firewall service is active (firewalld, nftables, ufw). Where a unit of the \
                     host's own filters it, name that unit in firewall_units."
                        .to_owned(),
                ),
            ),
            Some(active) if active.is_empty() => (
                State::Warning,
                Some(format!(
                    "None of the firewall units is active ({}).",
                    units.iter().map(short).collect::<Vec<_>>().join(", ")
                )),
            ),
            Some(_) => (State::Ok, None),
        };
        Ok(self
            .observation(
                context,
                "firewall",
                "Firewall service",
                state,
                "systemctl is-active",
            )?
            .with_scope(
                "Whether one of the host's firewall units runs: firewalld, nftables or ufw, or the \
                 units that firewall_units names. Their rules are not read.",
            )
            .with_fields(vec![Field::text(
                "Active",
                active.map(|active| active.join(", ")),
            )])
            .with_findings(finding.into_iter().collect())
            .with_max_age(180))
    }
}

impl Provider for HostCare {
    fn name(&self) -> &'static str {
        "host-care"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let mut report = Report::default();
        for check in &self.checks {
            report.observations.push(match check.as_str() {
                "updates" => self.updates(context)?,
                "restart" => self.restart(context)?,
                "clock" => self.clock(context)?,
                "disk" => self.disk(context)?,
                _ => self.firewall(context)?,
            });
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
