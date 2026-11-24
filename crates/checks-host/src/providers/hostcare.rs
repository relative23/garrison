//! Host care: what the host itself needs from its operator. Pending security
//! updates, a restart that is due, a clock that is not synchronised, a disk
//! that fills up and a host without a firewall service.
//!
//! Each check reads what the host already knows and changes nothing. The
//! package manager is asked for its own list, from the metadata it has
//! fetched already, so the answer is as fresh as the host's own update job
//! keeps it. A check that cannot be made is Unknown, never in order.

use std::collections::BTreeSet;
use std::path::PathBuf;

use garrison_core::config::is_unit_name;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, Required, State};
use serde::{Deserialize, Serialize};

mod packages;
mod reading;
mod restart;

use reading::{Pending, Sample};

use crate::context::{Collected, Context, HostPath, Provider, ProviderError, Report, Use};
use crate::kept::{Kept, cached};
use crate::options::{Checked, Options, fail};

const CHECKS: [&str; 5] = ["updates", "restart", "clock", "disk", "firewall"];
/// The package manager is asked every six hours, after a failure every hour.
const ASK_EVERY: i64 = 6 * 3600;
const ASK_AGAIN: i64 = 3600;
/// After a change to the host's packages it is asked again, at most every
/// five minutes: a long upgrade changes them many times.
const ASK_SOONEST: i64 = 300;
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
    source: String,
    pending: Option<Pending>,
    problem: Option<String>,
    /// The repositories whose cache folders kept dnf out, where that was the problem.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    blocked: Vec<String>,
}

/// What the status database keeps of the free space: the readings, with the
/// path whose file system they measured.
#[derive(Debug, Deserialize, Serialize)]
struct Readings {
    path: PathBuf,
    samples: Vec<Sample>,
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
        if !checks.contains("disk") && options.has("disk_path") {
            return fail("providers[host-care].disk_path needs the disk check");
        }
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
        Observation::new(Required {
            id: &format!("host.{id}"),
            provider: self.name(),
            title,
            modules: self.modules.iter().copied(),
            evidence: Evidence::Probe,
            state,
            checked_at: &context.checked_at(),
            source,
        })
        .map_err(ProviderError::from)
    }

    /// The pending updates, asking the package manager where that is due.
    fn asked(&self, context: &Context<'_>) -> Kept<Asked> {
        let now = context.now.as_second();
        let wait = |at: i64, kept: &Asked| {
            let wait = if kept.problem.is_some() {
                ASK_AGAIN
            } else {
                ASK_EVERY
            };
            // After a change to the host the answer is no longer used, but
            // never sooner than five minutes after it was asked.
            if now.saturating_sub(at) >= ASK_SOONEST && self.changed(at, kept, now) {
                0
            } else {
                wait
            }
        };
        cached(context, UPDATES, wait, |_| {
            let (source, outcome) = packages::pending(&self.root, context.runner);
            match outcome {
                Ok(pending) => Asked {
                    source,
                    pending: Some(pending),
                    problem: None,
                    blocked: Vec::new(),
                },
                Err(problem) => Asked {
                    source,
                    pending: None,
                    problem: Some(problem),
                    blocked: packages::unreadable(&self.root),
                },
            }
        })
    }

    /// Whether the host changed since `kept` was asked at `asked`: packages
    /// installed or removed, new metadata fetched, or the cache folders that
    /// kept dnf out opened. A change time ahead of the clock waits until the
    /// clock is there.
    fn changed(&self, asked: i64, kept: &Asked, now: i64) -> bool {
        packages::last_change(&self.root).is_some_and(|at| at > asked && at <= now)
            || (!kept.blocked.is_empty() && packages::unreadable(&self.root) != kept.blocked)
    }

    fn updates(&self, context: &Context<'_>) -> Made {
        let kept = self.asked(context);
        let asked = &kept.answer;
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
        let observation = self
            .observation(context, "updates", "System updates", state, &asked.source)?
            .with_scope(
                "What a full upgrade would install, from the metadata the host has fetched; \
                 asked again after a change to the packages or the metadata, otherwise every six hours.",
            )
            .with_fields(vec![
                Field::new("Security updates", asked.pending.map(|pending| pending.security), Format::Number),
                Field::new("Other updates", asked.pending.map(|pending| pending.other), Format::Number),
                Field::new("Asked", kept.asked(), Format::Datetime),
            ])
            .with_findings(finding.into_iter().collect());
        // The card is as old as the package manager's answer.
        Ok(kept.dated(observation))
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
        // The readings of another file system say nothing of this one. The
        // releases before kept the readings alone, of the same `disk_path`
        // unless it changed with the upgrade.
        let kept: Vec<Sample> = context.memory.recall(DISK).map_or_else(Vec::new, |text| {
            match serde_json::from_str::<Readings>(&text) {
                Ok(readings) if readings.path == self.disk_path => readings.samples,
                Ok(_) => Vec::new(),
                Err(_) => serde_json::from_str(&text).unwrap_or_default(),
            }
        });
        let samples = reading::recorded(
            kept.clone(),
            Sample {
                at: context.now.as_second(),
                free,
            },
        );
        // Also where one reading goes as another comes, so that their number
        // stays the same: the one that came is kept, and the other is gone.
        let readings = Readings {
            path: self.disk_path.clone(),
            samples,
        };
        if readings.samples != kept
            && let Ok(text) = serde_json::to_string(&readings)
        {
            context.memory.keep(DISK, &text);
        }
        let samples = readings.samples;
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
        // The exit code only says whether all are active; the lines say
        // which, one for each unit, or there is no answer.
        let answer = match context.runner.run(&arguments) {
            Err(_) => Err("systemctl did not answer."),
            Ok(output) => {
                let states: Vec<&str> = output.stdout.lines().map(str::trim).collect();
                if states.len() == units.len() {
                    Ok(units
                        .iter()
                        .zip(&states)
                        .filter(|(_, state)| **state == "active")
                        .map(|(unit, _)| short(unit))
                        .collect::<Vec<String>>())
                } else {
                    Err("systemctl gave no state for every firewall unit.")
                }
            }
        };
        let active = answer.as_ref().ok().cloned();
        let (state, finding) = match &answer {
            Err(why) => (State::Unknown, Some((*why).to_owned())),
            Ok(active) if active.is_empty() && self.firewall_units.is_none() => (
                State::Warning,
                Some(
                    "No firewall service is active (firewalld, nftables, ufw). Where a unit of the \
                     host's own filters it, name that unit in firewall_units."
                        .to_owned(),
                ),
            ),
            Ok(active) if active.is_empty() => (
                State::Warning,
                Some(format!(
                    "None of the firewall units is active ({}).",
                    units.iter().map(short).collect::<Vec<_>>().join(", ")
                )),
            ),
            Ok(_) => (State::Ok, None),
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

    fn ids(&self) -> Vec<String> {
        self.checks
            .iter()
            .map(|check| match check.as_str() {
                "disk" => "host.disk-forecast".to_owned(),
                check => format!("host.{check}"),
            })
            .collect()
    }

    fn paths(&self) -> Vec<HostPath<'_>> {
        vec![
            HostPath {
                option: "root",
                path: &self.root,
                used: Use::Reads,
            },
            HostPath {
                option: "disk_path",
                path: &self.disk_path,
                used: Use::Measures,
            },
        ]
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
