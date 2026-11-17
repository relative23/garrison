//! Process and schedule states from systemd.
//!
//! `systemctl show` works without privileges. Timers additionally report their
//! loaded calendar and next run, which describes what systemd will actually do
//! rather than what a unit file on disk says. systemd answers an alias, such
//! as `sshd.service` for `ssh.service`, under the unit it names, so each unit
//! takes the answer that lists it among the unit's names.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use garrison_core::config::is_unit_name;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Kind, Observation, Required, State};
use garrison_core::systemd::SYSTEMCTL;
use garrison_core::time;
use regex_lite::Regex;
use serde_json::{Map, json};

use crate::context::{Collected, Context, Provider, Report};
use crate::options::{Checked, Options, fail, modules_of};

const PROPERTIES: &str = "Id,Names,LoadState,ActiveState,SubState,Result,TimersCalendar,\
                          TimersMonotonic,NextElapseUSecRealtime,NextElapseUSecMonotonic,\
                          LastTriggerUSec,LastTriggerUSecMonotonic,ExecMainStartTimestamp,\
                          ExecMainExitTimestamp,ExecMainStatus";

#[derive(Debug)]
struct Unit {
    name: String,
    label: String,
    modules: BTreeSet<ModuleId>,
    /// One-shot jobs are "idle": inactive after a successful run is normal.
    idle: bool,
    /// For a job: how old its last finished run may be, in hours.
    max_age_hours: Option<i64>,
}

#[derive(Debug)]
pub struct Systemd {
    units: Vec<Unit>,
}

/// One of this file's regular expressions. Each is a constant, and whether
/// it compiles depends on nothing else, regex-lite's release being locked:
/// `the_patterns_compile` compiles every one, so a build whose tests pass
/// never comes to the `unreachable!`.
fn pattern(text: &str) -> Regex {
    Regex::new(text).unwrap_or_else(|_| unreachable!("the pattern {text} does not compile"))
}

static TIMESTAMP: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (UTC|[A-Z]{3,5})"));
static CALENDAR: LazyLock<Regex> = LazyLock::new(|| pattern(r"OnCalendar=([^;}]+)"));
static INTERVAL: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"OnUnit(?:Active|Inactive)USec=([^;}]+)"));
static SPAN: LazyLock<Regex> =
    LazyLock::new(|| pattern(r"(\d+(?:\.\d+)?)\s*(y|months?|w|d|h|min|ms|us|μs|s)\b"));

/// systemd's `Thu 2026-10-29 03:00:00 UTC`; another zone or `n/a` is `None`.
fn instant(value: &str) -> Option<time::Timestamp> {
    let found = TIMESTAMP.captures(value)?;
    if &found[2] != "UTC" {
        return None;
    }
    time::parse_naive_utc(&found[1])
}

fn timestamp(value: &str) -> Option<String> {
    instant(value).map(time::isoformat)
}

fn calendar(value: &str) -> Option<String> {
    CALENDAR
        .captures(value)
        .map(|found| found[1].trim().to_owned())
}

/// The interval of a timer that runs again a while after its unit last ran:
/// `every 1min` for `{ OnUnitActiveUSec=1min ; next_elapse=... }`.
fn interval(value: &str) -> Option<String> {
    INTERVAL
        .captures(value)
        .map(|found| format!("every {}", found[1].trim()))
}

/// A time span as systemd prints it, such as `11h 14min 25.705796s`, in seconds.
fn span(value: &str) -> Option<f64> {
    let mut seconds = 0.0;
    let mut parts = 0;
    for found in SPAN.captures_iter(value) {
        let number: f64 = found[1].parse().ok()?;
        seconds += number
            * match &found[2] {
                "y" => 31_557_600.0,
                "month" | "months" => 2_629_800.0,
                "w" => 604_800.0,
                "d" => 86400.0,
                "h" => 3600.0,
                "min" => 60.0,
                "s" => 1.0,
                "ms" => 0.001,
                _ => 0.000_001,
            };
        parts += 1;
    }
    (parts > 0).then_some(seconds)
}

/// When a timer runs next. A calendar timer says so in wall-clock time. An
/// interval timer counts from the start of the host: its next run is as far
/// from its last one as the two counts are apart.
fn next_run(values: &BTreeMap<String, String>) -> Option<String> {
    let get = |key: &str| values.get(key).map(String::as_str);
    if let Some(at) = timestamp(get("NextElapseUSecRealtime").unwrap_or_default()) {
        return Some(at);
    }
    let last = instant(get("LastTriggerUSec")?)?;
    let ahead = span(get("NextElapseUSecMonotonic")?)? - span(get("LastTriggerUSecMonotonic")?)?;
    // Whole seconds; a next run that is not after the last one is no answer.
    #[allow(clippy::cast_possible_truncation)]
    let ahead = ahead.round() as i64;
    (ahead > 0)
        .then(|| time::Timestamp::from_second(last.as_second() + ahead).ok())
        .flatten()
        .map(time::isoformat)
}

/// The state a unit's systemd properties show; `idle` units are one-shot jobs
/// that are inactive between their runs.
fn classify(values: &BTreeMap<String, String>, idle: bool) -> State {
    let get = |key: &str| values.get(key).map(String::as_str);
    let (active, loaded) = (get("ActiveState"), get("LoadState"));
    match active {
        _ if values.is_empty() || loaded.is_none() => State::Unknown,
        _ if loaded != Some("loaded") || active == Some("failed") => State::Failed,
        Some("active") => State::Ok,
        // A one-shot job that is currently running is expected, not a warning.
        Some("activating" | "reloading" | "deactivating") if idle => State::Ok,
        Some("activating" | "reloading" | "deactivating") => State::Warning,
        Some("inactive") if idle && get("Result") == Some("success") => State::Ok,
        _ => State::Failed,
    }
}

/// Whether `values` are systemd's answer for `unit`: its `Id` or one of its
/// `Names`, where an alias is listed beside the unit it names.
fn names(values: &BTreeMap<String, String>, unit: &str) -> bool {
    values.get("Id").is_some_and(|id| id == unit)
        || values
            .get("Names")
            .is_some_and(|names| names.split_whitespace().any(|name| name == unit))
}

/// What systemd remembers of a job's last run since the host started, and
/// what its age means for the job's state.
fn last_run(
    unit: &Unit,
    values: &BTreeMap<String, String>,
    now: time::Timestamp,
    state: &mut State,
    findings: &mut Vec<String>,
) -> [Field; 3] {
    let get = |key: &str| values.get(key).map(String::as_str);
    let started = instant(get("ExecMainStartTimestamp").unwrap_or_default());
    let ended = instant(get("ExecMainExitTimestamp").unwrap_or_default())
        .filter(|ended| started.is_none_or(|started| *ended >= started));
    let result = ended.map(|_| match (get("Result"), get("ExecMainStatus")) {
        (Some("success"), _) => "success".to_owned(),
        (Some(result), Some(status)) if !status.is_empty() => {
            format!("{result} (exit status {status})")
        }
        (result, _) => result.unwrap_or("unknown").to_owned(),
    });
    if let Some(hours) = unit.max_age_hours.filter(|_| *state == State::Ok) {
        match ended.map(|ended| now.as_second() - ended.as_second()) {
            Some(age) if age <= hours * 3600 => {}
            Some(_) => {
                *state = State::Warning;
                findings.push(format!("The last run is older than {hours} hours."));
            }
            None => {
                *state = State::Unknown;
                findings.push("No run since the host started.".to_owned());
            }
        }
    }
    [
        Field::new("Last run", ended.map(time::isoformat), Format::Datetime),
        Field::text("Result", result),
        Field::new(
            "Duration",
            started
                .zip(ended)
                .map(|(started, ended)| ended.as_second() - started.as_second()),
            Format::Duration,
        ),
    ]
}

impl Systemd {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["units"])?;
        let mut units = Vec::new();
        for item in options.tables("units")? {
            let unit = item
                .get("unit")
                .and_then(toml::Value::as_str)
                .unwrap_or_default();
            if !is_unit_name(unit) {
                return fail("providers[systemd].units.unit must be a systemd unit name");
            }
            let label = item.get("label").and_then(toml::Value::as_str);
            let Some(label) = label.filter(|label| (1..=120).contains(&label.chars().count()))
            else {
                return fail(format!("providers[systemd] unit {unit} needs a label"));
            };
            if item.keys().any(|key| {
                !["unit", "label", "modules", "expect", "max_age_hours"].contains(&key.as_str())
            }) {
                return fail(format!(
                    "providers[systemd] unit {unit} has unknown settings"
                ));
            }
            let idle = match item.get("expect").map(toml::Value::as_str) {
                None | Some(Some("active")) => false,
                Some(Some("idle")) => true,
                Some(_) => {
                    return fail(format!(
                        "providers[systemd] unit {unit} expect must be active or idle"
                    ));
                }
            };
            let max_age_hours = match item.get("max_age_hours").map(toml::Value::as_integer) {
                None => None,
                Some(Some(hours)) if idle && (1..=8760).contains(&hours) => Some(hours),
                Some(_) => {
                    return fail(format!(
                        "providers[systemd] unit {unit} max_age_hours must be 1 to 8760 hours, \
                         for a unit with expect = \"idle\""
                    ));
                }
            };
            let modules = modules_of(item.get("modules"), &format!("unit {unit} modules"))?;
            units.push(Unit {
                name: unit.to_owned(),
                label: label.to_owned(),
                modules,
                idle,
                max_age_hours,
            });
        }
        if units.is_empty() {
            return fail("providers[systemd] needs at least one unit");
        }
        Ok(Systemd { units })
    }

    /// The properties systemd gives in one `systemctl show` for all units,
    /// one block for each; `Err` says why there are none.
    fn answers(&self, context: &Context<'_>) -> Result<Vec<BTreeMap<String, String>>, String> {
        let mut arguments = vec!["/usr/bin/env", "TZ=UTC", SYSTEMCTL, "show", "--no-pager"];
        let property = format!("--property={PROPERTIES}");
        arguments.push(&property);
        arguments.extend(self.units.iter().map(|unit| unit.name.as_str()));
        let output = context
            .runner
            .run(&arguments)
            .map_err(|error| format!("systemctl show could not be run: {error}."))?;
        let mut answers = Vec::new();
        for block in output.stdout.split("\n\n") {
            // A property a unit has several of, such as a timer's rules,
            // comes as one line each: they are kept side by side.
            let mut values: BTreeMap<String, String> = BTreeMap::new();
            for (key, value) in block.lines().filter_map(|line| line.split_once('=')) {
                values
                    .entry(key.to_owned())
                    .and_modify(|held| {
                        held.push(' ');
                        held.push_str(value);
                    })
                    .or_insert_with(|| value.to_owned());
            }
            if !values.is_empty() {
                answers.push(values);
            }
        }
        Ok(answers)
    }

    fn observation(
        &self,
        context: &Context<'_>,
        unit: &Unit,
        answer: Result<&BTreeMap<String, String>, String>,
    ) -> Result<Observation, crate::context::ProviderError> {
        let empty = BTreeMap::new();
        let (values, why) = match answer {
            Ok(values) => (values, None),
            Err(why) => (&empty, Some(why)),
        };
        let get = |key: &str| values.get(key).map(String::as_str);
        let (active, loaded) = (get("ActiveState"), get("LoadState"));
        // systemd unit names are case-sensitive; only `.timer` is a timer.
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        let timer = unit.name.ends_with(".timer");
        let mut state = classify(values, unit.idle);
        // Unknown always says why: no answer, or one without the load state.
        let mut findings: Vec<String> = why.into_iter().collect();
        if state == State::Unknown && findings.is_empty() {
            findings.push("systemctl show gave no load state for this unit.".to_owned());
        }
        let mut fields = vec![
            Field::text(
                "Load state",
                loaded.filter(|text| !text.is_empty()).unwrap_or("unknown"),
            ),
            Field::text(
                "Active state",
                format!(
                    "{} ({})",
                    active.filter(|text| !text.is_empty()).unwrap_or("unknown"),
                    get("SubState").unwrap_or("unknown")
                ),
            ),
        ];
        // An alias is answered as the unit it stands for: the card says which.
        if let Some(named) = get("Id").filter(|id| !id.is_empty() && *id != unit.name) {
            fields.push(Field::text("Alias of", named));
        }
        if timer {
            fields.extend([
                Field::text(
                    "Schedule",
                    calendar(get("TimersCalendar").unwrap_or_default())
                        .or_else(|| interval(get("TimersMonotonic").unwrap_or_default())),
                ),
                Field::new("Next run", next_run(values), Format::Datetime),
                Field::new(
                    "Last trigger",
                    timestamp(get("LastTriggerUSec").unwrap_or_default()),
                    Format::Datetime,
                ),
            ]);
        }
        if unit.idle && !timer {
            fields.extend(last_run(
                unit,
                values,
                context.now,
                &mut state,
                &mut findings,
            ));
        }
        let scope = if timer {
            "The loaded schedule; a successful run is shown by the job's receipt."
        } else if unit.idle {
            "What systemd reports of the job's last run; it does not prove what the job did."
        } else {
            "A running process does not prove that it handled mail correctly."
        };
        let mut value = Map::new();
        value.insert("unit".into(), json!(unit.name));
        value.insert("activeState".into(), json!(active));
        value.insert("subState".into(), json!(get("SubState")));
        Ok(Observation::new(Required {
            id: &format!("systemd.{}", unit.name),
            provider: self.name(),
            title: &unit.label,
            modules: unit.modules.iter().copied(),
            evidence: Evidence::Process,
            state,
            checked_at: &context.checked_at(),
            source: &format!("systemctl show {}", unit.name),
        })?
        .with_kind(Kind::Service)
        .with_scope(scope)
        .with_fields(fields)
        .with_findings(findings)
        .with_value(value)
        .with_max_age(180))
    }
}

impl Provider for Systemd {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn ids(&self) -> Vec<String> {
        self.units
            .iter()
            .map(|unit| format!("systemd.{}", unit.name))
            .collect()
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let answers = self.answers(context);
        let mut report = Report::default();
        let mut healthy = 0_u32;
        for unit in &self.units {
            // Only an answer that names the unit is its own; the order of the
            // answers is not relied on.
            let answer = match &answers {
                Ok(answers) => answers
                    .iter()
                    .find(|values| names(values, &unit.name))
                    .ok_or_else(|| "systemctl show gave no answer for this unit.".to_owned()),
                Err(why) => Err(why.clone()),
            };
            let observation = self.observation(context, unit, answer)?;
            healthy += u32::from(observation.state == State::Ok);
            report.observations.push(observation);
        }
        Ok(report.gauge("healthy_services", f64::from(healthy)))
    }
}

#[cfg(test)]
mod tests;
