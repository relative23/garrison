//! Installed versions from local commands, e.g. `clamdscan --version`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use garrison_core::files::answered_by;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Kind, Observation, Required, State};
use regex_lite::Regex;
use serde_json::{Map, json};

use super::ran::{SECONDS, not_run, patience, silent};
use crate::context::{Collected, Context, HostPath, Provider, Report, Use};
use crate::options::{Checked, Options, fail};

const MAX_OUTPUT: usize = 4096;

#[derive(Debug)]
pub struct VersionCommand {
    component: String,
    command: Vec<String>,
    /// Searched in the output; its first group is the version.
    pattern: Regex,
    modules: BTreeSet<ModuleId>,
}

impl VersionCommand {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["component", "command", "pattern", "modules"])?;
        let component = options.text("component", None)?;
        let command: Option<Vec<String>> = match raw.get("command") {
            Some(toml::Value::Array(parts)) if (1..=8).contains(&parts.len()) => parts
                .iter()
                .map(|part| part.as_str().map(str::to_owned))
                .collect(),
            _ => None,
        };
        let Some(command) = command.filter(|parts| parts[0].starts_with('/')) else {
            return fail("providers[version-command].command must be an absolute command");
        };
        let pattern = options.text("pattern", Some(r"(\d+\.\d+\.\d+)"))?;
        let Ok(pattern) = Regex::new(&pattern) else {
            return fail("providers[version-command].pattern must be a valid regular expression");
        };
        if pattern.captures_len() < 2 {
            return fail(
                "providers[version-command].pattern needs a group, ( ), around the version",
            );
        }
        Ok(VersionCommand {
            component,
            command,
            pattern,
            modules: options.modules(&["services"])?,
        })
    }

    /// The version the command gives, or why it gives none. The program's
    /// file system is asked first, by `until`: starting a program waits for
    /// the file system it lies on, and the runner's time begins only after.
    pub(super) fn version(&self, context: &Context<'_>, until: Instant) -> Result<String, String> {
        let program = &self.command[0];
        let looked = PathBuf::from(program);
        if answered_by(until, move || fs::metadata(&looked)).is_err_and(|error| silent(&error)) {
            return Err(format!(
                "{program} was not run: its file system did not answer within {SECONDS} seconds."
            ));
        }
        let arguments: Vec<&str> = self.command.iter().map(String::as_str).collect();
        let output = context
            .runner
            .run(&arguments)
            .map_err(|error| format!("{}.", not_run(program, &error)))?;
        match output.code {
            Some(0) => {}
            Some(code) => return Err(format!("{program} exited with status {code}.")),
            None => return Err(format!("{program} was ended by a signal.")),
        }
        // As `nginx -v` writes its version to standard error, which the
        // runner does not keep.
        if output.stdout.trim().is_empty() {
            return Err(format!(
                "{program} wrote nothing to its standard output, the only output that is read."
            ));
        }
        let head: String = output.stdout.chars().take(MAX_OUTPUT).collect();
        let found = self.pattern.captures(&head);
        match found.as_ref().and_then(|found| found.get(1)) {
            Some(version) => Ok(version.as_str().to_owned()),
            None if head.len() < output.stdout.len() => Err(format!(
                "The first {MAX_OUTPUT} characters of the output of {program} hold nothing that \
                 `pattern` finds."
            )),
            None => Err(format!(
                "The output of {program} holds nothing that `pattern` finds."
            )),
        }
    }
}

impl VersionCommand {
    /// The id of its observation: the component's name decides it.
    fn id(&self) -> String {
        format!(
            "version.{}",
            self.component.to_lowercase().replace(' ', "-")
        )
    }
}

impl Provider for VersionCommand {
    fn name(&self) -> &'static str {
        "version-command"
    }

    fn ids(&self) -> Vec<String> {
        vec![self.id()]
    }

    /// The program it runs, which its options always name.
    fn paths(&self) -> Vec<HostPath<'_>> {
        self.command
            .first()
            .map(|program| HostPath {
                option: "command",
                path: Path::new(program),
                used: Use::Runs,
            })
            .into_iter()
            .collect()
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let version = self.version(context, patience());
        let mut value = Map::new();
        value.insert("component".into(), json!(self.component));
        value.insert("version".into(), json!(version.as_ref().ok()));
        let observation = Observation::new(Required {
            id: &self.id(),
            provider: self.name(),
            title: &self.component,
            modules: self.modules.iter().copied(),
            evidence: Evidence::Inventory,
            state: if version.is_ok() {
                State::Ok
            } else {
                State::Unknown
            },
            checked_at: &context.checked_at(),
            source: &self.command[0],
        })?
        .with_kind(Kind::Version)
        .with_scope("Installed binary; the running process version is not verified.")
        .with_value(value)
        .with_findings(version.err().into_iter().collect())
        .with_max_age(3600);
        Ok(Report::of(observation))
    }
}
