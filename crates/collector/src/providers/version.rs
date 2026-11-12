//! Installed versions from local commands, e.g. `clamdscan --version`.

use std::collections::BTreeSet;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Kind, Observation, State};
use regex_lite::Regex;
use serde_json::{Map, json};

use crate::context::{Collected, Context, Provider, Report};
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
        Ok(VersionCommand {
            component,
            command,
            pattern,
            modules: options.modules(&["services"])?,
        })
    }

    fn version(&self, context: &Context<'_>) -> Option<String> {
        let arguments: Vec<&str> = self.command.iter().map(String::as_str).collect();
        let output = context.runner.run(&arguments).ok()?;
        if output.code != Some(0) {
            return None;
        }
        let head: String = output.stdout.chars().take(MAX_OUTPUT).collect();
        let found = self.pattern.captures(&head)?;
        Some(found.get(1)?.as_str().to_owned())
    }
}

impl Provider for VersionCommand {
    fn name(&self) -> &'static str {
        "version-command"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let version = self.version(context);
        let mut value = Map::new();
        value.insert("component".into(), json!(self.component));
        value.insert("version".into(), json!(version));
        let observation = Observation::new(
            format!(
                "version.{}",
                self.component.to_lowercase().replace(' ', "-")
            ),
            self.name(),
            self.component.clone(),
            self.modules.iter().copied(),
            Evidence::Inventory,
            if version.is_some() {
                State::Ok
            } else {
                State::Unknown
            },
            context.checked_at(),
            self.command[0].clone(),
        )?
        .with_kind(Kind::Version)
        .with_scope("Installed binary; the running process version is not verified.")
        .with_value(value)
        .with_max_age(3600);
        Ok(Report::of(observation))
    }
}
