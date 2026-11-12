//! `garrison detect`: what this host already runs.
//!
//! It only reads: files, `systemctl show`, the package database, `ss` and the
//! container list. Each fact names its source, so a path taken from a unit is
//! told apart from a distribution default. What it cannot see is reported as
//! not found, which is not proof that it is absent. `--format toml` prints
//! provider entries with the paths it found, for the operator to review.

mod components;
mod host;
mod report;
mod system;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use clap::ValueEnum;
use garrison_collector::SystemRunner;
use garrison_core::modules::ModuleId;

use host::{Host, Unit};

/// How `detect` prints what it found.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum Format {
    /// A report to read.
    Text,
    /// The inventory for other tools.
    Json,
    /// Provider entries for garrison.toml.
    Toml,
}

/// Everything `detect` found on one host.
#[derive(Debug)]
struct Inventory {
    system: system::System,
    components: Vec<Component>,
}

/// One part of a mail host that Garrison can observe.
#[derive(Debug)]
struct Component {
    id: &'static str,
    label: &'static str,
    found: bool,
    /// Facts for the report, each with its source.
    details: Vec<String>,
    /// The systemd units that belong to it.
    units: Vec<String>,
    /// The jobs its timers start: units that rest between their runs.
    jobs: Vec<String>,
    /// Provider settings with the paths found.
    settings: BTreeMap<&'static str, String>,
}

impl Component {
    fn new(id: &'static str, label: &'static str) -> Self {
        Self {
            id,
            label,
            found: false,
            details: Vec::new(),
            units: Vec::new(),
            jobs: Vec::new(),
            settings: BTreeMap::new(),
        }
    }

    fn note(&mut self, detail: String) {
        self.details.push(detail);
    }

    /// A unit systemd knows marks the component as found.
    fn unit(&mut self, name: &str, unit: &Unit) {
        self.found = true;
        self.units.push(name.to_owned());
        let state = if unit.enabled.is_empty() {
            unit.active.clone()
        } else {
            format!("{}, {}", unit.active, unit.enabled)
        };
        self.note(format!("{name}: {state}"));
    }
}

pub(crate) fn run(format: Format) -> u8 {
    let runner = SystemRunner;
    let host = Host::new(PathBuf::from("/"), &runner);
    crate::say(report::render(&inspect(&host), format).trim_end());
    0
}

/// The components this host runs, each with its units or else its first fact:
/// what `garrison modules` shows next to each module.
pub(crate) fn found() -> BTreeMap<&'static str, Vec<String>> {
    let runner = SystemRunner;
    summary(&inspect(&Host::new(PathBuf::from("/"), &runner)))
}

/// Provider entries for what this host runs that the chosen `modules` show
/// and the configured `providers` do not cover yet; empty if there are none.
pub(crate) fn entries(modules: &BTreeSet<ModuleId>, providers: &[toml::Table]) -> String {
    let runner = SystemRunner;
    let inventory = inspect(&Host::new(PathBuf::from("/"), &runner));
    report::adoptable(&inventory, &report::Scope::of(modules, providers))
}

fn summary(inventory: &Inventory) -> BTreeMap<&'static str, Vec<String>> {
    inventory
        .components
        .iter()
        .filter(|component| component.found)
        .map(|component| {
            let shown = if component.units.is_empty() {
                component.details.iter().take(1).cloned().collect()
            } else {
                component.units.clone()
            };
            (component.id, shown)
        })
        .collect()
}

fn inspect(host: &Host<'_>) -> Inventory {
    let system = system::inspect(host);
    let components = components::inspect(host, &system);
    Inventory { system, components }
}
