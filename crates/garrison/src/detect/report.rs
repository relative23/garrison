//! The three outputs of `detect`: a report, JSON and provider entries.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use garrison_core::modules::ModuleId;
use serde_json::{Value, json};

use super::system::Packages;
use super::{Format, Inventory};
use crate::units;

/// Garrison's own units, with the labels of the example configuration.
const GARRISON_LABELS: [(&str, &str); 5] = [
    (units::WEB, "Garrison web service"),
    (units::INGEST, "Garrison event receiver"),
    (units::BROKER_SOCKET, "Garrison maintenance broker"),
    (units::COLLECT_TIMER, "Garrison collector schedule"),
    (units::WATCH_TIMER, "Garrison collector watch"),
];

pub(super) fn render(inventory: &Inventory, format: Format) -> String {
    match format {
        Format::Text => text(inventory),
        Format::Json => serde_json::to_string_pretty(&json(inventory)).unwrap_or_default(),
        Format::Toml => toml(inventory, None),
    }
}

fn text(inventory: &Inventory) -> String {
    let system = &inventory.system;
    let mut text = String::new();
    let packages = system
        .packages
        .map_or("no known package database", Packages::as_str);
    let _ = writeln!(
        text,
        "{}, {}, packages: {packages}",
        system.name,
        std::env::consts::ARCH
    );
    let mut guards: Vec<String> = system.confinement.iter().cloned().collect();
    guards.extend(
        system
            .guards
            .iter()
            .map(|(unit, label)| format!("{label} ({unit})")),
    );
    if !guards.is_empty() {
        let _ = writeln!(text, "{}", guards.join(", "));
    }
    if !system.firewall_units.is_empty() {
        let _ = writeln!(
            text,
            "Host care's firewall check knows only firewalld, nftables and ufw: \
             name this host's in firewall_units = [{}]",
            names(&system.firewall_units)
        );
    }
    for component in &inventory.components {
        let state = if component.found {
            "found"
        } else {
            "not found"
        };
        let _ = writeln!(text, "\n{:<22}{state}", component.label);
        for detail in &component.details {
            let _ = writeln!(text, "    {detail}");
        }
    }
    text.push_str("\nNothing was changed. Provider entries: garrison detect --format toml\n");
    text
}

fn json(inventory: &Inventory) -> Value {
    let system = &inventory.system;
    let guards: Vec<Value> = system
        .guards
        .iter()
        .map(|(unit, label)| json!({"unit": unit, "label": label}))
        .collect();
    let components: Vec<Value> = inventory
        .components
        .iter()
        .map(|component| {
            json!({
                "id": component.id,
                "label": component.label,
                "found": component.found,
                "details": component.details,
                "units": component.units,
                "settings": component.settings,
            })
        })
        .collect();
    json!({
        "system": {
            "name": system.name,
            "family": system.family.as_str(),
            "architecture": std::env::consts::ARCH,
            "packages": system.packages.map(Packages::as_str),
            "confinement": system.confinement,
            "guards": guards,
            "firewall_units": system.firewall_units,
        },
        "components": components,
    })
}

/// What `garrison modules` may add: entries for the chosen modules that
/// the configured providers do not cover yet.
#[derive(Debug)]
pub(super) struct Scope<'a> {
    modules: &'a BTreeSet<ModuleId>,
    /// Units that a systemd provider watches already.
    units: BTreeSet<String>,
    /// Whether a `ClamAV` provider is configured.
    clamav: bool,
}

impl<'a> Scope<'a> {
    pub(super) fn of(modules: &'a BTreeSet<ModuleId>, providers: &[toml::Table]) -> Self {
        Self {
            modules,
            units: of_type(providers, "systemd")
                .filter_map(|table| table.get("units").and_then(toml::Value::as_array))
                .flatten()
                .filter_map(|item| item.get("unit").and_then(toml::Value::as_str))
                .map(str::to_owned)
                .collect(),
            clamav: of_type(providers, "clamav").next().is_some(),
        }
    }
}

fn of_type<'t>(
    providers: &'t [toml::Table],
    kind: &'t str,
) -> impl Iterator<Item = &'t toml::Table> {
    providers
        .iter()
        .filter(move |table| table.get("type").and_then(toml::Value::as_str) == Some(kind))
}

/// Entries for what was found within `scope`; empty if there is nothing to add.
pub(super) fn adoptable(inventory: &Inventory, scope: &Scope<'_>) -> String {
    toml(inventory, Some(scope))
}

/// `[[providers]]` entries for what was found: `ClamAV` with its paths and
/// one systemd provider for every unit, all of them or those in `scope`.
fn toml(inventory: &Inventory, scope: Option<&Scope<'_>>) -> String {
    let wanted = |id: &str| scope.is_none_or(|scope| scope.modules.contains(&module(id)));
    let new = |unit: &str| scope.is_none_or(|scope| !scope.units.contains(unit));
    let mut text = String::new();
    // Signature files alone, without a scanner or milter, protect nothing.
    let scanning = inventory.components.iter().any(|component| {
        matches!(component.id, "clamav-scanner" | "clamav-milter") && component.found
    });
    if scanning && wanted("clamav-scanner") && scope.is_none_or(|scope| !scope.clamav) {
        text.push_str("\n[[providers]]\ntype = \"clamav\"\n");
        let settings = inventory
            .components
            .iter()
            .filter(|component| module(component.id) == ModuleId::Antivirus)
            .flat_map(|component| component.settings.iter());
        for (key, value) in settings {
            let _ = writeln!(text, "{key} = {}", quoted(value));
        }
    }
    let mut units: Vec<(&str, &str, &[&str], bool)> = inventory
        .system
        .guards
        .iter()
        .filter(|(unit, _)| new(unit))
        .map(|(unit, label)| (unit.as_str(), *label, &["services"][..], false))
        .collect();
    for component in inventory
        .components
        .iter()
        .filter(|component| wanted(component.id))
    {
        for unit in component.units.iter().filter(|unit| new(unit)) {
            let label = GARRISON_LABELS
                .iter()
                .find(|(name, _)| *name == unit.as_str())
                .map_or(component.label, |(_, label)| *label);
            units.push((unit, label, modules(component.id), false));
        }
        for job in component.jobs.iter().filter(|job| new(job)) {
            units.push((job, "Backup job", modules(component.id), true));
        }
    }
    if !units.is_empty() {
        text.push_str("\n[[providers]]\ntype = \"systemd\"\nunits = [\n");
        for (unit, label, modules, job) in units {
            let modules: Vec<String> = modules.iter().map(|module| quoted(module)).collect();
            // A job rests between its runs; its entry shows the last one.
            let rests = if job { ", expect = \"idle\"" } else { "" };
            let _ = writeln!(
                text,
                "  {{ unit = {}, label = {}, modules = [{}]{rests} }},",
                quoted(unit),
                quoted(label),
                modules.join(", ")
            );
        }
        text.push_str("]\n");
    }
    let firewall_units = &inventory.system.firewall_units;
    if scope.is_none() && !firewall_units.is_empty() {
        let _ = write!(
            text,
            "\n# The firewall rules come from this host's own units: name them in\n\
             # the host-care entry, so its firewall check asks for them.\n\
             # firewall_units = [{}]\n",
            names(firewall_units)
        );
    }
    match scope {
        Some(_) if text.is_empty() => text,
        Some(_) => format!("# Added by `garrison modules` from what `detect` found.\n{text}"),
        None => {
            format!("# Found by `garrison detect`. Review before adding to garrison.toml.\n{text}")
        }
    }
}

/// The module whose page an entry serves; everything else shows on the
/// services page, which every installation has.
fn module(id: &str) -> ModuleId {
    match id {
        "clamav-scanner" | "clamav-milter" | "signatures" => ModuleId::Antivirus,
        "certificates" | "resolver" => ModuleId::DnsTls,
        "backups" => ModuleId::Backups,
        "notifications" => ModuleId::Alerts,
        _ => ModuleId::Services,
    }
}

/// The modules an entry shows on: its own, and the services page.
fn modules(id: &str) -> &'static [&'static str] {
    match module(id) {
        ModuleId::Antivirus => &["antivirus", "services"],
        ModuleId::DnsTls => &["dns_tls", "services"],
        ModuleId::Backups => &["backups", "services"],
        ModuleId::Alerts => &["alerts", "services"],
        _ => &["services"],
    }
}

/// A TOML basic string: JSON's escapes are valid there.
fn quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// `"a.service", "b.service"`, for a TOML array.
fn names(units: &[String]) -> String {
    units
        .iter()
        .map(|unit| quoted(unit))
        .collect::<Vec<_>>()
        .join(", ")
}
