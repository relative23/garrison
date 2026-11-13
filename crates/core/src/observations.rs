//! The observation contract shared by collector providers and the interface.
//!
//! An observation states what was looked at, when, how, and what that does not
//! prove. The evidence kinds keep configuration, process state, probes and
//! historical tests apart, so a running process is never presented as proof that
//! mail was scanned.
//!
//! The collector stores observations as JSON and the web service reads them
//! back as these same types, so the stored form has one description.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::modules::ModuleId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Evidence {
    /// A file or API setting was read.
    Configuration,
    /// A service or endpoint responded.
    Process,
    /// The collector performed an active check (e.g. TLS).
    Probe,
    /// A dated result written by another job.
    Receipt,
    /// Installed files, versions or directory entries.
    Inventory,
    /// A numeric value exported by a running service.
    Metric,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Ok,
    Warning,
    Failed,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    #[default]
    Text,
    Number,
    Bytes,
    Datetime,
    /// Seconds.
    Duration,
    Boolean,
    Url,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Labelled fields and an optional table.
    #[default]
    Details,
    /// One process or schedule state.
    Service,
    /// One installed component version.
    Version,
    /// One external destination.
    Link,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub label: String,
    pub value: Value,
    pub format: Format,
}

impl Field {
    pub fn new(label: impl Into<String>, value: impl Into<Value>, format: Format) -> Self {
        Field {
            label: label.into(),
            value: value.into(),
            format,
        }
    }

    pub fn text(label: impl Into<String>, value: impl Into<Value>) -> Self {
        Field::new(label, value, Format::Text)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Column {
    pub label: String,
    pub format: Format,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Table {
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("observation {0} names no module")]
pub struct NoModule(pub String);

/// One result of one provider. Build it with [`Observation::new`] and the
/// `with_*` methods; the fields serialize to the JSON the status database keeps.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub id: String,
    pub provider: String,
    pub title: String,
    #[serde(serialize_with = "alphabetical", deserialize_with = "known")]
    pub modules: BTreeSet<ModuleId>,
    pub evidence: Evidence,
    pub state: State,
    pub checked_at: String,
    pub source: String,
    pub kind: Kind,
    pub scope: String,
    pub fields: Vec<Field>,
    pub table: Option<Table>,
    pub findings: Vec<String>,
    pub value: Map<String, Value>,
    /// Seconds after which the interface marks this observation as stale.
    pub max_age: u32,
}

/// Module names are stored alphabetically.
fn alphabetical<S: Serializer>(
    modules: &BTreeSet<ModuleId>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut names: Vec<&str> = modules.iter().map(|id| id.as_str()).collect();
    names.sort_unstable();
    serializer.collect_seq(names)
}

/// The stored module names this release knows. A name it does not know, as a
/// snapshot of another release may hold, shows the observation to nobody
/// through that module instead of making the whole snapshot unreadable.
fn known<'de, D: Deserializer<'de>>(deserializer: D) -> Result<BTreeSet<ModuleId>, D::Error> {
    let names = Vec::<String>::deserialize(deserializer)?;
    Ok(names.iter().filter_map(|name| name.parse().ok()).collect())
}

impl Observation {
    /// An observation must name at least one module, or nobody could see it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        provider: impl Into<String>,
        title: impl Into<String>,
        modules: impl IntoIterator<Item = ModuleId>,
        evidence: Evidence,
        state: State,
        checked_at: impl Into<String>,
        source: impl Into<String>,
    ) -> Result<Self, NoModule> {
        let id = id.into();
        let modules: BTreeSet<ModuleId> = modules.into_iter().collect();
        if modules.is_empty() {
            return Err(NoModule(id));
        }
        Ok(Observation {
            id,
            provider: provider.into(),
            title: title.into(),
            modules,
            evidence,
            state,
            checked_at: checked_at.into(),
            source: source.into(),
            kind: Kind::Details,
            scope: String::new(),
            fields: Vec::new(),
            table: None,
            findings: Vec::new(),
            value: Map::new(),
            max_age: 300,
        })
    }

    #[must_use]
    pub fn with_kind(mut self, kind: Kind) -> Self {
        self.kind = kind;
        self
    }

    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = scope.into();
        self
    }

    #[must_use]
    pub fn with_fields(mut self, fields: Vec<Field>) -> Self {
        self.fields = fields;
        self
    }

    #[must_use]
    pub fn with_table(mut self, table: Table) -> Self {
        self.table = Some(table);
        self
    }

    #[must_use]
    pub fn with_findings(mut self, findings: Vec<String>) -> Self {
        self.findings = findings;
        self
    }

    #[must_use]
    pub fn with_value(mut self, value: Map<String, Value>) -> Self {
        self.value = value;
        self
    }

    #[must_use]
    pub fn with_max_age(mut self, seconds: u32) -> Self {
        self.max_age = seconds;
        self
    }
}

impl Observation {
    /// An observation is visible only through a module that names it.
    pub fn visible_to(&self, granted: &BTreeSet<ModuleId>) -> bool {
        !self.modules.is_disjoint(granted)
    }
}

/// Observation ids are an interface (docs/operator/observations.md): the
/// ids renamed in this release, old and new. For one release the old id goes
/// with the observation as `value.aliases`, and the notifier carries what it
/// remembers over to the new id. Empty while no rename is that recent.
pub const RENAMED: &[(&str, &str)] = &[];

/// Adds each renamed observation's old ids to `value.aliases`. They go into
/// the free-form values because the observation's own fields reject what an
/// older release does not know, and a rollback reads newer snapshots.
pub fn with_aliases(observations: &mut [Observation], renamed: &[(&str, &str)]) {
    for observation in observations {
        let aliases: Vec<Value> = renamed
            .iter()
            .filter(|(_, new)| *new == observation.id)
            .map(|(old, _)| Value::from(*old))
            .collect();
        if !aliases.is_empty() {
            observation
                .value
                .insert("aliases".to_owned(), Value::Array(aliases));
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_renamed_observation_carries_its_old_id_for_one_release() {
        let observation = |id: &str| {
            Observation::new(
                id,
                "notifications",
                "Notifications",
                [ModuleId::Alerts],
                Evidence::Probe,
                State::Ok,
                "2026-11-13T00:00:00+00:00",
                "ntfy",
            )
            .unwrap()
        };
        let mut observations = vec![
            observation("notifications.channels"),
            observation("host.clock"),
        ];
        with_aliases(
            &mut observations,
            &[("notifications.ntfy", "notifications.channels")],
        );
        assert_eq!(
            observations[0].value["aliases"],
            json!(["notifications.ntfy"])
        );
        assert!(!observations[1].value.contains_key("aliases"));
        // Free-form values are what a release that knows no aliases reads too.
        let stored = serde_json::to_value(&observations[0]).unwrap();
        assert_eq!(stored["value"]["aliases"], json!(["notifications.ntfy"]));
        assert!(serde_json::from_value::<Observation>(stored).is_ok());
        let mut untouched = vec![observation("notifications.channels")];
        with_aliases(&mut untouched, RENAMED);
        assert_eq!(untouched[0].value.is_empty(), RENAMED.is_empty());
    }

    #[test]
    fn serializes_to_the_stored_json_shape() {
        let observation = Observation::new(
            "clamav.signatures",
            "clamav",
            "Signature files",
            [ModuleId::DnsTls, ModuleId::Antivirus],
            Evidence::Inventory,
            State::Warning,
            "2026-10-29T00:00:00+00:00",
            "/var/lib/clamav",
        )
        .unwrap()
        .with_fields(vec![Field::new("Size", 1024, Format::Bytes)])
        .with_table(Table {
            columns: vec![Column {
                label: "File".into(),
                format: Format::Text,
            }],
            rows: vec![vec![json!("main.cvd")]],
        })
        .with_findings(vec!["Old".into()])
        .with_max_age(600);
        let expected = json!({
            "id": "clamav.signatures",
            "provider": "clamav",
            "title": "Signature files",
            "modules": ["antivirus", "dns_tls"],
            "evidence": "inventory",
            "state": "warning",
            "checkedAt": "2026-10-29T00:00:00+00:00",
            "source": "/var/lib/clamav",
            "kind": "details",
            "scope": "",
            "fields": [{"label": "Size", "value": 1024, "format": "bytes"}],
            "table": {"columns": [{"label": "File", "format": "text"}], "rows": [["main.cvd"]]},
            "findings": ["Old"],
            "value": {},
            "maxAge": 600,
        });
        assert_eq!(serde_json::to_value(&observation).unwrap(), expected);
        let keys: Vec<&String> = expected.as_object().unwrap().keys().collect();
        let written = serde_json::to_value(&observation).unwrap();
        let written_keys: Vec<&String> = written.as_object().unwrap().keys().collect();
        assert_eq!(written_keys, keys, "key order is part of the stored format");
    }

    #[test]
    fn an_observation_without_modules_is_refused() {
        let empty: [ModuleId; 0] = [];
        let result = Observation::new("x", "p", "t", empty, Evidence::Probe, State::Ok, "", "");
        assert_eq!(result, Err(NoModule("x".into())));
    }

    fn stored(modules: &Value) -> Value {
        json!({
            "id": "x", "provider": "p", "title": "t", "modules": modules,
            "evidence": "probe", "state": "ok", "checkedAt": "2026-10-29T00:00:00+00:00",
            "source": "s", "kind": "details", "scope": "", "fields": [], "table": null,
            "findings": [], "value": {}, "maxAge": 300,
        })
    }

    #[test]
    fn visibility_needs_a_granted_module() {
        let granted = BTreeSet::from([ModuleId::Logs]);
        let read = |modules| serde_json::from_value::<Observation>(stored(&modules)).unwrap();
        assert!(read(json!(["dashboard", "logs"])).visible_to(&granted));
        assert!(!read(json!(["dashboard"])).visible_to(&granted));
        // A name this release does not know grants nothing and breaks nothing.
        let other = read(json!(["LOGS", "quarantine", "dashboard"]));
        assert_eq!(other.modules, BTreeSet::from([ModuleId::Dashboard]));
        assert!(!other.visible_to(&granted));
        assert!(!read(json!([])).visible_to(&granted));
        assert!(!read(json!(["logs"])).visible_to(&BTreeSet::new()));
    }

    #[test]
    fn a_stored_observation_reads_back_as_it_was_written() {
        let observation = Observation::new(
            "clamav.signatures",
            "clamav",
            "Signature files",
            [ModuleId::DnsTls, ModuleId::Antivirus],
            Evidence::Inventory,
            State::Warning,
            "2026-10-29T00:00:00+00:00",
            "/var/lib/clamav",
        )
        .unwrap()
        .with_kind(Kind::Version)
        .with_scope("host")
        .with_fields(vec![Field::new("Size", 1024, Format::Bytes)])
        .with_table(Table {
            columns: vec![Column {
                label: "File".into(),
                format: Format::Text,
            }],
            rows: vec![vec![json!("main.cvd")]],
        })
        .with_findings(vec!["Old".into()])
        .with_value(Map::from_iter([("count".to_owned(), json!(3))]))
        .with_max_age(600);
        let written = serde_json::to_string(&observation).unwrap();
        assert_eq!(
            serde_json::from_str::<Observation>(&written).unwrap(),
            observation
        );
    }

    #[test]
    fn what_no_release_writes_is_not_an_observation() {
        let read = |change: fn(&mut Value)| {
            let mut value = stored(&json!(["logs"]));
            change(&mut value);
            serde_json::from_value::<Observation>(value)
        };
        assert!(read(|_| {}).is_ok());
        assert!(read(|value| value["extra"] = json!(1)).is_err());
        assert!(read(|value| value["state"] = json!("fine")).is_err());
        assert!(read(|value| value["modules"] = json!("logs")).is_err());
        assert!(read(|value| value["modules"] = json!(["logs", 1])).is_err());
        assert!(read(|value| value["maxAge"] = json!(-1)).is_err());
        assert!(read(|value| value["fields"] = json!([{"label": "a", "value": 1}])).is_err());
        assert!(
            read(|value| {
                value.as_object_mut().unwrap().remove("findings");
            })
            .is_err()
        );
    }
}
