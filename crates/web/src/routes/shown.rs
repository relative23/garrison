//! Stored observations as the API states them.
//!
//! The collector's types describe what the status database keeps, the types in
//! `models` what the API promises. Each conversion here names every field and
//! every variant, so one the collector adds or changes fails to compile until
//! the API, and with it the interface's types, takes a decision about it.

use std::collections::BTreeSet;

use garrison_core::modules::ModuleId;
use garrison_core::observations;

use crate::models::{
    Column, Evidence, Format, Kind, Observation, ObservationField, ObservationTable, State,
};

/// A stored observation as the API shows it to one user: with the modules
/// they were granted only, and with whether it is stale now.
pub(super) fn shown(
    observation: observations::Observation,
    granted: &BTreeSet<ModuleId>,
    stale: bool,
) -> Observation {
    let observations::Observation {
        id,
        provider,
        title,
        modules,
        evidence,
        state,
        checked_at,
        source,
        kind,
        scope,
        fields,
        table,
        findings,
        value,
        max_age,
    } = observation;
    // Alphabetical, as the collector stores the names.
    let mut modules: Vec<String> = modules
        .intersection(granted)
        .map(|id| id.as_str().to_owned())
        .collect();
    modules.sort_unstable();
    Observation {
        id,
        provider,
        title,
        modules,
        evidence: evidence.into(),
        state: state.into(),
        checked_at,
        source,
        kind: kind.into(),
        scope,
        fields: fields.into_iter().map(ObservationField::from).collect(),
        table: table.map(ObservationTable::from),
        findings,
        value,
        max_age: i64::from(max_age),
        stale,
    }
}

impl From<observations::Field> for ObservationField {
    fn from(field: observations::Field) -> Self {
        let observations::Field {
            label,
            value,
            format,
        } = field;
        ObservationField {
            label,
            value,
            format: format.into(),
        }
    }
}

impl From<observations::Table> for ObservationTable {
    fn from(table: observations::Table) -> Self {
        let observations::Table { columns, rows } = table;
        let columns = columns
            .into_iter()
            .map(|observations::Column { label, format }| Column {
                label,
                format: format.into(),
            })
            .collect();
        ObservationTable { columns, rows }
    }
}

impl From<observations::Format> for Format {
    fn from(format: observations::Format) -> Self {
        match format {
            observations::Format::Text => Format::Text,
            observations::Format::Number => Format::Number,
            observations::Format::Bytes => Format::Bytes,
            observations::Format::Datetime => Format::Datetime,
            observations::Format::Duration => Format::Duration,
            observations::Format::Boolean => Format::Boolean,
            observations::Format::Url => Format::Url,
        }
    }
}

impl From<observations::Evidence> for Evidence {
    fn from(evidence: observations::Evidence) -> Self {
        match evidence {
            observations::Evidence::Configuration => Evidence::Configuration,
            observations::Evidence::Process => Evidence::Process,
            observations::Evidence::Probe => Evidence::Probe,
            observations::Evidence::Receipt => Evidence::Receipt,
            observations::Evidence::Inventory => Evidence::Inventory,
            observations::Evidence::Metric => Evidence::Metric,
        }
    }
}

impl From<observations::State> for State {
    fn from(state: observations::State) -> Self {
        match state {
            observations::State::Ok => State::Ok,
            observations::State::Warning => State::Warning,
            observations::State::Failed => State::Failed,
            observations::State::Partial => State::Partial,
            observations::State::Unknown => State::Unknown,
        }
    }
}

impl From<observations::Kind> for Kind {
    fn from(kind: observations::Kind) -> Self {
        match kind {
            observations::Kind::Details => Kind::Details,
            observations::Kind::Service => Kind::Service,
            observations::Kind::Version => Kind::Version,
            observations::Kind::Link => Kind::Link,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, json};

    use super::*;

    #[test]
    fn every_variant_keeps_the_name_it_is_stored_under() {
        use observations::{Evidence as E, Format as F, Kind as K, State as S};
        for stored in [
            F::Text,
            F::Number,
            F::Bytes,
            F::Datetime,
            F::Duration,
            F::Boolean,
            F::Url,
        ] {
            assert_eq!(json!(Format::from(stored)), json!(stored));
        }
        for stored in [
            E::Configuration,
            E::Process,
            E::Probe,
            E::Receipt,
            E::Inventory,
            E::Metric,
        ] {
            assert_eq!(json!(Evidence::from(stored)), json!(stored));
        }
        for stored in [S::Ok, S::Warning, S::Failed, S::Partial, S::Unknown] {
            assert_eq!(json!(State::from(stored)), json!(stored));
        }
        for stored in [K::Details, K::Service, K::Version, K::Link] {
            assert_eq!(json!(Kind::from(stored)), json!(stored));
        }
    }

    #[test]
    fn a_shown_observation_is_the_stored_one_with_granted_modules_and_staleness() {
        let stored = observations::Observation::new(
            "clamav.signatures",
            "clamav",
            "Signature files",
            [ModuleId::Dashboard, ModuleId::Antivirus, ModuleId::Actions],
            observations::Evidence::Inventory,
            observations::State::Warning,
            "2026-10-29T00:00:00+00:00",
            "/var/lib/clamav",
        )
        .unwrap()
        .with_kind(observations::Kind::Version)
        .with_scope("host")
        .with_fields(vec![observations::Field::new(
            "Size",
            1024,
            observations::Format::Bytes,
        )])
        .with_table(observations::Table {
            columns: vec![observations::Column {
                label: "File".into(),
                format: observations::Format::Text,
            }],
            rows: vec![vec![json!("main.cvd")]],
        })
        .with_findings(vec!["Old".into()])
        .with_value(Map::from_iter([("count".to_owned(), json!(3))]))
        .with_max_age(600);
        // Every stored field goes out as it is; the modules are those the
        // user was granted, in the alphabetical order they are stored in.
        let mut expected = json!(stored);
        expected["modules"] = json!(["actions", "antivirus"]);
        expected["stale"] = json!(true);
        let granted = BTreeSet::from([ModuleId::Antivirus, ModuleId::Logs, ModuleId::Actions]);
        assert_eq!(json!(shown(stored, &granted, true)), expected);
    }
}
