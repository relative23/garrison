//! The status snapshot: what one collection run found, as the status database
//! keeps it and the web service reads it back.

use garrison_core::observations::Observation;
use serde::{Deserialize, Serialize};

/// The version of the stored form.
pub const SCHEMA: u32 = 1;

/// A provider that did not report in the run; an Unknown observation stands
/// in for it, and the cause is in the collector's journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderError {
    pub provider: String,
    /// `failed` or `crashed`.
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u32,
    pub collected_at: String,
    pub observations: Vec<Observation>,
    pub provider_errors: Vec<ProviderError>,
}
