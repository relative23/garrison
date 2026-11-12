//! Request and response schemas of the web API.
//!
//! These types are the API contract: every answer is built from them, and the
//! OpenAPI document that the frontend's TypeScript types are generated from
//! (`cargo xtask api`, then `npm run api`) is derived from them. Changing a
//! field here is an API change. Unknown fields are refused.

mod attacks;
mod destinations;

use std::collections::BTreeMap;

pub use attacks::{
    AttackNetwork, AttackSource, AttackTotals, AttackedAccount, Attacks, Ban, BanReason,
};
pub use destinations::{
    DeliveryCause, Destination, DestinationTotals, Destinations, WaitingMessage,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;

/// A JSON object whose keys keep their order (links, outcomes, fields).
pub type Object = Map<String, Value>;

// -- session -------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleInfo {
    pub id: String,
    pub label: String,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Preferences {
    #[schema(inline)]
    pub theme: Theme,
    pub hidden_modules: Vec<String>,
    /// The rows that switch between Garrison and the Stalwart WebUI, in
    /// both menus; shown unless the user turns them off.
    #[serde(default = "shown")]
    #[schema(default = true)]
    pub show_switch: bool,
}

fn shown() -> bool {
    true
}

impl Default for Preferences {
    fn default() -> Self {
        Preferences {
            theme: Theme::default(),
            hidden_modules: Vec::new(),
            show_switch: true,
        }
    }
}

/// Whether the signed-in user wants the switch row in the Stalwart WebUI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SwitchInfo {
    pub show: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Links {
    pub admin: String,
    /// Named links in the order the operator wrote them.
    #[schema(value_type = HashMap<String, String>)]
    pub other: Object,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SessionInfo {
    pub version: String,
    pub email: String,
    pub csrf: String,
    /// The second the session ends, since the epoch.
    pub expires_at: i64,
    pub modules: Vec<ModuleInfo>,
    pub actions: Vec<String>,
    pub profiles: Vec<String>,
    pub preferences: Preferences,
    pub links: Links,
}

/// The visitor's session, or `null` when nobody is signed in: the interface
/// asks before every sign-in, and that question is no error.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionState {
    #[schema(required)]
    pub session: Option<SessionInfo>,
}

// -- status --------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Text,
    Number,
    Bytes,
    Datetime,
    Duration,
    Boolean,
    Url,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservationField {
    pub label: String,
    #[schema(value_type = Value)]
    pub value: Value,
    #[schema(inline)]
    pub format: Format,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Column {
    pub label: String,
    #[schema(inline)]
    pub format: Format,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservationTable {
    pub columns: Vec<Column>,
    #[schema(value_type = Vec<Vec<Value>>)]
    pub rows: Vec<Vec<Value>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Evidence {
    Configuration,
    Process,
    Probe,
    Receipt,
    Inventory,
    Metric,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Ok,
    Warning,
    Failed,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Details,
    Service,
    Version,
    Link,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Observation {
    pub id: String,
    pub provider: String,
    pub title: String,
    pub modules: Vec<String>,
    #[schema(inline)]
    pub evidence: Evidence,
    #[schema(inline)]
    pub state: State,
    pub checked_at: String,
    pub source: String,
    #[schema(inline)]
    pub kind: Kind,
    pub scope: String,
    pub fields: Vec<ObservationField>,
    #[schema(required)]
    pub table: Option<ObservationTable>,
    pub findings: Vec<String>,
    #[schema(value_type = HashMap<String, Value>)]
    pub value: Object,
    pub max_age: i64,
    /// True when checkedAt is older than maxAge.
    pub stale: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatusResponse {
    pub available: bool,
    #[schema(required)]
    pub collected_at: Option<String>,
    pub observations: Vec<Observation>,
    pub provider_errors: Vec<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MetricsResponse {
    pub from: i64,
    pub to: i64,
    #[schema(value_type = Vec<HashMap<String, Option<f64>>>)]
    pub points: Vec<Object>,
    #[schema(value_type = HashMap<String, f64>)]
    pub totals: Object,
    #[schema(value_type = HashMap<String, f64>)]
    pub latest: Object,
    #[schema(required)]
    pub coverage_from: Option<i64>,
    #[schema(required)]
    pub coverage_to: Option<i64>,
    pub sampled_minutes: i64,
    pub counter_resets: i64,
}

// -- events --------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EventItem {
    pub seq: i64,
    pub id: String,
    pub created_at: i64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub label: String,
    pub category: String,
    #[schema(required)]
    pub span_id: Option<String>,
    #[schema(required)]
    pub queue_id: Option<String>,
    #[schema(value_type = HashMap<String, Value>)]
    pub fields: Object,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsPage {
    pub items: Vec<EventItem>,
    #[schema(required)]
    pub next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeliverySummary {
    pub queue_id: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub event_count: i64,
    pub from: String,
    pub to: Vec<String>,
    pub status: String,
    #[schema(value_type = HashMap<String, String>)]
    pub recipient_outcomes: Object,
    pub recipient_evidence_complete: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveriesPage {
    pub items: Vec<DeliverySummary>,
    #[schema(required)]
    pub next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryDetail {
    pub summary: DeliverySummary,
    pub events: Vec<EventItem>,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SessionSummary {
    pub span_id: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub event_count: i64,
    #[schema(required)]
    pub listener: Option<String>,
    #[schema(required)]
    pub remote_ip: Option<String>,
    #[schema(required)]
    pub ehlo: Option<String>,
    #[schema(required)]
    pub from: Option<String>,
    pub to: Vec<String>,
    #[schema(value_type = HashMap<String, String>)]
    pub authentication: Object,
    pub rejections: Vec<String>,
    pub queue_ids: Vec<String>,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionsPage {
    pub items: Vec<SessionSummary>,
    #[schema(required)]
    pub next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionDetail {
    pub summary: SessionSummary,
    pub events: Vec<EventItem>,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    pub start: i64,
    pub end: i64,
    pub reason: String,
}

/// The history begins later than its retention allows: events up to `until`
/// were removed to keep the size limit `limit` (`events` or `bytes`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Trimmed {
    pub until: i64,
    pub limit: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Coverage {
    pub available: bool,
    pub receiver: String,
    #[serde(default)]
    pub heartbeat_at: Option<i64>,
    #[serde(default)]
    pub recording_since: Option<i64>,
    #[serde(default)]
    pub last_batch_at: Option<i64>,
    #[serde(default)]
    pub retention_days: Option<i64>,
    #[serde(default)]
    #[schema(default = 0)]
    pub event_count: i64,
    #[serde(default)]
    pub trimmed: Option<Trimmed>,
    /// Windows inside the history in which events may be missing.
    #[serde(default)]
    #[schema(default = 0)]
    pub gap_count: i64,
    pub gaps: Vec<Gap>,
    pub limitations: Vec<String>,
}

// -- actions -------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionInfo {
    pub id: String,
    pub title: String,
    pub description: String,
    pub confirmation: String,
    pub cooldown_seconds: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Job {
    pub id: String,
    pub action_id: String,
    /// The OIDC subject that asked for the job.
    pub actor: String,
    /// The subject's address when it asked; empty in older jobs.
    pub actor_email: String,
    pub request_id: String,
    #[schema(inline)]
    pub status: JobStatus,
    #[schema(required)]
    pub created_at: Option<String>,
    #[schema(required)]
    pub started_at: Option<String>,
    #[schema(required)]
    pub finished_at: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionsResponse {
    pub actions: Vec<ActionInfo>,
    pub jobs: Vec<Job>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubmitRequest {
    #[schema(max_length = 64)]
    pub action: String,
    #[schema(max_length = 36)]
    pub request_id: String,
    #[schema(max_length = 64)]
    pub confirmation: String,
}

impl SubmitRequest {
    /// The lengths the schema states.
    pub fn is_within_limits(&self) -> bool {
        self.action.chars().count() <= 64
            && self.request_id.chars().count() <= 36
            && self.confirmation.chars().count() <= 64
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SubmitResponse {
    pub job: Job,
    pub replayed: bool,
}

/// Turn a JSON value from another layer into a typed answer; a mismatch is an
/// internal error.
pub fn typed<T: serde::de::DeserializeOwned>(value: Value) -> crate::error::ApiResult<T> {
    serde_json::from_value(value).map_err(|error| crate::error::ApiError::internal(&error))
}
