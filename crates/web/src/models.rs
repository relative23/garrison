//! Request and response schemas of the web API.
//!
//! These types are the API contract: every answer is built from them, and the
//! OpenAPI document that the frontend's TypeScript types are generated from
//! (`cargo xtask api`, then `npm run api`) is derived from them. Changing a
//! field here is an API change. Unknown fields are refused.

mod attacks;
mod destinations;
pub mod errors;

use std::collections::BTreeMap;

pub(crate) use attacks::{
    AttackNetwork, AttackSource, AttackTotals, AttackedAccount, Attacks, Ban, BanReason,
    FullListener,
};
pub use destinations::{
    DeliveryCause, Destination, DestinationTotals, Destinations, WaitingMessage,
};
pub(crate) use errors::ErrorDetail;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;

/// A JSON object whose keys keep their order (links, outcomes, fields).
pub(crate) type Object = Map<String, Value>;

// -- session -------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModuleInfo {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) description: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Preferences {
    #[schema(inline)]
    pub(crate) theme: Theme,
    pub(crate) hidden_modules: Vec<String>,
    /// The rows that switch between Garrison and the Stalwart WebUI, in
    /// both menus; hidden until the user turns them on.
    #[serde(default)]
    #[schema(default = false)]
    pub(crate) show_switch: bool,
}

/// The answer to a sign-out: the session is gone here. An error answers
/// otherwise, so `ok` is always true.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogoutResponse {
    pub(crate) ok: bool,
}

/// Whether the signed-in user wants the switch row in the Stalwart WebUI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SwitchInfo {
    pub(crate) show: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Links {
    pub(crate) admin: String,
    /// Named links in the order the operator wrote them.
    #[schema(value_type = HashMap<String, String>)]
    pub(crate) other: Object,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SessionInfo {
    pub(crate) version: String,
    pub(crate) email: String,
    pub(crate) csrf: String,
    /// The second the session ends, since the epoch.
    pub(crate) expires_at: i64,
    /// Seconds from this answer to the session's end, by the server's clock.
    /// A page counts them down on its own clock and then asks again: the
    /// browser's clock may be another than the server's. Null where the end
    /// lies further ahead than a session lasts, as for a row written while
    /// the clock ran ahead: the page then counts nothing down.
    #[schema(required)]
    pub(crate) expires_in: Option<i64>,
    pub(crate) modules: Vec<ModuleInfo>,
    pub(crate) actions: Vec<String>,
    pub(crate) profiles: Vec<String>,
    pub(crate) preferences: Preferences,
    pub(crate) links: Links,
}

/// The visitor's session, or `null` when nobody is signed in: the interface
/// asks before every sign-in, and that question is no error.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionState {
    #[schema(required)]
    pub(crate) session: Option<SessionInfo>,
}

// -- status --------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Format {
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
pub(crate) struct ObservationField {
    pub(crate) label: String,
    #[schema(value_type = Value)]
    pub(crate) value: Value,
    #[schema(inline)]
    pub(crate) format: Format,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Column {
    pub(crate) label: String,
    #[schema(inline)]
    pub(crate) format: Format,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObservationTable {
    pub(crate) columns: Vec<Column>,
    #[schema(value_type = Vec<Vec<Value>>)]
    pub(crate) rows: Vec<Vec<Value>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Evidence {
    Configuration,
    Process,
    Probe,
    Receipt,
    Inventory,
    Metric,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum State {
    Ok,
    Warning,
    Failed,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    Details,
    Service,
    Version,
    Link,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Observation {
    pub(crate) id: String,
    pub(crate) provider: String,
    pub(crate) title: String,
    pub(crate) modules: Vec<String>,
    #[schema(inline)]
    pub(crate) evidence: Evidence,
    #[schema(inline)]
    pub(crate) state: State,
    pub(crate) checked_at: String,
    pub(crate) source: String,
    #[schema(inline)]
    pub(crate) kind: Kind,
    pub(crate) scope: String,
    pub(crate) fields: Vec<ObservationField>,
    #[schema(required)]
    pub(crate) table: Option<ObservationTable>,
    pub(crate) findings: Vec<String>,
    #[schema(value_type = HashMap<String, Value>)]
    pub(crate) value: Object,
    pub(crate) max_age: i64,
    /// Seconds from checkedAt to this answer, by the server's clock; null
    /// when checkedAt cannot be read. A page that gets no newer answer adds
    /// the time that passes and compares with maxAge.
    #[schema(required)]
    pub(crate) age: Option<i64>,
    /// True when checkedAt is older than maxAge.
    pub(crate) stale: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct StatusResponse {
    pub(crate) available: bool,
    #[schema(required)]
    pub(crate) collected_at: Option<String>,
    pub(crate) observations: Vec<Observation>,
    pub(crate) provider_errors: Vec<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct MetricsResponse {
    pub(crate) from: i64,
    pub(crate) to: i64,
    #[schema(value_type = Vec<HashMap<String, Option<f64>>>)]
    pub(crate) points: Vec<Object>,
    #[schema(value_type = HashMap<String, f64>)]
    pub(crate) totals: Object,
    #[schema(value_type = HashMap<String, f64>)]
    pub(crate) latest: Object,
    #[schema(required)]
    pub(crate) coverage_from: Option<i64>,
    #[schema(required)]
    pub(crate) coverage_to: Option<i64>,
    pub(crate) sampled_minutes: i64,
    pub(crate) counter_resets: i64,
}

// -- events --------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct EventItem {
    pub(crate) seq: i64,
    pub(crate) id: String,
    pub(crate) created_at: i64,
    #[serde(rename = "type")]
    pub(crate) event_type: String,
    pub(crate) label: String,
    pub(crate) category: String,
    #[schema(required)]
    pub(crate) span_id: Option<String>,
    #[schema(required)]
    pub(crate) queue_id: Option<String>,
    #[schema(value_type = HashMap<String, Value>)]
    pub(crate) fields: Object,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventsPage {
    pub(crate) items: Vec<EventItem>,
    #[schema(required)]
    pub(crate) next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct DeliverySummary {
    pub(crate) queue_id: String,
    pub(crate) first_seen: i64,
    pub(crate) last_seen: i64,
    pub(crate) event_count: i64,
    pub(crate) from: String,
    pub(crate) to: Vec<String>,
    pub(crate) status: String,
    #[schema(value_type = HashMap<String, String>)]
    pub(crate) recipient_outcomes: Object,
    pub(crate) recipient_evidence_complete: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeliveriesPage {
    pub(crate) items: Vec<DeliverySummary>,
    #[schema(required)]
    pub(crate) next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeliveryDetail {
    pub(crate) summary: DeliverySummary,
    pub(crate) events: Vec<EventItem>,
    pub(crate) truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SessionSummary {
    pub(crate) span_id: String,
    pub(crate) first_seen: i64,
    pub(crate) last_seen: i64,
    pub(crate) event_count: i64,
    #[schema(required)]
    pub(crate) listener: Option<String>,
    #[schema(required)]
    pub(crate) remote_ip: Option<String>,
    #[schema(required)]
    pub(crate) ehlo: Option<String>,
    #[schema(required)]
    pub(crate) from: Option<String>,
    pub(crate) to: Vec<String>,
    #[schema(value_type = HashMap<String, String>)]
    pub(crate) authentication: Object,
    pub(crate) rejections: Vec<String>,
    pub(crate) queue_ids: Vec<String>,
    pub(crate) complete: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionsPage {
    pub(crate) items: Vec<SessionSummary>,
    #[schema(required)]
    pub(crate) next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionDetail {
    pub(crate) summary: SessionSummary,
    pub(crate) events: Vec<EventItem>,
    pub(crate) truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Gap {
    pub(crate) start: i64,
    pub(crate) end: i64,
    pub(crate) reason: String,
}

/// The history begins later than its retention allows: events up to `until`
/// were removed to keep the size limit `limit` (`events` or `bytes`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Trimmed {
    pub(crate) until: i64,
    pub(crate) limit: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Coverage {
    pub(crate) available: bool,
    pub(crate) receiver: String,
    #[serde(default)]
    pub(crate) heartbeat_at: Option<i64>,
    #[serde(default)]
    pub(crate) recording_since: Option<i64>,
    #[serde(default)]
    pub(crate) last_batch_at: Option<i64>,
    /// Seconds from `lastBatchAt` to this answer, by the server's clock; null
    /// before the first batch. A page adds the time it waits since: the
    /// browser's own clock may be another than the server's.
    #[serde(default)]
    pub(crate) last_batch_age: Option<i64>,
    /// Since when the receiver runs without storing what Stalwart sends
    /// (`receiver` is then "refusing"); null while it stores.
    #[serde(default)]
    pub(crate) failing_since: Option<i64>,
    #[serde(default)]
    pub(crate) retention_days: Option<i64>,
    #[serde(default)]
    #[schema(default = 0)]
    pub(crate) event_count: i64,
    #[serde(default)]
    pub(crate) trimmed: Option<Trimmed>,
    /// Windows inside the history in which events may be missing.
    #[serde(default)]
    #[schema(default = 0)]
    pub(crate) gap_count: i64,
    pub(crate) gaps: Vec<Gap>,
    pub(crate) limitations: Vec<String>,
}

// -- actions -------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ActionInfo {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) description: String,
    pub(crate) confirmation: String,
    pub(crate) cooldown_seconds: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Job {
    pub(crate) id: String,
    pub(crate) action_id: String,
    /// The OIDC subject that asked for the job.
    pub(crate) actor: String,
    /// The subject's address when it asked; empty in older jobs.
    pub(crate) actor_email: String,
    pub(crate) request_id: String,
    #[schema(inline)]
    pub(crate) status: JobStatus,
    #[schema(required)]
    pub(crate) created_at: Option<String>,
    #[schema(required)]
    pub(crate) started_at: Option<String>,
    #[schema(required)]
    pub(crate) finished_at: Option<String>,
    pub(crate) message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActionsResponse {
    pub(crate) actions: Vec<ActionInfo>,
    pub(crate) jobs: Vec<Job>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SubmitRequest {
    #[schema(max_length = 64)]
    pub(crate) action: String,
    #[schema(max_length = 36)]
    pub(crate) request_id: String,
    #[schema(max_length = 64)]
    pub(crate) confirmation: String,
}

impl SubmitRequest {
    /// The lengths the schema states.
    pub(crate) fn is_within_limits(&self) -> bool {
        self.action.chars().count() <= 64
            && self.request_id.chars().count() <= 36
            && self.confirmation.chars().count() <= 64
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmitResponse {
    pub(crate) job: Job,
    pub(crate) replayed: bool,
}

/// Turn a JSON value from another layer into a typed answer; a mismatch is an
/// internal error.
pub(crate) fn typed<T: serde::de::DeserializeOwned>(value: Value) -> crate::error::ApiResult<T> {
    serde_json::from_value(value).map_err(|error| crate::error::ApiError::internal(&error))
}
