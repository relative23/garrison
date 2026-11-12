//! The OpenAPI document of the web API, derived from the routes and the
//! response types, so the frontend's types cannot drift from the server.

use serde_json::Value;
use utoipa::OpenApi;

use crate::models;
use crate::routes::{actions, api, attacks, destinations, events};

#[derive(OpenApi)]
#[openapi(
    info(title = "Garrison API"),
    paths(
        actions::catalog,
        actions::submit,
        actions::job,
        attacks::attacks,
        destinations::destinations,
        events::coverage,
        events::deliveries,
        events::delivery,
        events::events,
        api::logout,
        api::metrics,
        api::save_preferences,
        api::session,
        events::sessions,
        events::session,
        api::status,
        api::switch,
    ),
    components(schemas(
        models::ActionInfo,
        models::ActionsResponse,
        models::AttackNetwork,
        models::AttackSource,
        models::AttackTotals,
        models::AttackedAccount,
        models::Attacks,
        models::Ban,
        models::BanReason,
        models::Column,
        models::Coverage,
        models::DeliveriesPage,
        models::DeliveryDetail,
        models::DeliveryCause,
        models::DeliverySummary,
        models::Destination,
        models::DestinationTotals,
        models::Destinations,
        models::EventItem,
        models::EventsPage,
        models::Gap,
        models::Trimmed,
        models::Job,
        models::Links,
        models::MetricsResponse,
        models::ModuleInfo,
        models::Observation,
        models::ObservationField,
        models::ObservationTable,
        models::Preferences,
        models::SessionDetail,
        models::SessionInfo,
        models::SessionState,
        models::SessionSummary,
        models::SessionsPage,
        models::StatusResponse,
        models::SubmitRequest,
        models::SubmitResponse,
        models::WaitingMessage,
        models::SwitchInfo,
    ))
)]
struct Document;

/// The document as JSON, with this release's version.
pub fn document() -> Value {
    let mut document = Document::openapi();
    env!("CARGO_PKG_VERSION").clone_into(&mut document.info.version);
    serde_json::to_value(document).unwrap_or(Value::Null)
}

/// Sorted keys and two-space indentation, as the committed contract is written.
pub fn text() -> String {
    fn sorted(value: Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut entries: Vec<(String, Value)> = map.into_iter().collect();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));
                Value::Object(
                    entries
                        .into_iter()
                        .map(|(key, value)| (key, sorted(value)))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
            other => other,
        }
    }
    let mut text = serde_json::to_string_pretty(&sorted(document())).unwrap_or_default();
    text.push('\n');
    text
}
