//! Delivery problems by destination and cause from the event history.

use std::sync::Arc;

use axum::extract::State;
use axum::http::Uri;
use axum::routing::get;
use axum::{Json, Router};
use garrison_core::modules::ModuleId;
use garrison_ingest::destinations as found;

use super::attacks::PeriodQuery;
use super::events::{checked, run};
use crate::app::App;
use crate::error::ApiResult;
use crate::models::errors::{
    BadAnswer, Busy, Internal, Invalid, Refused, SignInRequired, Unavailable,
};
use crate::models::{DeliveryCause, Destination, DestinationTotals, Destinations, WaitingMessage};
use crate::security::Visitor;

pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/api/destinations", get(destinations))
}

/// A count as the API states it; none here can pass the largest JSON integer.
fn count(number: u64) -> i64 {
    i64::try_from(number).unwrap_or(i64::MAX)
}

// Each conversion names every field: one the receiver adds or changes fails
// to compile until the API takes a decision about it.

impl From<found::Destination> for Destination {
    fn from(destination: found::Destination) -> Self {
        let found::Destination {
            domain,
            delivered,
            delays,
            bounces,
            last_problem,
            cause,
            hosts,
        } = destination;
        Destination {
            domain,
            delivered: count(delivered),
            delays: count(delays),
            bounces: count(bounces),
            last_problem,
            cause,
            hosts,
        }
    }
}

impl From<found::Cause> for DeliveryCause {
    fn from(cause: found::Cause) -> Self {
        let found::Cause {
            cause,
            delays,
            bounces,
            domains,
            last_seen,
        } = cause;
        DeliveryCause {
            cause,
            delays: count(delays),
            bounces: count(bounces),
            domains: count(domains),
            last_seen,
        }
    }
}

impl From<found::Waiting> for WaitingMessage {
    fn from(waiting: found::Waiting) -> Self {
        let found::Waiting {
            queue_id,
            queued_at,
            last_event,
        } = waiting;
        WaitingMessage {
            queue_id,
            queued_at,
            last_event,
        }
    }
}

impl From<found::Destinations> for Destinations {
    fn from(summary: found::Destinations) -> Self {
        let found::Destinations {
            since,
            until,
            truncated,
            totals,
            destinations,
            causes,
            waiting,
        } = summary;
        let found::Totals {
            delivered,
            delays,
            bounces,
            destinations: domains,
            waiting: open,
        } = totals;
        Destinations {
            since,
            until,
            truncated,
            totals: DestinationTotals {
                delivered: count(delivered),
                delays: count(delays),
                bounces: count(bounces),
                destinations: count(domains),
                waiting: count(open),
            },
            destinations: destinations.into_iter().map(Destination::from).collect(),
            causes: causes.into_iter().map(DeliveryCause::from).collect(),
            waiting: waiting.into_iter().map(WaitingMessage::from).collect(),
        }
    }
}

/// Outgoing deliveries of the last day, week or 30 days by destination and
/// by the cause of their delays and bounces, and the messages that wait.
#[utoipa::path(
    get,
    path = "/api/destinations",
    operation_id = "getDestinations",
    params(PeriodQuery),
    responses(
        (status = 200, body = Destinations),
        (status = 400, response = Invalid),
        (status = 401, response = SignInRequired),
        (status = 403, response = Refused),
        (status = 429, response = Busy),
        (status = 500, response = Internal),
        (status = 502, response = BadAnswer),
        (status = 503, response = Unavailable),
    ),
)]
async fn destinations(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    uri: Uri,
) -> ApiResult<Json<Destinations>> {
    let (since, until) = checked(&app, visitor, &[ModuleId::Deliveries], move || {
        PeriodQuery::stretch(&uri)
    })
    .await?;
    let summary = run(&app, move |db| found::destinations(db, since, until)).await?;
    Ok(Json(summary.into()))
}
