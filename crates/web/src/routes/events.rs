//! Logs, delivery history and sessions from the recorded event history.

use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::Uri;
use axum::routing::get;
use axum::{Json, Router};
use garrison_core::config::Database;
use garrison_core::modules::ModuleId;
use garrison_core::sqlite::reading;
use garrison_core::time;
use garrison_ingest::coverage as history;
use garrison_ingest::policy::{category, event_types, is_recorded};
use garrison_ingest::queries::{self, Filter, QueryError};
use rusqlite::Connection;
use serde::Deserialize;

use crate::app::App;
use crate::error::{ApiError, ApiResult, blocking};
use crate::models::{
    Coverage, DeliveriesPage, DeliveryDetail, EventsPage, SessionDetail, SessionsPage,
};
use crate::security::Visitor;

const READ_BUDGET: Duration = Duration::from_secs(2);
const LATEST_SECOND: i64 = 253_402_300_799;

static CATEGORIES: LazyLock<BTreeSet<&'static str>> =
    LazyLock::new(|| event_types().into_iter().map(category).collect());

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/coverage", get(coverage))
        .route("/api/events", get(events))
        .route("/api/deliveries", get(deliveries))
        .route("/api/deliveries/{queue_id}", get(delivery))
        .route("/api/sessions", get(sessions))
        .route("/api/sessions/{span_id}", get(session))
}

fn fifty() -> i64 {
    50
}

fn twenty_five() -> i64 {
    25
}

/// The query of the event list, as the schema states it.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EventsQuery {
    #[serde(default)]
    #[param(default = "", max_length = 200)]
    search: String,
    #[serde(default)]
    #[param(default = "", max_length = 40)]
    category: String,
    #[serde(default, rename = "type")]
    #[param(rename = "type", default = "", max_length = 100)]
    event_type: String,
    #[param(nullable, minimum = 0, maximum = 253_402_300_799_i64)]
    since: Option<i64>,
    #[param(nullable, minimum = 0, maximum = 253_402_300_799_i64)]
    until: Option<i64>,
    #[param(nullable, max_length = 64, pattern = "^[0-9:]+$")]
    before: Option<String>,
    #[serde(default = "fifty")]
    #[param(default = 50, minimum = 1, maximum = 100)]
    limit: i64,
}

/// The query of the delivery and session lists, which take no category or type.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct GroupQuery {
    #[serde(default)]
    #[param(default = "", max_length = 200)]
    search: String,
    #[param(nullable, minimum = 0, maximum = 253_402_300_799_i64)]
    since: Option<i64>,
    #[param(nullable, minimum = 0, maximum = 253_402_300_799_i64)]
    until: Option<i64>,
    #[param(nullable, max_length = 64, pattern = "^[0-9:]+$")]
    before: Option<String>,
    #[serde(default = "twenty_five")]
    #[param(default = 25, minimum = 1, maximum = 50)]
    limit: i64,
}

/// Check the parameters every list shares and build its filter.
fn filter(
    search: String,
    since: Option<i64>,
    until: Option<i64>,
    before: Option<String>,
    limit: (i64, i64),
) -> ApiResult<Filter> {
    let moment =
        |value: Option<i64>| value.is_none_or(|value| (0..=LATEST_SECOND).contains(&value));
    let before_ok = before.as_ref().is_none_or(|before| {
        !before.is_empty()
            && before.len() <= 64
            && before
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b':')
    });
    let (limit, max) = limit;
    if search.chars().count() > 200
        || !moment(since)
        || !moment(until)
        || !before_ok
        || !(1..=max).contains(&limit)
    {
        return Err(ApiError::invalid());
    }
    Ok(Filter {
        search,
        category: String::new(),
        event_type: String::new(),
        since,
        until,
        before,
        limit: usize::try_from(limit).unwrap_or(1),
    })
}

pub(super) fn parsed<T: serde::de::DeserializeOwned>(uri: &Uri) -> ApiResult<T> {
    Query::<T>::try_from_uri(uri)
        .map(|Query(query)| query)
        .map_err(|_| ApiError::invalid())
}

/// One query on the event history, within the history's concurrency and time budget.
pub(super) fn run<T>(
    app: &App,
    query: impl FnOnce(&Connection) -> Result<T, QueryError>,
) -> ApiResult<T> {
    let Ok(_slot) = app.query_slots.try_acquire() else {
        return Err(ApiError::new(429, "Too many concurrent history queries"));
    };
    let db = reading(&app.config.database(Database::Events), READ_BUDGET)?;
    let db = db.ok_or_else(|| ApiError::new(503, "The event history is not available yet"))?;
    query(&db).map_err(failure)
}

/// What a failed history query tells the user.
fn failure(error: QueryError) -> ApiError {
    match error {
        QueryError::Invalid => ApiError::new(400, "Invalid query"),
        // The reader's progress handler interrupts queries over their budget.
        error @ QueryError::Sqlite(_) if error.is_interrupted() => {
            ApiError::new(503, "The query took too long; narrow the filter")
        }
        error @ QueryError::Sqlite(_) => ApiError::internal(&error),
    }
}

/// How complete the recorded event history is.
#[utoipa::path(
    get,
    path = "/api/coverage",
    operation_id = "getCoverage",
    responses((status = 200, body = Coverage)),
)]
async fn coverage(State(app): State<Arc<App>>, visitor: Visitor) -> ApiResult<Json<Coverage>> {
    blocking(move || {
        app.gate.require(
            &visitor,
            &[ModuleId::Logs, ModuleId::Deliveries, ModuleId::Sessions],
        )?;
        let db = reading(&app.config.database(Database::Events), READ_BUDGET)?;
        let coverage = history::read(db.as_deref(), time::now().as_second())
            .map_err(|error| ApiError::internal(&error))?;
        Ok(Json(coverage.into()))
    })
    .await
}

/// Recorded events, newest first.
#[utoipa::path(
    get,
    path = "/api/events",
    operation_id = "listEvents",
    params(EventsQuery),
    responses((status = 200, body = EventsPage)),
)]
async fn events(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    uri: Uri,
) -> ApiResult<Json<EventsPage>> {
    blocking(move || {
        app.gate.require(&visitor, &[ModuleId::Logs])?;
        let query: EventsQuery = parsed(&uri)?;
        let mut filter = filter(
            query.search,
            query.since,
            query.until,
            query.before,
            (query.limit, 100),
        )?;
        (filter.category, filter.event_type) = (query.category, query.event_type);
        let unknown_category =
            !filter.category.is_empty() && !CATEGORIES.contains(filter.category.as_str());
        let unknown_type = !filter.event_type.is_empty() && !is_recorded(&filter.event_type);
        if unknown_category || unknown_type {
            return Err(ApiError::new(400, "Unknown event category or type"));
        }
        let page = run(&app, |db| queries::list_events(db, &filter))?;
        Ok(Json(page.into()))
    })
    .await
}

fn grouped_filter(uri: &Uri) -> ApiResult<Filter> {
    let query: GroupQuery = parsed(uri)?;
    filter(
        query.search,
        query.since,
        query.until,
        query.before,
        (query.limit, 50),
    )
}

/// Queue lifecycles reconstructed from recorded events, newest first.
#[utoipa::path(
    get,
    path = "/api/deliveries",
    operation_id = "listDeliveries",
    params(GroupQuery),
    responses((status = 200, body = DeliveriesPage)),
)]
async fn deliveries(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    uri: Uri,
) -> ApiResult<Json<DeliveriesPage>> {
    blocking(move || {
        app.gate.require(&visitor, &[ModuleId::Deliveries])?;
        let filter = grouped_filter(&uri)?;
        let page = run(&app, |db| queries::list_deliveries(db, &filter))?;
        Ok(Json(page.into()))
    })
    .await
}

/// A queue or span ID: 1 to 20 ASCII digits.
fn identifier(text: &str) -> ApiResult<()> {
    if (1..=20).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err(ApiError::invalid())
    }
}

/// Every recorded event of one queued message.
#[utoipa::path(
    get,
    path = "/api/deliveries/{queue_id}",
    operation_id = "getDelivery",
    params(("queue_id" = String, Path, pattern = "^[0-9]{1,20}$")),
    responses((status = 200, body = DeliveryDetail)),
)]
async fn delivery(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    Path(queue_id): Path<String>,
) -> ApiResult<Json<DeliveryDetail>> {
    blocking(move || {
        app.gate.require(&visitor, &[ModuleId::Deliveries])?;
        identifier(&queue_id)?;
        run(&app, |db| queries::delivery_detail(db, &queue_id))?
            .map(|detail| Json(detail.into()))
            .ok_or_else(|| ApiError::new(404, "No recorded events for this queue ID"))
    })
    .await
}

/// SMTP sessions reconstructed from recorded events, newest first.
#[utoipa::path(
    get,
    path = "/api/sessions",
    operation_id = "listSmtpSessions",
    params(GroupQuery),
    responses((status = 200, body = SessionsPage)),
)]
async fn sessions(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    uri: Uri,
) -> ApiResult<Json<SessionsPage>> {
    blocking(move || {
        app.gate.require(&visitor, &[ModuleId::Sessions])?;
        let filter = grouped_filter(&uri)?;
        let page = run(&app, |db| queries::list_sessions(db, &filter))?;
        Ok(Json(page.into()))
    })
    .await
}

/// Every recorded event of one SMTP session.
#[utoipa::path(
    get,
    path = "/api/sessions/{span_id}",
    operation_id = "getSmtpSession",
    params(("span_id" = String, Path, pattern = "^[0-9]{1,20}$")),
    responses((status = 200, body = SessionDetail)),
)]
async fn session(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    Path(span_id): Path<String>,
) -> ApiResult<Json<SessionDetail>> {
    blocking(move || {
        app.gate.require(&visitor, &[ModuleId::Sessions])?;
        identifier(&span_id)?;
        run(&app, |db| queries::session_detail(db, &span_id))?
            .map(|detail| Json(detail.into()))
            .ok_or_else(|| ApiError::new(404, "No recorded events for this session"))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_queries_say_what_the_user_can_do() {
        let sqlite = |code| {
            QueryError::Sqlite(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ))
        };
        let answers = [
            failure(QueryError::Invalid),
            failure(sqlite(rusqlite::ffi::SQLITE_INTERRUPT)),
            failure(sqlite(rusqlite::ffi::SQLITE_CORRUPT)),
        ];
        let answers: Vec<(u16, &str)> = answers
            .iter()
            .map(|error| (error.status.as_u16(), error.detail.as_str()))
            .collect();
        assert_eq!(
            answers,
            [
                (400, "Invalid query"),
                (503, "The query took too long; narrow the filter"),
                (500, "Internal error"),
            ]
        );
    }
}
