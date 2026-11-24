//! Logs, delivery history and sessions from the recorded event history.

use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::extract::rejection::PathRejection;
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

use super::recorded;
use crate::app::App;
use crate::error::{ApiError, ApiResult, SLOW, blocking, stopped};
use crate::models::errors::{
    BadAnswer, Busy, Internal, Invalid, NotFound, Refused, SignInRequired, Unavailable,
};
use crate::models::{
    Coverage, DeliveriesPage, DeliveryDetail, EventsPage, SessionDetail, SessionsPage,
};
use crate::security::Visitor;

const READ_BUDGET: Duration = Duration::from_secs(2);
const LATEST_SECOND: i64 = 253_402_300_799;

static CATEGORIES: LazyLock<BTreeSet<&'static str>> =
    LazyLock::new(|| event_types().into_iter().map(category).collect());

pub(crate) fn routes() -> Router<Arc<App>> {
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
pub(crate) struct EventsQuery {
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
pub(crate) struct GroupQuery {
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

/// The caller's rights, then the request's parameters, checked off the async
/// threads before a query waits for its turn: a stranger never takes a place.
pub(super) async fn checked<T: Send + 'static>(
    app: &Arc<App>,
    visitor: Visitor,
    modules: &'static [ModuleId],
    prepare: impl FnOnce() -> ApiResult<T> + Send + 'static,
) -> ApiResult<T> {
    let app = Arc::clone(app);
    blocking(move || {
        app.gate.require(&visitor, modules)?;
        prepare()
    })
    .await
}

/// One query on the event history, in its turn (see `queries`).
pub(super) async fn run<T: Send + 'static>(
    app: &App,
    query: impl FnOnce(&Connection) -> Result<T, QueryError> + Send + 'static,
) -> ApiResult<T> {
    let path = app.config.database(Database::Events);
    let missing = "The event history is not available yet";
    app.queries
        .run(path, missing, move |db| {
            query(db).map_err(|error| failure(&error))
        })
        .await
}

/// What a failed history query tells the user, where its filter, if it has
/// one, is too wide for its time: `slow`.
fn failed(error: &QueryError, slow: &'static str) -> ApiError {
    match error {
        QueryError::Invalid => ApiError::new(400, "Invalid query"),
        // The reader's progress handler interrupts queries over their
        // budget, and the writer's commit may outlast a reader's wait.
        QueryError::Sqlite(cause) => {
            stopped(cause, slow).unwrap_or_else(|| ApiError::internal(error))
        }
        // What the history holds and cannot be read is the service's fault;
        // the journal names it under the answer's reference.
        QueryError::Unreadable(_) => ApiError::internal(error),
    }
}

/// What a failed list, detail or summary of the history tells the user.
fn failure(error: &QueryError) -> ApiError {
    failed(error, "The query took too long; narrow the filter")
}

/// How complete the recorded event history is.
#[utoipa::path(
    get,
    path = "/api/coverage",
    operation_id = "getCoverage",
    responses(
        (
            status = 200,
            description = "What the event history covers, and whether the receiver runs.",
            body = Coverage
        ),
        (status = 401, response = SignInRequired),
        (status = 403, response = Refused),
        (status = 500, response = Internal),
        (status = 502, response = BadAnswer),
        (status = 503, response = Unavailable),
    ),
)]
async fn coverage(State(app): State<Arc<App>>, visitor: Visitor) -> ApiResult<Json<Coverage>> {
    blocking(move || {
        // Every module that shows what the history holds; the coverage
        // itself holds no mail metadata.
        app.gate.require(
            &visitor,
            &[
                ModuleId::Logs,
                ModuleId::Deliveries,
                ModuleId::Sessions,
                ModuleId::Attacks,
            ],
        )?;
        let db = reading(&app.config.database(Database::Events), READ_BUDGET)?;
        let now = time::now().as_second();
        let coverage = history::read(db.as_deref(), now).map_err(|error| failed(&error, SLOW))?;
        // The age of the last batch is counted at the answer: the receiver
        // may have stored one in a second that began after `now` was read.
        Ok(Json(recorded::coverage(coverage, time::now().as_second())))
    })
    .await
}

/// Recorded events, newest first.
#[utoipa::path(
    get,
    path = "/api/events",
    operation_id = "listEvents",
    params(EventsQuery),
    responses(
        (
            status = 200,
            description = "A page of events and the cursor of the next older page.",
            body = EventsPage
        ),
        (status = 400, response = Invalid),
        (status = 401, response = SignInRequired),
        (status = 403, response = Refused),
        (status = 429, response = Busy),
        (status = 500, response = Internal),
        (status = 502, response = BadAnswer),
        (status = 503, response = Unavailable),
    ),
)]
async fn events(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    uri: Uri,
) -> ApiResult<Json<EventsPage>> {
    let filter = checked(&app, visitor, &[ModuleId::Logs], move || {
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
        Ok(filter)
    })
    .await?;
    let page = run(&app, move |db| queries::list_events(db, &filter)).await?;
    Ok(Json(page.into()))
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
    responses(
        (
            status = 200,
            description = "A page of deliveries and the cursor of the next older page.",
            body = DeliveriesPage
        ),
        (status = 400, response = Invalid),
        (status = 401, response = SignInRequired),
        (status = 403, response = Refused),
        (status = 429, response = Busy),
        (status = 500, response = Internal),
        (status = 502, response = BadAnswer),
        (status = 503, response = Unavailable),
    ),
)]
async fn deliveries(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    uri: Uri,
) -> ApiResult<Json<DeliveriesPage>> {
    let filter = checked(&app, visitor, &[ModuleId::Deliveries], move || {
        grouped_filter(&uri)
    })
    .await?;
    let page = run(&app, move |db| queries::list_deliveries(db, &filter)).await?;
    Ok(Json(page.into()))
}

/// A queue or span ID: 1 to 20 ASCII digits. A path segment axum could not
/// decode is refused as any other one is, with the API's error answer.
fn identifier(path: Result<Path<String>, PathRejection>) -> ApiResult<String> {
    match path {
        Ok(Path(text))
            if (1..=20).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            Ok(text)
        }
        _ => Err(ApiError::invalid()),
    }
}

/// Every recorded event of one queued message.
#[utoipa::path(
    get,
    path = "/api/deliveries/{queue_id}",
    operation_id = "getDelivery",
    params(("queue_id" = String, Path, pattern = "^[0-9]{1,20}$")),
    responses(
        (
            status = 200,
            description = "The message's summary and its recorded events.",
            body = DeliveryDetail
        ),
        (status = 400, response = Invalid),
        (status = 401, response = SignInRequired),
        (status = 403, response = Refused),
        (status = 404, response = NotFound),
        (status = 429, response = Busy),
        (status = 500, response = Internal),
        (status = 502, response = BadAnswer),
        (status = 503, response = Unavailable),
    ),
)]
async fn delivery(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    queue_id: Result<Path<String>, PathRejection>,
) -> ApiResult<Json<DeliveryDetail>> {
    let queue_id = checked(&app, visitor, &[ModuleId::Deliveries], move || {
        identifier(queue_id)
    })
    .await?;
    run(&app, move |db| queries::delivery_detail(db, &queue_id))
        .await?
        .map(|detail| Json(detail.into()))
        .ok_or_else(|| ApiError::new(404, "No recorded events for this queue ID"))
}

/// SMTP sessions reconstructed from recorded events, newest first.
#[utoipa::path(
    get,
    path = "/api/sessions",
    operation_id = "listSmtpSessions",
    params(GroupQuery),
    responses(
        (
            status = 200,
            description = "A page of SMTP sessions and the cursor of the next older page.",
            body = SessionsPage
        ),
        (status = 400, response = Invalid),
        (status = 401, response = SignInRequired),
        (status = 403, response = Refused),
        (status = 429, response = Busy),
        (status = 500, response = Internal),
        (status = 502, response = BadAnswer),
        (status = 503, response = Unavailable),
    ),
)]
async fn sessions(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    uri: Uri,
) -> ApiResult<Json<SessionsPage>> {
    let filter = checked(&app, visitor, &[ModuleId::Sessions], move || {
        grouped_filter(&uri)
    })
    .await?;
    let page = run(&app, move |db| queries::list_sessions(db, &filter)).await?;
    Ok(Json(page.into()))
}

/// Every recorded event of one SMTP session.
#[utoipa::path(
    get,
    path = "/api/sessions/{span_id}",
    operation_id = "getSmtpSession",
    params(("span_id" = String, Path, pattern = "^[0-9]{1,20}$")),
    responses(
        (
            status = 200,
            description = "The session's summary and its recorded events.",
            body = SessionDetail
        ),
        (status = 400, response = Invalid),
        (status = 401, response = SignInRequired),
        (status = 403, response = Refused),
        (status = 404, response = NotFound),
        (status = 429, response = Busy),
        (status = 500, response = Internal),
        (status = 502, response = BadAnswer),
        (status = 503, response = Unavailable),
    ),
)]
async fn session(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    span_id: Result<Path<String>, PathRejection>,
) -> ApiResult<Json<SessionDetail>> {
    let span_id = checked(&app, visitor, &[ModuleId::Sessions], move || {
        identifier(span_id)
    })
    .await?;
    run(&app, move |db| queries::session_detail(db, &span_id))
        .await?
        .map(|detail| Json(detail.into()))
        .ok_or_else(|| ApiError::new(404, "No recorded events for this session"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WAITED;

    #[test]
    fn failed_queries_say_what_the_user_can_do() {
        let sqlite = |code| {
            QueryError::Sqlite(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ))
        };
        let answers = [
            failure(&QueryError::Invalid),
            failure(&sqlite(rusqlite::ffi::SQLITE_INTERRUPT)),
            failure(&sqlite(rusqlite::ffi::SQLITE_BUSY)),
            failure(&sqlite(rusqlite::ffi::SQLITE_CORRUPT)),
            failure(&QueryError::Unreadable("Event 2 cannot be read".to_owned())),
            // The coverage has no filter to narrow.
            failed(&sqlite(rusqlite::ffi::SQLITE_INTERRUPT), SLOW),
            failed(&sqlite(rusqlite::ffi::SQLITE_BUSY), SLOW),
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
                (503, WAITED),
                (500, "Internal error"),
                (500, "Internal error"),
                (503, SLOW),
                (503, WAITED),
            ]
        );
    }
}
