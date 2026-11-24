//! Session, preferences, status snapshot and metric history.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use garrison_collector::snapshot::ProviderError;
use garrison_collector::store::{History, PERIODS, history, latest_snapshot};
use garrison_core::config::Database;
use garrison_core::modules::{Module, ModuleId};
use garrison_core::observations;
use garrison_core::sqlite::reading;
use garrison_core::{json, time};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::auth::delete_cookie;
use super::events::checked;
use super::shown::shown;
use crate::app::App;
use crate::error::{ApiError, ApiResult, blocking};
use crate::models::errors::{
    BadAnswer, Busy, Internal, Invalid, Refused, SignInRequired, TooLarge, Unavailable,
};
use crate::models::{
    Links, LogoutResponse, MetricsResponse, ModuleInfo, Preferences, SessionInfo, SessionState,
    StatusResponse, SwitchInfo,
};
use crate::security::{SESSION_COOKIE, Visitor};

const READ_BUDGET: Duration = Duration::from_secs(2);
const MAX_BODY: usize = 65536;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/session", get(session))
        .route("/api/logout", post(logout))
        .route("/api/preferences", put(save_preferences))
        .route("/api/status", get(status))
        .route("/api/metrics", get(metrics))
        .route("/api/switch", get(switch))
}

/// The body as axum read it. One it could not read gets the API's error
/// answer, as every refusal does, and only after the caller was checked.
pub fn read(data: Result<Bytes, BytesRejection>) -> ApiResult<Bytes> {
    data.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(413, "The request body is larger than the service reads")
        } else {
            ApiError::invalid()
        }
    })
}

/// A JSON body for `T`: a JSON media type, strict JSON (no duplicate keys),
/// no unknown fields.
pub fn body<T: serde::de::DeserializeOwned>(visitor: &Visitor, data: &[u8]) -> ApiResult<T> {
    let media = visitor.header("content-type").unwrap_or_default();
    let media = media
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media != "application/json"
        && !(media.starts_with("application/") && media.ends_with("+json"))
    {
        return Err(ApiError::invalid());
    }
    let value = json::parse(data, MAX_BODY).map_err(|_| ApiError::invalid())?;
    serde_json::from_value(value).map_err(|_| ApiError::invalid())
}

/// The signed-in user: modules, actions, preferences and links; `null`
/// without a valid session.
#[utoipa::path(
    get,
    path = "/api/session",
    operation_id = "getSession",
    responses(
        (
            status = 200,
            description = "The signed-in user, or `session: null` without a valid session.",
            body = SessionState
        ),
        (status = 403, response = Refused),
        (status = 500, response = Internal),
        (status = 502, response = BadAnswer),
        (status = 503, response = Unavailable),
    ),
)]
async fn session(State(app): State<Arc<App>>, visitor: Visitor) -> ApiResult<Json<SessionState>> {
    blocking(move || {
        let caller = match app.gate.caller(&visitor) {
            Ok(caller) => caller,
            Err(error) if error.status == StatusCode::UNAUTHORIZED => {
                return Ok(Json(SessionState { session: None }));
            }
            Err(error) => return Err(error),
        };
        let grant = &caller.grant;
        let modules = ModuleId::all()
            .filter(|id| grant.allows_module(*id))
            .map(|id| {
                let Module {
                    label, description, ..
                } = id.module();
                ModuleInfo {
                    id: id.as_str().to_owned(),
                    label: (*label).to_owned(),
                    description: (*description).to_owned(),
                }
            })
            .collect();
        let actions = if grant.allows_module(ModuleId::Actions) {
            grant.actions.iter().cloned().collect()
        } else {
            Vec::new()
        };
        let preferences = app.store.preferences(&grant.subject)?;
        let deployment = &app.config.deployment;
        let other: Map<String, Value> = deployment
            .links
            .iter()
            .map(|(name, url)| (name.clone(), Value::String(url.clone())))
            .collect();
        Ok(Json(SessionState {
            session: Some(SessionInfo {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                email: grant.email.clone(),
                csrf: caller.session.csrf.clone(),
                expires_at: caller.session.expires_at,
                expires_in: time_left(
                    caller.session.expires_at,
                    time::now(),
                    i64::from(app.config.web.session_minutes) * 60,
                ),
                modules,
                actions,
                profiles: grant.profiles.clone(),
                preferences,
                links: Links {
                    admin: deployment.admin_url.clone(),
                    other,
                },
            }),
        }))
    })
    .await
}

/// The seconds a session that ends at `expires_at` has left at `now`, a
/// begun second counted whole, so that a page asks no earlier than the store
/// ends it; none where the end lies further ahead than `lifetime`, as for a
/// session begun under a longer `session_minutes`.
fn time_left(expires_at: i64, now: time::Timestamp, lifetime: i64) -> Option<i64> {
    let left = expires_at.checked_sub(now.as_second())?;
    (left <= lifetime).then_some(left.max(0))
}

/// Sign out: end the session and revoke its access token.
#[utoipa::path(
    post,
    path = "/api/logout",
    operation_id = "logout",
    responses(
        (
            status = 200,
            description = "The session has ended here, and the answer removes its cookie.",
            body = LogoutResponse
        ),
        (status = 403, response = Refused),
        (status = 500, response = Internal),
        (status = 503, response = Unavailable),
    ),
)]
async fn logout(State(app): State<Arc<App>>, visitor: Visitor) -> ApiResult<Response> {
    blocking(move || {
        // Logout needs Origin and CSRF like every write, but tolerates a dead grant.
        if let Some(session) = app.gate.session(&visitor)? {
            app.gate.check_write(&visitor, &session)?;
            // "ok" only for a session that is gone here; its token is
            // revoked whether or not it is.
            app.gate.end(&session, true)?;
        }
        let mut response = Json(LogoutResponse { ok: true }).into_response();
        delete_cookie(&mut response, SESSION_COOKIE);
        Ok(response)
    })
    .await
}

/// Save the signed-in user's theme and hidden modules.
#[utoipa::path(
    put,
    path = "/api/preferences",
    operation_id = "savePreferences",
    request_body = Preferences,
    responses(
        (
            status = 200,
            description = "The preferences as they were saved.",
            body = Preferences
        ),
        (status = 400, response = Invalid),
        (status = 401, response = SignInRequired),
        (status = 403, response = Refused),
        (status = 413, response = TooLarge),
        (status = 500, response = Internal),
        (status = 502, response = BadAnswer),
        (status = 503, response = Unavailable),
    ),
)]
async fn save_preferences(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    data: Result<Bytes, BytesRejection>,
) -> ApiResult<Json<Preferences>> {
    blocking(move || {
        let caller = app.gate.writer(&visitor)?;
        let value: Preferences = body(&visitor, &read(data)?)?;
        app.store
            .save_preferences(&caller.grant.subject, value)?
            .map(Json)
            .ok_or_else(ApiError::invalid)
    })
    .await
}

/// Whether the signed-in user wants the switch rows. The "Switch to Garrison
/// WebUI" script asks from the Stalwart WebUI's origin, so this answer, and no
/// other, may be read there with the user's cookie. The rows are off until a
/// user turns them on, so without a session they stay hidden.
#[utoipa::path(
    get,
    path = "/api/switch",
    operation_id = "getSwitch",
    responses(
        (
            status = 200,
            description = "Whether the signed-in user turned the switch rows on; `false` without a \
                           session.",
            body = SwitchInfo
        ),
        (status = 500, response = Internal),
    ),
)]
async fn switch(State(app): State<Arc<App>>, visitor: Visitor) -> ApiResult<Response> {
    let stalwart = crate::switch::origin(&app.config.deployment.admin_url);
    let show = blocking(move || match app.gate.session(&visitor)? {
        Some(session) => app
            .store
            .preferences(&session.subject)
            .map(|preferences| preferences.show_switch)
            .map_err(ApiError::from),
        None => Ok(false),
    })
    .await?;
    let mut response = Json(SwitchInfo { show }).into_response();
    let headers = response.headers_mut();
    if let Ok(origin) = HeaderValue::from_str(&stalwart) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    Ok(response)
}

/// When an observation was checked; `None` for a time that cannot be read.
fn checked_at(observation: &observations::Observation) -> Option<time::Timestamp> {
    let text = observation.checked_at.as_str();
    time::parse(text).or_else(|| time::parse_naive_utc(text))
}

/// Whether an observation is older than its `maxAge`; one without a time
/// that can be read is.
pub fn stale(observation: &observations::Observation, now: f64) -> bool {
    checked_at(observation)
        .is_none_or(|checked| now - time::unix(checked) > f64::from(observation.max_age))
}

/// How many seconds old an observation is at `now`, a begun second counted
/// whole; `None` for one without a time that can be read. A page adds the
/// time that passes without a new answer and so sees by itself when the
/// observation goes stale.
pub fn age(observation: &observations::Observation, now: time::Timestamp) -> Option<i64> {
    let checked = checked_at(observation)?;
    let micros = now.as_microsecond() - checked.as_microsecond();
    Some((micros + 999_999).div_euclid(1_000_000))
}

/// The latest status snapshot, limited to the user's modules.
#[utoipa::path(
    get,
    path = "/api/status",
    operation_id = "getStatus",
    responses(
        (
            status = 200,
            description = "The latest snapshot with the observations of the user's modules; \
                           `available` is false before the first collection run.",
            body = StatusResponse
        ),
        (status = 401, response = SignInRequired),
        (status = 403, response = Refused),
        (status = 500, response = Internal),
        (status = 502, response = BadAnswer),
        (status = 503, response = Unavailable),
    ),
)]
async fn status(State(app): State<Arc<App>>, visitor: Visitor) -> ApiResult<Json<StatusResponse>> {
    blocking(move || {
        let caller = app.gate.caller(&visitor)?;
        let db = reading(&app.config.database(Database::Status), READ_BUDGET)?;
        let snapshot = match db {
            Some(db) => latest_snapshot(&db)?,
            None => None,
        };
        let Some(snapshot) = snapshot else {
            return Ok(Json(StatusResponse {
                available: false,
                collected_at: None,
                observations: Vec::new(),
                provider_errors: Vec::new(),
            }));
        };
        let now = time::now();
        let granted = &caller.grant.modules;
        let observations = snapshot
            .observations
            .into_iter()
            .filter(|observation| observation.visible_to(granted))
            .map(|observation| {
                let stale = stale(&observation, time::unix(now));
                let age = age(&observation, now);
                shown(observation, granted, stale, age)
            })
            .collect();
        // Provider names are operational detail of the services module only.
        let provider_errors = if granted.contains(&ModuleId::Services) {
            snapshot
                .provider_errors
                .into_iter()
                .map(|ProviderError { provider, error }| {
                    BTreeMap::from([
                        ("provider".to_owned(), provider),
                        ("error".to_owned(), error),
                    ])
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(Json(StatusResponse {
            available: true,
            collected_at: Some(snapshot.collected_at),
            observations,
            provider_errors,
        }))
    })
    .await
}

fn day() -> String {
    "24h".to_owned()
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MetricsQuery {
    #[serde(default = "day")]
    #[param(default = "24h", pattern = "^(24h|7d|30d|90d|custom)$")]
    period: String,
    #[param(nullable, minimum = 0)]
    from: Option<i64>,
    #[param(nullable, minimum = 0)]
    to: Option<i64>,
}

/// Recorded metric history for the dashboard charts.
#[utoipa::path(
    get,
    path = "/api/metrics",
    operation_id = "getMetrics",
    params(MetricsQuery),
    responses(
        (
            status = 200,
            description = "The metric history of the period.",
            body = MetricsResponse
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
async fn metrics(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    uri: Uri,
) -> ApiResult<Json<MetricsResponse>> {
    // Parameters are checked after the caller, so strangers learn nothing.
    let (start, end, buckets) = checked(&app, visitor, &[ModuleId::Dashboard], move || {
        let Ok(Query(query)) = Query::<MetricsQuery>::try_from_uri(&uri) else {
            return Err(ApiError::invalid());
        };
        let period = query.period.as_str();
        if query.from.is_some_and(|from| from < 0) || query.to.is_some_and(|to| to < 0) {
            return Err(ApiError::invalid());
        }
        let now = time::now().as_second();
        let (start, end, buckets) = if period == "custom" {
            match (query.from, query.to) {
                (Some(start), Some(end))
                    if end <= now + 60 && (1..=90 * 86400).contains(&(end - start)) =>
                {
                    (start, end, 60)
                }
                _ => {
                    return Err(ApiError::new(
                        400,
                        "A custom range needs from < to, at most 90 days, not in the future",
                    ));
                }
            }
        } else {
            let Some((_, duration, buckets)) = PERIODS.iter().find(|(name, _, _)| *name == period)
            else {
                return Err(ApiError::invalid());
            };
            let end = now - now.rem_euclid(60);
            (end - duration, end, *buckets)
        };
        Ok((start, end, buckets))
    })
    .await?;
    let path = app.config.database(Database::Status);
    let missing = "Metric history is not available yet";
    let history = app
        .queries
        .run(path, missing, move |db| {
            Ok(history(db, start, end, buckets)?)
        })
        .await?;
    Ok(Json(history.into()))
}

impl From<History> for MetricsResponse {
    /// Every field is named: one the collector adds fails to compile here.
    fn from(history: History) -> Self {
        let History {
            from,
            to,
            points,
            totals,
            coverage_from,
            coverage_to,
            sampled_minutes,
            counter_resets,
            latest,
        } = history;
        MetricsResponse {
            from,
            to,
            points,
            totals,
            latest,
            coverage_from,
            coverage_to,
            sampled_minutes,
            counter_resets,
        }
    }
}

#[cfg(test)]
mod tests;
