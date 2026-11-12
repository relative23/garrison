//! Session, preferences, status snapshot and metric history.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
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
use serde_json::{Map, Value, json as object};

use super::auth::{delete_cookie, revoke};
use super::shown::shown;
use crate::app::App;
use crate::error::{ApiError, ApiResult, blocking};
use crate::models::{
    Links, MetricsResponse, ModuleInfo, Preferences, SessionInfo, SessionState, StatusResponse,
    SwitchInfo,
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
    responses((status = 200, body = SessionState)),
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

/// Sign out: end the session and revoke its access token.
#[utoipa::path(
    post,
    path = "/api/logout",
    operation_id = "logout",
    responses((status = 200, body = Value)),
)]
async fn logout(State(app): State<Arc<App>>, visitor: Visitor) -> ApiResult<Response> {
    blocking(move || {
        // Logout needs Origin and CSRF like every write, but tolerates a dead grant.
        if let Some(session) = app.gate.session(&visitor)? {
            app.gate.check_write(&visitor, &session)?;
            app.gate.forget(&session);
            revoke(&app, &session.token);
        }
        let mut response = Json(object!({"ok": true})).into_response();
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
    responses((status = 200, body = Preferences)),
)]
async fn save_preferences(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    data: Bytes,
) -> ApiResult<Json<Preferences>> {
    blocking(move || {
        let caller = app.gate.writer(&visitor)?;
        let value: Preferences = body(&visitor, &data)?;
        app.store
            .save_preferences(&caller.grant.subject, value)?
            .map(Json)
            .ok_or_else(ApiError::invalid)
    })
    .await
}

/// Whether the signed-in user wants the switch rows. The "Switch to Garrison
/// WebUI" script asks from the Stalwart WebUI's origin, so this answer, and no
/// other, may be read there with the user's cookie. Without a session the rows
/// stay.
#[utoipa::path(
    get,
    path = "/api/switch",
    operation_id = "getSwitch",
    responses((status = 200, body = SwitchInfo)),
)]
async fn switch(State(app): State<Arc<App>>, visitor: Visitor) -> ApiResult<Response> {
    let stalwart = crate::switch::origin(&app.config.deployment.admin_url);
    let show = blocking(move || match app.gate.session(&visitor)? {
        Some(session) => app
            .store
            .preferences(&session.subject)
            .map(|preferences| preferences.show_switch)
            .map_err(ApiError::from),
        None => Ok(true),
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

/// Whether an observation is older than its `maxAge`; one without a time
/// that can be read is.
pub fn stale(observation: &observations::Observation, now: f64) -> bool {
    let text = observation.checked_at.as_str();
    time::parse(text)
        .or_else(|| time::parse_naive_utc(text))
        .is_none_or(|checked| now - time::unix(checked) > f64::from(observation.max_age))
}

/// The latest status snapshot, limited to the user's modules.
#[utoipa::path(
    get,
    path = "/api/status",
    operation_id = "getStatus",
    responses((status = 200, body = StatusResponse)),
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
        let now = time::unix(time::now());
        let granted = &caller.grant.modules;
        let observations = snapshot
            .observations
            .into_iter()
            .filter(|observation| observation.visible_to(granted))
            .map(|observation| {
                let stale = stale(&observation, now);
                shown(observation, granted, stale)
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
    responses((status = 200, body = MetricsResponse)),
)]
async fn metrics(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    uri: Uri,
) -> ApiResult<Json<MetricsResponse>> {
    blocking(move || {
        app.gate.require(&visitor, &[ModuleId::Dashboard])?;
        // Parameters are checked after the caller, so strangers learn nothing.
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
        let Ok(_slot) = app.query_slots.try_acquire() else {
            return Err(ApiError::new(429, "Too many concurrent history queries"));
        };
        let db = reading(&app.config.database(Database::Status), READ_BUDGET)?;
        let db = db.ok_or_else(|| ApiError::new(503, "Metric history is not available yet"))?;
        let history = history(&db, start, end, buckets)?;
        Ok(Json(history.into()))
    })
    .await
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
