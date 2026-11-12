//! Maintenance actions. The broker authorizes and audits every request itself.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use garrison_broker::client::CallError;
use garrison_broker::protocol::{Catalog, Request, Submitted};
use garrison_broker::service::is_job_id;
use garrison_broker::store::{self, JobView};
use garrison_core::config::PublicAction;
use garrison_core::modules::ModuleId;

use super::api::body;
use crate::app::App;
use crate::error::{ApiError, ApiResult, blocking};
use crate::models::{
    ActionInfo, ActionsResponse, Job, JobStatus, SubmitRequest, SubmitResponse, typed,
};
use crate::security::Visitor;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/actions", get(catalog).post(submit))
        .route("/api/actions/jobs/{job_id}", get(job))
}

/// The broker's answer as the type both sides of the socket share.
fn call<T: serde::de::DeserializeOwned>(app: &App, request: &Request) -> ApiResult<T> {
    match app.gate.broker().call(request) {
        Ok(answer) => typed(answer),
        Err(CallError::Unavailable(_)) => {
            Err(ApiError::new(503, "The maintenance broker is unavailable"))
        }
        Err(CallError::Refused(error)) => Err(ApiError::new(error.status, error.message)),
    }
}

/// The maintenance actions the user may start, and recent jobs.
#[utoipa::path(
    get,
    path = "/api/actions",
    operation_id = "listActions",
    responses((status = 200, body = ActionsResponse)),
)]
async fn catalog(
    State(app): State<Arc<App>>,
    visitor: Visitor,
) -> ApiResult<Json<ActionsResponse>> {
    blocking(move || {
        let caller = app.gate.require(&visitor, &[ModuleId::Actions])?;
        let request = Request::Catalog {
            token: caller.session.token,
        };
        let catalog: Catalog = call(&app, &request)?;
        Ok(Json(catalog.into()))
    })
    .await
}

/// One maintenance job and its result.
#[utoipa::path(
    get,
    path = "/api/actions/jobs/{job_id}",
    operation_id = "getJob",
    params(("job_id" = String, Path, pattern = "^[0-9a-f]{32}$")),
    responses((status = 200, body = Job)),
)]
async fn job(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    Path(job_id): Path<String>,
) -> ApiResult<Json<Job>> {
    blocking(move || {
        let caller = app.gate.require(&visitor, &[ModuleId::Actions])?;
        if !is_job_id(&job_id) {
            return Err(ApiError::invalid());
        }
        let request = Request::Job {
            token: caller.session.token,
            id: job_id,
        };
        let job: JobView = call(&app, &request)?;
        Ok(Json(job.into()))
    })
    .await
}

/// Start a maintenance action after its typed confirmation.
#[utoipa::path(
    post,
    path = "/api/actions",
    operation_id = "submitAction",
    request_body = SubmitRequest,
    responses((status = 202, body = SubmitResponse)),
)]
async fn submit(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    data: Bytes,
) -> ApiResult<(StatusCode, Json<SubmitResponse>)> {
    blocking(move || {
        let caller = app.gate.writer(&visitor)?;
        let request: SubmitRequest = body(&visitor, &data)?;
        if !request.is_within_limits() {
            return Err(ApiError::invalid());
        }
        if !caller.grant.allows_action(&request.action) {
            return Err(ApiError::new(
                403,
                "This maintenance action is not authorized",
            ));
        }
        // The broker re-derives the identity from the token and re-checks the grant.
        let request = Request::Submit {
            token: caller.session.token,
            action: request.action,
            request_id: request.request_id,
            confirmation: request.confirmation,
        };
        let submitted: Submitted = call(&app, &request)?;
        Ok((StatusCode::ACCEPTED, Json(submitted.into())))
    })
    .await
}

// The broker's answers as the API states them. Each conversion names every
// field, so a field the broker adds or changes fails to compile here until the
// API, and with it the interface's types, takes a decision about it.

impl From<store::JobStatus> for JobStatus {
    fn from(status: store::JobStatus) -> Self {
        match status {
            store::JobStatus::Queued => JobStatus::Queued,
            store::JobStatus::Running => JobStatus::Running,
            store::JobStatus::Succeeded => JobStatus::Succeeded,
            store::JobStatus::Failed => JobStatus::Failed,
            store::JobStatus::Uncertain => JobStatus::Uncertain,
        }
    }
}

impl From<JobView> for Job {
    fn from(job: JobView) -> Self {
        let JobView {
            id,
            action_id,
            actor,
            actor_email,
            request_id,
            status,
            created_at,
            started_at,
            finished_at,
            message,
        } = job;
        Job {
            id,
            action_id,
            actor,
            actor_email,
            request_id,
            status: status.into(),
            created_at,
            started_at,
            finished_at,
            message,
        }
    }
}

impl From<PublicAction> for ActionInfo {
    fn from(action: PublicAction) -> Self {
        let PublicAction {
            id,
            title,
            description,
            confirmation,
            cooldown_seconds,
        } = action;
        ActionInfo {
            id,
            title,
            description,
            confirmation,
            cooldown_seconds: i64::from(cooldown_seconds),
        }
    }
}

impl From<Catalog> for ActionsResponse {
    fn from(catalog: Catalog) -> Self {
        let Catalog { actions, jobs } = catalog;
        ActionsResponse {
            actions: actions.into_iter().map(ActionInfo::from).collect(),
            jobs: jobs.into_iter().map(Job::from).collect(),
        }
    }
}

impl From<Submitted> for SubmitResponse {
    fn from(submitted: Submitted) -> Self {
        let Submitted { job, replayed } = submitted;
        SubmitResponse {
            job: job.into(),
            replayed,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn job(status: store::JobStatus) -> JobView {
        JobView {
            id: "a".repeat(32),
            action_id: "run_monitor".into(),
            actor: "1".into(),
            actor_email: "1@example.test".into(),
            request_id: "0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b".into(),
            status,
            created_at: Some("2026-10-29T00:00:00+00:00".into()),
            started_at: Some("2026-10-29T00:00:01+00:00".into()),
            finished_at: None,
            message: "Running.".into(),
        }
    }

    #[test]
    fn the_api_passes_the_brokers_answers_on_under_the_same_names() {
        for status in [
            store::JobStatus::Queued,
            store::JobStatus::Running,
            store::JobStatus::Succeeded,
            store::JobStatus::Failed,
            store::JobStatus::Uncertain,
        ] {
            assert_eq!(json!(JobStatus::from(status)), json!(status));
        }
        let catalog = Catalog {
            actions: vec![PublicAction {
                id: "run_monitor".into(),
                title: "Run health checks".into(),
                description: "Starts the monitor once.".into(),
                confirmation: "RUN HEALTH CHECKS".into(),
                cooldown_seconds: 300,
            }],
            jobs: vec![job(store::JobStatus::Running)],
        };
        assert_eq!(
            json!(ActionsResponse::from(catalog.clone())),
            json!(catalog)
        );
        let submitted = Submitted {
            job: job(store::JobStatus::Uncertain),
            replayed: true,
        };
        assert_eq!(
            json!(SubmitResponse::from(submitted.clone())),
            json!(submitted)
        );
    }
}
