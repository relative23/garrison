//! A sign-in that approves at once and a broker that grants every module and
//! action, so the preview needs no Stalwart. A sign-in asked for with
//! `profile=viewer` gets the rights of a profile that grants little instead:
//! the dashboard and no action. A started job is queued, and the first look
//! at it finds it done, as a broker's job runs on its own.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::Router;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use garrison_broker::client::CallError;
use garrison_broker::protocol::{BrokerError, Request};
use garrison_core::config::Config;
use garrison_core::modules::ModuleId;
use garrison_core::time;
use garrison_stalwart::oidc::{CodeExchange, Token};
use serde_json::{Value, json};
use url::form_urlencoded;

/// The issuer's path on the preview's own origin.
pub(crate) const ISSUER_PATH: &str = "/preview-sign-in";
const TOKEN: &str = "preview-token";
/// The code and the token of a sign-in with the viewer's rights.
const VIEWER_CODE: &str = "preview-viewer";
const VIEWER_TOKEN: &str = "preview-token-viewer";

pub(crate) struct Identity;

impl garrison_web::Identity for Identity {
    fn exchange_code(
        &self,
        exchange: &CodeExchange<'_>,
    ) -> Result<Token, garrison_stalwart::Error> {
        let token = if exchange.code == VIEWER_CODE {
            VIEWER_TOKEN
        } else {
            TOKEN
        };
        Ok(Token {
            access_token: token.into(),
            expires_in: 8 * 3600,
        })
    }

    fn revoke(&self, _: &str, _: &str) -> Result<(), garrison_stalwart::Error> {
        Ok(())
    }
}

pub(crate) struct Broker {
    grant: Value,
    viewer: Value,
    actions: Vec<Value>,
    jobs: Mutex<Vec<Value>>,
}

impl Broker {
    pub(crate) fn new(config: &Config) -> Self {
        let actions: Vec<&str> = config
            .broker
            .actions
            .iter()
            .map(|action| action.id.as_str())
            .collect();
        Broker {
            grant: json!({
                "subject": "1",
                "email": "preview@example.test",
                "modules": ModuleId::all().map(ModuleId::as_str).collect::<Vec<_>>(),
                "actions": actions,
                "profiles": ["preview"],
                "checkedAt": time::now_isoformat(),
            }),
            viewer: json!({
                "subject": "2",
                "email": "viewer@example.test",
                "modules": ["dashboard"],
                "actions": [],
                "profiles": ["viewer"],
                "checkedAt": time::now_isoformat(),
            }),
            actions: config
                .broker
                .actions
                .iter()
                .map(|action| json!(action.public()))
                .collect(),
            jobs: Mutex::new(Vec::new()),
        }
    }

    fn jobs(&self) -> std::sync::MutexGuard<'_, Vec<Value>> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn refused(status: u16, message: &str) -> CallError {
    CallError::Refused(BrokerError {
        status,
        message: message.into(),
    })
}

impl garrison_web::security::Broker for Broker {
    fn call(&self, request: &Request) -> Result<Value, CallError> {
        let viewer = request.token() == VIEWER_TOKEN;
        match request {
            Request::Authorize { .. } if viewer => Ok(self.viewer.clone()),
            Request::Authorize { .. } => Ok(self.grant.clone()),
            // The web service asks for no more than the viewer's rights
            // allow; this answers as a broker would if it did.
            _ if viewer => Err(refused(403, "This maintenance action is not authorized")),
            Request::Catalog { .. } => Ok(json!({"actions": self.actions, "jobs": *self.jobs()})),
            Request::Submit {
                action, request_id, ..
            } => {
                let mut jobs = self.jobs();
                let job = json!({
                    "id": format!("{:032x}", jobs.len() + 1),
                    "actionId": action,
                    "actor": self.grant["subject"],
                    "actorEmail": self.grant["email"],
                    "requestId": request_id,
                    "status": "queued",
                    "createdAt": time::now_isoformat(),
                    "startedAt": null,
                    "finishedAt": null,
                    "message": "Accepted for execution.",
                });
                jobs.insert(0, job.clone());
                Ok(json!({"job": job, "replayed": false}))
            }
            Request::Job { id, .. } => {
                let mut jobs = self.jobs();
                let job = jobs
                    .iter_mut()
                    .find(|job| job["id"] == *id)
                    .ok_or_else(|| refused(404, "Job not found"))?;
                if job["status"] == "queued" {
                    let now = time::now_isoformat();
                    job["status"] = json!("succeeded");
                    job["startedAt"] = json!(now);
                    job["finishedAt"] = json!(now);
                    job["message"] = json!("Preview: nothing ran.");
                }
                Ok(job.clone())
            }
        }
    }
}

/// The issuer's login page approves at once and returns to Garrison's own
/// callback with a code, the state and the issuer (RFC 9207), as Stalwart
/// does; any other address is refused. `profile=viewer` in the request
/// signs in with the viewer's rights.
pub(crate) fn sign_in(origin: &str) -> Router {
    let callback = garrison_web::app::redirect_uri(origin);
    let issuer = format!("{origin}{ISSUER_PATH}");
    Router::new().route(
        &format!("{ISSUER_PATH}/login"),
        get(
            move |Query(query): Query<HashMap<String, String>>| async move {
                approve(&callback, &issuer, &query)
            },
        ),
    )
}

fn approve(callback: &str, issuer: &str, query: &HashMap<String, String>) -> Response {
    let (Some(redirect), Some(state)) = (query.get("redirect_uri"), query.get("state")) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if redirect != callback {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let code = match query.get("profile").map(String::as_str) {
        None => "preview",
        Some("viewer") => VIEWER_CODE,
        Some(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let answer = form_urlencoded::Serializer::new(String::new())
        .append_pair("code", code)
        .append_pair("state", state)
        .append_pair("iss", issuer)
        .finish();
    Redirect::to(&format!("{callback}?{answer}")).into_response()
}
