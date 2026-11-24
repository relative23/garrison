//! The management API as setup calls it: one method a request, with the
//! administrator's credential.

use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::json;
use garrison_stalwart::Error;
use garrison_stalwart::http::Request;
use garrison_stalwart::jmap::{Answers, Calls, Get, Problem};
use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Serialize};

use super::MAX_ANSWER;
use super::objects::{In, Listed, Refused, Set};
use super::states;
use crate::state::State;

/// A call Stalwart did not carry out: what setup says of it, and JMAP's
/// error type where Stalwart named one, by which a caller tells a refusal
/// apart from the others.
#[derive(Debug)]
pub(super) struct Failed {
    pub(super) state: State,
    pub(super) kind: Option<String>,
}

impl Failed {
    /// Whether Stalwart refused the method, or the object, for `kind`.
    pub(super) fn is(&self, kind: &str) -> bool {
        self.kind.as_deref() == Some(kind)
    }
}

impl From<State> for Failed {
    fn from(state: State) -> Self {
        Self { state, kind: None }
    }
}

impl From<Failed> for State {
    fn from(failed: Failed) -> Self {
        failed.state
    }
}

/// Management-API calls with the operator-supplied administrator credential.
pub(super) struct Admin {
    pub(super) url: String,
    pub(super) authorization: String,
}

impl Admin {
    pub(super) fn new(config: &Config, authorization: String) -> Self {
        Admin {
            url: format!("{}/jmap/", config.deployment.stalwart_url),
            authorization,
        }
    }

    /// One method call, its answer read as a `T`.
    ///
    /// An answer that is no `T` is reported without its text: answers hold
    /// secrets, and serde quotes what it could not read.
    pub(super) fn call<A: Serialize, T: DeserializeOwned>(
        &self,
        method: &str,
        arguments: &A,
    ) -> Result<T, Failed> {
        let body = serde_json::to_string(&Calls::new([(method, arguments)]))
            .map_err(|error| states::call_failed(method, error))?;
        let answer = Request::post(&self.url, body.as_bytes())
            .header("Authorization", &self.authorization)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(30))
            .limit(MAX_ANSWER)
            .send()
            .map_err(|error| match error {
                Error::Unreadable(why) => states::unreadable(method, why),
                Error::Limited(_) => states::limited(method),
                Error::Unavailable(why)
                | Error::InvalidToken(why)
                | Error::Denied(why)
                | Error::Misconfigured(why) => states::call_failed(method, why),
            })?;
        match answer.status {
            200 => {}
            401 => return Err(states::administrator_refused().into()),
            403 => return Err(states::administrator_refused_here().into()),
            status => return Err(states::call_failed(method, format_args!("HTTP {status}")).into()),
        }
        let document = json::parse(&answer.body, MAX_ANSWER)
            .map_err(|error| states::unreadable(method, error))?;
        let malformed = || states::unreadable(method, "malformed answer");
        let answers: Answers = json::object(document).map_err(|_| malformed())?;
        let first = answers.method_responses.into_iter().next();
        let (name, payload, _) = first.ok_or_else(malformed)?;
        if name == "error" {
            let problem: Problem = json::object(payload).unwrap_or_default();
            let kind = problem.kind.unwrap_or_default();
            let description = problem.description.unwrap_or_default();
            let state = states::stalwart_error(method, &kind, &description);
            return Err(Failed {
                state,
                kind: Some(kind),
            });
        }
        if !payload.is_object() {
            return Err(malformed().into());
        }
        let refused = Refused::deserialize(&payload).map_err(|_| malformed())?;
        if let Some((kind, refusal)) = refused.first() {
            let state = states::stalwart_refused(method, &refusal);
            return Err(Failed { state, kind });
        }
        json::object(payload).map_err(|_| states::unreadable(method, "unexpected answer").into())
    }

    /// A `/set` method whose answer says nothing setup needs.
    pub(super) fn set<T: Serialize>(
        &self,
        method: &str,
        arguments: &Set<'_, T>,
    ) -> Result<(), State> {
        self.call::<_, IgnoredAny>(method, arguments)
            .map(drop)
            .map_err(State::from)
    }

    /// Every object of a kind in `account`, or in the administrator's own
    /// where that is `None`, and which account it is.
    pub(super) fn list_in<T: DeserializeOwned>(
        &self,
        kind: &str,
        account: Option<&str>,
    ) -> Result<Listed<T>, Failed> {
        let all = In {
            account,
            arguments: Get {
                ids: None,
                properties: None,
            },
        };
        self.call(&format!("x:{kind}/get"), &all)
    }

    /// A `/set` method on the objects of `account`, or on the
    /// administrator's own where that is `None`.
    pub(super) fn set_in<T: Serialize>(
        &self,
        method: &str,
        account: Option<&str>,
        arguments: &Set<'_, T>,
    ) -> Result<(), State> {
        let arguments = In { account, arguments };
        self.call::<_, IgnoredAny>(method, &arguments)
            .map(drop)
            .map_err(State::from)
    }

    /// Where a key opens its JMAP session.
    pub(super) fn session_url(&self) -> String {
        format!("{}session", self.url)
    }

    /// Every object of a kind, read as far as `T` names its fields.
    pub(super) fn list<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>, Failed> {
        self.list_in(kind, None).map(|listed| listed.list)
    }
}
