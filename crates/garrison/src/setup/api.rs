//! The management API as setup calls it: one method a request, with the
//! administrator's credential.

use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::json;
use garrison_stalwart::http::Request;
use garrison_stalwart::jmap::{Answers, Calls, Get, Problem};
use garrison_stalwart::{Error, SUPPORTED};
use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Serialize};

use super::MAX_ANSWER;
use super::objects::{In, Listed, Refused, Set};

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
    ) -> Result<T, String> {
        let body = serde_json::to_string(&Calls::new([(method, arguments)]))
            .map_err(|error| format!("{method}: {error}"))?;
        let answer = Request::post(&self.url, body.as_bytes())
            .header("Authorization", &self.authorization)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(30))
            .limit(MAX_ANSWER)
            .send()
            .map_err(|error| match error {
                Error::Unreadable(why) => unreadable(method, &why),
                Error::Limited(_) => format!("{method}: {}", limited()),
                Error::Unavailable(why)
                | Error::InvalidToken(why)
                | Error::Denied(why)
                | Error::Misconfigured(why) => format!("{method}: {why}"),
            })?;
        match answer.status {
            200 => {}
            // A wrong password, an unknown user and an API key Stalwart does
            // not know (measured on Stalwart 1.1.0 and 1.2.0).
            401 => {
                return Err(
                    "Stalwart refused the administrator (HTTP 401): check the user name \
                            and the password, or the API key."
                        .into(),
                );
            }
            // A credential Stalwart knows, from an address it does not take
            // it from: an API key's networks. An address it blocked gets its
            // connections closed (measured on 1.1.0), so not this answer.
            403 => {
                return Err(
                    "Stalwart refused the administrator from this host's address (HTTP \
                            403): its API key may not allow that address."
                        .into(),
                );
            }
            status => return Err(format!("{method}: HTTP {status}")),
        }
        let document = json::parse(&answer.body, MAX_ANSWER)
            .map_err(|error| unreadable(method, &error.to_string()))?;
        let malformed = || unreadable(method, "malformed answer");
        let answers: Answers = json::object(document).map_err(|_| malformed())?;
        let first = answers.method_responses.into_iter().next();
        let (name, payload, _) = first.ok_or_else(malformed)?;
        if name == "error" {
            let problem: Problem = json::object(payload).unwrap_or_default();
            return Err(format!(
                "{method}: {} {}",
                problem.kind.unwrap_or_default(),
                problem.description.unwrap_or_default()
            ));
        }
        if !payload.is_object() {
            return Err(malformed());
        }
        let refused = Refused::deserialize(&payload).map_err(|_| malformed())?;
        if let Some(refusal) = refused.first() {
            return Err(format!("{method}: {refusal}"));
        }
        json::object(payload).map_err(|_| unreadable(method, "unexpected answer"))
    }

    /// A `/set` method whose answer says nothing setup needs.
    pub(super) fn set<T: Serialize>(
        &self,
        method: &str,
        arguments: &Set<'_, T>,
    ) -> Result<(), String> {
        self.call::<_, IgnoredAny>(method, arguments).map(drop)
    }

    /// Every object of a kind in `account`, or in the administrator's own
    /// where that is `None`, and which account it is.
    pub(super) fn list_in<T: DeserializeOwned>(
        &self,
        kind: &str,
        account: Option<&str>,
    ) -> Result<Listed<T>, String> {
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
    ) -> Result<(), String> {
        let arguments = In { account, arguments };
        self.call::<_, IgnoredAny>(method, &arguments).map(drop)
    }

    /// Where a key opens its JMAP session.
    pub(super) fn session_url(&self) -> String {
        format!("{}session", self.url)
    }

    /// Every object of a kind, read as far as `T` names its fields.
    pub(super) fn list<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>, String> {
        self.list_in(kind, None).map(|listed| listed.list)
    }
}

/// What setup says where Stalwart refuses a request for its rate limit
/// (HTTP 429), as where it sees setup at another address than 127.0.0.1: a
/// run after the limit's window goes through.
pub(super) fn limited() -> String {
    "Stalwart refused the request for its limit of requests (HTTP 429), whose window is a \
     minute unless it was set otherwise"
        .to_owned()
}

/// What setup says of an answer of Stalwart's that this release does not
/// read: the method, what was wrong with it, and where the supported
/// Stalwart releases are named, since no run of setup mends it.
pub(super) fn unreadable(method: &str, what: &str) -> String {
    format!("{method}: {what}, which this release of Garrison does not read; {SUPPORTED}")
}
