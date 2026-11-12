//! Read-only calls to the Stalwart 1.0 management API (JMAP `x:` methods).
//!
//! Callers pass fixed method names and arguments; nothing here is
//! request-driven. The API key must be a dedicated, narrowly permitted Stalwart
//! API key.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use garrison_core::json;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::Error;
use crate::http::{self, MAX_RESPONSE, Request};

/// The arguments or the answer of a native method, as Stalwart sent them.
pub type Object = Map<String, Value>;

pub const USING: [&str; 2] = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"];

/// One request: each method with its arguments and a tag, which is its
/// position in the request and names it in the answer.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Calls<'a, A> {
    using: [&'static str; 2],
    method_calls: Vec<(&'a str, &'a A, String)>,
}

impl<'a, A> Calls<'a, A> {
    pub fn new(calls: impl IntoIterator<Item = (&'a str, &'a A)>) -> Self {
        let tagged = calls.into_iter().enumerate();
        Calls {
            using: USING,
            method_calls: tagged
                .map(|(index, (method, arguments))| (method, arguments, index.to_string()))
                .collect(),
        }
    }
}

/// The answer to [`Calls`]: for each method that answered its name, or
/// `error`, what it answered, and the tag of its call.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Answers {
    pub method_responses: Vec<(String, Value, String)>,
}

/// Why a method failed, as the `error` entry of an answer says it.
#[derive(Debug, Default, Deserialize)]
pub struct Problem {
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// The arguments of a `/get` method: the IDs (`None` for all objects) and
/// the properties to send (`None` for all of them).
#[derive(Clone, Debug, Serialize)]
pub struct Get<'a> {
    pub ids: Option<&'a [&'a str]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<&'a [&'a str]>,
}

/// What a `/get` method answers.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Got<T> {
    pub list: Vec<T>,
    /// The requested IDs that do not exist.
    #[serde(default)]
    pub not_found: Option<Vec<Value>>,
}

pub struct JmapClient {
    url: String,
    authorization: String,
    timeout: Duration,
}

impl fmt::Debug for JmapClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The API key stays out of logs and panic messages.
        formatter
            .debug_struct("JmapClient")
            .field("url", &self.url)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl JmapClient {
    pub fn new(stalwart_url: &str, api_key: &str) -> Self {
        JmapClient {
            url: format!("{stalwart_url}/jmap/"),
            authorization: format!("Bearer {api_key}"),
            timeout: http::DEFAULT_TIMEOUT,
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Several methods in one request; a method that failed yields `None`.
    ///
    /// Server-side failures are [`Error::Unavailable`], so callers can tell
    /// "temporarily unknown" from "denied".
    pub fn call_many<A: Serialize>(
        &self,
        calls: &[(&str, A)],
        limit: usize,
    ) -> Result<Vec<Option<Object>>, Error> {
        let request = Calls::new(calls.iter().map(|(method, arguments)| (*method, arguments)));
        let body = serde_json::to_string(&request)
            .map_err(|_| Error::denied("The native API request could not be written"))?;
        let answer = Request::post(&self.url, body.as_bytes())
            .header("Authorization", &self.authorization)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .timeout(self.timeout)
            .limit(limit)
            .send()?;
        match answer.status {
            200 => {}
            401 | 403 => return Err(Error::denied("The native API key was rejected")),
            status => {
                return Err(Error::Denied(format!(
                    "Unexpected native API status {status}"
                )));
            }
        }
        let malformed = || Error::denied("Malformed native API response");
        let result = json::parse(&answer.body, limit).map_err(|_| malformed())?;
        let answers: Answers = json::object(result).map_err(|_| malformed())?;
        let mut results: Vec<Option<Object>> = Vec::new();
        results.resize_with(calls.len(), || None);
        for (name, payload, tag) in answers.method_responses {
            if name == "error" && payload.is_object() {
                let problem: Problem = json::object(payload).unwrap_or_default();
                if matches!(
                    problem.kind.as_deref(),
                    Some("serverFail" | "serverUnavailable")
                ) {
                    return Err(Error::Unavailable(
                        "Stalwart could not complete the request".into(),
                    ));
                }
                continue;
            }
            let index = tag
                .parse::<usize>()
                .ok()
                .filter(|index| tag == index.to_string())
                .filter(|index| calls.get(*index).is_some_and(|(method, _)| name == *method));
            match (index, payload) {
                (Some(index), Value::Object(payload)) => results[index] = Some(payload),
                _ => {
                    return Err(Error::denied(
                        "Native API answered with an unexpected method",
                    ));
                }
            }
        }
        Ok(results)
    }

    pub fn call<A: Serialize>(&self, method: &str, arguments: A) -> Result<Object, Error> {
        self.call_many(&[(method, arguments)], MAX_RESPONSE)?
            .pop()
            .flatten()
            .ok_or_else(|| Error::Denied(format!("{method} was refused")))
    }

    /// Objects by ID (`None` for all), each read as a `T`. Missing IDs are an
    /// error, not a partial success, and so is an object `T` does not accept:
    /// a shape Garrison does not know must never be read as one it knows.
    pub fn get<T: DeserializeOwned>(
        &self,
        kind: &str,
        ids: Option<&[&str]>,
        properties: &[&str],
    ) -> Result<Vec<T>, Error> {
        let method = format!("x:{kind}/get");
        let arguments = Get {
            ids,
            properties: Some(properties),
        };
        let result = self.call(&method, arguments)?;
        let incomplete = || Error::Denied(format!("{method} returned incomplete data"));
        let got: Got<Value> = json::object(Value::Object(result)).map_err(|_| incomplete())?;
        if got.not_found.is_some_and(|missing| !missing.is_empty()) {
            return Err(incomplete());
        }
        // Whatever is no object is no object of this kind either.
        let objects: Vec<Object> = got
            .list
            .into_iter()
            .filter_map(|item| match item {
                Value::Object(object) => Some(object),
                _ => None,
            })
            .collect();
        if let Some(ids) = ids {
            let returned: BTreeSet<Option<&str>> = objects
                .iter()
                .map(|item| item.get("id").and_then(Value::as_str))
                .collect();
            let requested: BTreeSet<Option<&str>> = ids.iter().copied().map(Some).collect();
            if returned != requested {
                return Err(incomplete());
            }
        }
        objects
            .into_iter()
            .map(|object| {
                serde_json::from_value(Value::Object(object))
                    .map_err(|_| Error::Denied(format!("{method} returned an unsupported object")))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
