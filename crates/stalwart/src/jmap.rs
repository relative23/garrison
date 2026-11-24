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

mod listed;

pub use listed::{Listed, PAGE};

/// The arguments or the answer of a native method, as Stalwart sent them.
pub type Object = Map<String, Value>;

pub(crate) const USING: [&str; 2] = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"];

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

impl Problem {
    /// What this error of `method` means, where Stalwart did not fail on its
    /// side: `forbidden` refuses the key (measured on 1.1.0 for a key without
    /// the method's permission); any other, such as `unknownMethod` for a
    /// method Stalwart does not know (measured), is no answer this release
    /// reads. A type that is no plain name is not repeated.
    fn meaning(&self, method: &str) -> Error {
        let plain = |kind: &&str| {
            (1..=64).contains(&kind.len())
                && kind
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b":._-".contains(&byte))
        };
        match self.kind.as_deref().filter(plain) {
            Some("forbidden") => Error::Denied(format!("{method} was refused")),
            Some(kind) => Error::Unreadable(format!("{method} answered the error {kind}")),
            None => Error::Unreadable(format!(
                "{method} answered an error this release does not know"
            )),
        }
    }
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

    /// Several methods in one request; for each, what it answered, or why it
    /// gave nothing: Stalwart refused the key that method
    /// ([`Error::Denied`]), or answered it with an error this release does
    /// not expect, or not at all ([`Error::Unreadable`]).
    ///
    /// Server-side failures are [`Error::Unavailable`] for the whole request,
    /// so callers can tell "temporarily unknown" from "denied".
    pub fn call_many<A: Serialize>(
        &self,
        calls: &[(&str, A)],
        limit: usize,
    ) -> Result<Vec<Result<Object, Error>>, Error> {
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
            // Stalwart refuses a key with 401 or 403; another status, such
            // as 400 for a request whose capability it does not know, is
            // no refusal (measured on 1.1.0).
            status => {
                return Err(Error::Unreadable(format!(
                    "Unexpected native API status {status}"
                )));
            }
        }
        let malformed = || Error::unreadable("Malformed native API response");
        let result = json::parse(&answer.body, limit).map_err(|_| malformed())?;
        let answers: Answers = json::object(result).map_err(|_| malformed())?;
        // A method Stalwart says nothing of was not answered.
        let mut results: Vec<Result<Object, Error>> = calls
            .iter()
            .map(|(method, _)| Err(Error::Unreadable(format!("{method} was not answered"))))
            .collect();
        let unexpected = || Error::unreadable("Native API answered with an unexpected method");
        for (name, payload, tag) in answers.method_responses {
            let index = tag
                .parse::<usize>()
                .ok()
                .filter(|index| tag == index.to_string())
                .filter(|index| *index < calls.len());
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
                let index = index.ok_or_else(unexpected)?;
                results[index] = Err(problem.meaning(calls[index].0));
                continue;
            }
            match (index.filter(|index| name == calls[*index].0), payload) {
                (Some(index), Value::Object(payload)) => results[index] = Ok(payload),
                _ => return Err(unexpected()),
            }
        }
        Ok(results)
    }

    pub fn call<A: Serialize>(&self, method: &str, arguments: A) -> Result<Object, Error> {
        self.call_many(&[(method, arguments)], MAX_RESPONSE)?
            .pop()
            .unwrap_or_else(|| Err(Error::Unreadable(format!("{method} was not answered"))))
    }

    /// Objects by ID (`None` for all), each read as a `T`. Missing IDs are an
    /// error, not a partial success, and so is an object `T` does not accept:
    /// a shape Garrison does not know must never be read as one it knows.
    /// Stalwart gives a `/get` of all objects the first 500 of them alone
    /// (measured on 1.1.0): [`JmapClient::listed`] reads more, in pages.
    ///
    /// An ID that Stalwart says is not there is its answer to the request,
    /// [`Error::Denied`]; an answer without its list, without the objects
    /// asked for, or with an object `T` does not accept is one this release
    /// does not read.
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
        let objects = got(&method, result, ids)?;
        objects
            .into_iter()
            .map(|object| read(&method, object))
            .collect()
    }
}

/// The objects `method`, a `/get`, answered with `result`, where it gave
/// those of `ids`, every one of them.
fn got(method: &str, result: Object, ids: Option<&[&str]>) -> Result<Vec<Object>, Error> {
    let unread = |what: &str| Error::Unreadable(format!("{method} {what}"));
    let got: Got<Value> =
        json::object(Value::Object(result)).map_err(|_| unread("returned no list of objects"))?;
    if got.not_found.is_some_and(|missing| !missing.is_empty()) {
        return Err(Error::Denied(format!(
            "{method} found no object of an ID asked for"
        )));
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
            return Err(unread("did not return the objects asked for"));
        }
    }
    Ok(objects)
}

/// One object `method` answered, as a `T`.
fn read<T: DeserializeOwned>(method: &str, object: Object) -> Result<T, Error> {
    serde_json::from_value(Value::Object(object))
        .map_err(|_| Error::Unreadable(format!("{method} returned an unsupported object")))
}

#[cfg(test)]
mod tests;
