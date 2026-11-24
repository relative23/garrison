//! Bounded HTTP requests to loopback listeners.
//!
//! The target always comes from configuration. Proxies from the environment and
//! redirects are disabled, bodies are size-bound and nothing is decompressed.
//!
//! A request has one time for all of it, from the connection to the last
//! byte of the answer: a listener that sends a byte now and then holds the
//! caller no longer than one that says nothing.
//!
//! Garrison has two HTTP clients, on purpose. This one speaks plain HTTP to
//! an address of this host, mostly Stalwart's own listener: it is built
//! without TLS and looks up no name. What is asked under a public name, the
//! way a visitor's browser would ask (TLS against the system's trust store,
//! the system's name lookup), goes through `garrison_checks::fetch`. Both
//! bound a request in the same way: the whole of it in time, the answer in
//! size, no redirect followed.

use std::sync::LazyLock;
use std::time::Duration;

use ureq::http::{self, Method};
use ureq::{Agent, AsSendBody, Body};

use crate::Error;

pub const MAX_RESPONSE: usize = 1024 * 1024;
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

static AGENT: LazyLock<Agent> = LazyLock::new(|| {
    Agent::config_builder()
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(concat!("garrison/", env!("CARGO_PKG_VERSION")))
        .accept("")
        .build()
        .into()
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// One request; `send` returns 4xx answers but 429, which is Stalwart's rate
/// limit, and fails on 5xx, 408 and I/O errors.
#[derive(Debug)]
pub struct Request<'a> {
    url: &'a str,
    body: Option<&'a [u8]>,
    headers: Vec<(&'a str, &'a str)>,
    timeout: Duration,
    limit: usize,
}

impl<'a> Request<'a> {
    pub fn get(url: &'a str) -> Self {
        Request {
            url,
            body: None,
            headers: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            limit: MAX_RESPONSE,
        }
    }

    pub fn post(url: &'a str, body: &'a [u8]) -> Self {
        Request {
            body: Some(body),
            ..Request::get(url)
        }
    }

    #[must_use]
    pub fn header(mut self, name: &'a str, value: &'a str) -> Self {
        self.headers.push((name, value));
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    pub fn send(self) -> Result<Response, Error> {
        let limit = self.limit;
        let mut answer = self.call().map_err(|_| unavailable())?;
        let status = answer.status().as_u16();
        if status == 429 {
            return Err(Error::Limited("Stalwart answered HTTP 429".into()));
        }
        if status >= 500 || status == 408 {
            return Err(Error::Unavailable(format!(
                "Stalwart answered HTTP {status}"
            )));
        }
        // ureq fails a read once the limit is used up, even at the end of the
        // body, so allow one byte more and compare.
        let body = answer
            .body_mut()
            .with_config()
            .limit(limit as u64 + 1)
            .read_to_vec();
        match body {
            Ok(body) if body.len() <= limit => Ok(Response { status, body }),
            Ok(_) | Err(ureq::Error::BodyExceedsLimit(_)) => Err(Error::unreadable(
                "Stalwart response exceeds its size limit",
            )),
            Err(_) => Err(unavailable()),
        }
    }

    /// Only the HTTP status; the body is not read.
    pub fn status(self) -> Result<u16, Error> {
        self.call()
            .map(|answer| answer.status().as_u16())
            .map_err(|_| Error::Unavailable("The endpoint did not answer".into()))
    }

    fn call(&self) -> Result<http::Response<Body>, ureq::Error> {
        match self.body {
            None => self.run(Method::GET, ()),
            Some(body) => self.run(Method::POST, body),
        }
    }

    fn run(
        &self,
        method: Method,
        body: impl AsSendBody,
    ) -> Result<http::Response<Body>, ureq::Error> {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(self.url)
            .header("Accept-Encoding", "identity");
        for (name, value) in &self.headers {
            builder = builder.header(*name, *value);
        }
        let request = AGENT
            .configure_request(builder.body(body)?)
            .timeout_global(Some(self.timeout))
            .build();
        AGENT.run(request)
    }
}

fn unavailable() -> Error {
    Error::Unavailable("Stalwart is unavailable".into())
}

/// Only the HTTP status of a loopback endpoint; the body is not read.
pub fn status_of(url: &str, timeout: Duration) -> Result<u16, Error> {
    Request::get(url).timeout(timeout).status()
}

#[cfg(test)]
mod tests;
