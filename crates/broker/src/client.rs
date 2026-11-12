//! The web service's side of the broker protocol.
//!
//! The web service forwards the user's token; the broker re-derives identity
//! from it. Nothing the web service says about the user is trusted.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use garrison_core::json;
use serde_json::Value;

use crate::protocol::{BrokerError, MAX_ANSWER, Request, read_line};

const MAX_ERROR: usize = 200;

/// Why a call did not produce an answer from the broker.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    /// The socket could not be reached or the answer was unusable.
    #[error("{0}")]
    Unavailable(&'static str),
    /// The broker refused the request.
    #[error("{0}")]
    Refused(BrokerError),
}

#[derive(Clone, Debug)]
pub struct BrokerClient {
    socket: PathBuf,
    timeout: Duration,
}

impl BrokerClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        BrokerClient {
            socket: socket.into(),
            timeout: Duration::from_secs(15),
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn exchange(&self, request: &Request) -> Option<Value> {
        let mut stream = UnixStream::connect(&self.socket).ok()?;
        stream.set_read_timeout(Some(self.timeout)).ok()?;
        stream.set_write_timeout(Some(self.timeout)).ok()?;
        let mut line = serde_json::to_string(request).ok()?;
        line.push('\n');
        stream.write_all(line.as_bytes()).ok()?;
        let answer = read_line(&mut stream, MAX_ANSWER).ok()?;
        json::parse(&answer, MAX_ANSWER).ok()
    }

    /// One request; the broker's `result`, or why there is none.
    pub fn call(&self, request: &Request) -> Result<Value, CallError> {
        let answer = self.exchange(request).ok_or(CallError::Unavailable(
            "The maintenance broker is unavailable",
        ))?;
        let Some(ok) = answer.get("ok").and_then(Value::as_bool) else {
            return Err(CallError::Unavailable(
                "The maintenance broker returned a malformed answer",
            ));
        };
        if ok {
            return Ok(answer.get("result").cloned().unwrap_or(Value::Null));
        }
        let status = answer
            .get("status")
            .and_then(Value::as_u64)
            .and_then(|status| u16::try_from(status).ok())
            .filter(|status| (400..=599).contains(status))
            .unwrap_or(502);
        let message = match answer.get("error") {
            Some(Value::String(text)) => text.clone(),
            Some(other) => other.to_string(),
            None => "Broker error".to_owned(),
        };
        Err(CallError::Refused(BrokerError {
            status,
            message: message.chars().take(MAX_ERROR).collect(),
        }))
    }
}
