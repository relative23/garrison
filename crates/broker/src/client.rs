//! The web service's side of the broker protocol.
//!
//! The web service forwards the user's token; the broker re-derives identity
//! from it. Nothing the web service says about the user is trusted.
//!
//! A broker that gives no answer the client can read is named in the web
//! service's journal, by why and at the socket, at once and then at most
//! once a minute with how many more there were: the broker's own journal
//! cannot say it, as it may not be running.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use garrison_core::json;
use serde_json::Value;

use crate::protocol::{BrokerError, MAX_ANSWER, Request, read_line};
use crate::quiet::Quiet;

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

/// Why the broker gave no answer the client can read.
#[derive(Debug)]
enum Silence {
    /// Its socket could not be reached: no socket, nobody listening on it,
    /// or no permission to it.
    Unreachable(io::Error),
    /// The request could not be written to it.
    NotSent(io::Error),
    /// No answer within the client's time.
    Late,
    /// The connection closed without an answer, as the broker closes one
    /// beyond the requests it serves at once.
    Closed,
    /// An answer that is no answer of the protocol: no JSON, more than an
    /// answer may be, or without `ok`.
    Unreadable,
    /// The answer could not be read for another reason.
    Failed(io::Error),
}

impl Silence {
    /// What the journal says of it.
    fn why(&self, timeout: Duration) -> String {
        match self {
            Silence::Unreachable(error) => format!("its socket could not be reached: {error}"),
            Silence::NotSent(error) => format!("the request could not be sent: {error}"),
            Silence::Late => format!("no answer within {} s", timeout.as_secs()),
            Silence::Closed => "it closed the connection without an answer".to_owned(),
            Silence::Unreadable => "its answer could not be read".to_owned(),
            Silence::Failed(error) => format!("its answer could not be read: {error}"),
        }
    }

    /// What the caller hears of it.
    const fn error(&self) -> CallError {
        match self {
            Silence::Unreadable => {
                CallError::Unavailable("The maintenance broker returned a malformed answer")
            }
            Silence::Unreachable(_)
            | Silence::NotSent(_)
            | Silence::Late
            | Silence::Closed
            | Silence::Failed(_) => CallError::Unavailable("The maintenance broker is unavailable"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BrokerClient {
    socket: PathBuf,
    timeout: Duration,
    /// When the journal last said that the broker gave no answer.
    quiet: Arc<Mutex<Quiet>>,
}

impl BrokerClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        BrokerClient {
            socket: socket.into(),
            timeout: Duration::from_secs(15),
            quiet: Arc::default(),
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn exchange(&self, request: &Request) -> Result<Value, Silence> {
        let mut stream = UnixStream::connect(&self.socket).map_err(Silence::Unreachable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(Silence::Failed)?;
        let mut line = serde_json::to_string(request)
            .map_err(|error| Silence::NotSent(io::Error::other(error)))?;
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .map_err(|error| match error.kind() {
                // The broker closed the connection before it read the request,
                // as it does beyond the requests it serves at once.
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => Silence::Closed,
                _ => Silence::NotSent(error),
            })?;
        let answer = read_line(&mut stream, MAX_ANSWER).map_err(|error| match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Silence::Late,
            io::ErrorKind::ConnectionReset => Silence::Closed,
            io::ErrorKind::InvalidData => Silence::Unreadable,
            _ => Silence::Failed(error),
        })?;
        if answer.is_empty() {
            return Err(Silence::Closed);
        }
        let answer = json::parse(&answer, MAX_ANSWER).map_err(|_| Silence::Unreadable)?;
        match answer.get("ok") {
            Some(Value::Bool(_)) => Ok(answer),
            _ => Err(Silence::Unreadable),
        }
    }

    /// Say why the broker gave no answer, at once and then at most once a
    /// minute.
    fn say(&self, silence: &Silence) {
        let why = silence.why(self.timeout);
        let more = self
            .quiet
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .due(&why, "for", Instant::now());
        if let Some(more) = more {
            log::warn!(
                "The broker gave the web service no answer it can use ({why}, at {}): rights \
                 cannot be checked, and users see \"Authorization is temporarily unavailable\", \
                 until it answers again{more}",
                self.socket.display()
            );
        }
    }

    /// One request; the broker's `result`, or why there is none.
    pub fn call(&self, request: &Request) -> Result<Value, CallError> {
        let answer = self.exchange(request).map_err(|silence| {
            self.say(&silence);
            silence.error()
        })?;
        if answer.get("ok") == Some(&Value::Bool(true)) {
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
