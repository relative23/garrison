//! Local broker protocol: one JSON request and one JSON answer per connection,
//! each a line. The client and the server share these types and limits, so the
//! two sides of one release cannot disagree about a field.
//!
//! The answer line is `{"ok": true, "result": …}` with a [`Grant`], a
//! [`Catalog`], a [`JobView`] or a [`Submitted`], or
//! `{"ok": false, "status": …, "error": …}` with a [`BrokerError`].
//!
//! [`Grant`]: garrison_authz::Grant

use std::fmt;
use std::io::{self, Read};

use garrison_core::config::PublicAction;
use garrison_core::json;
use serde::{Deserialize, Serialize};

use crate::store::JobView;

pub const MAX_REQUEST: usize = 16384;
pub const MAX_ANSWER: usize = 1024 * 1024;

/// One request. The user's token is all the broker hears about who asks; it
/// derives the identity and the rights itself.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum Request {
    /// The grant of the token's user.
    Authorize { token: String },
    /// The actions the user may start, and their recent jobs.
    Catalog { token: String },
    /// One job by its ID.
    Job { token: String, id: String },
    /// Start an action after its typed confirmation.
    #[serde(rename_all = "camelCase")]
    Submit {
        token: String,
        action: String,
        request_id: String,
        confirmation: String,
    },
}

impl Request {
    pub fn token(&self) -> &str {
        match self {
            Request::Authorize { token }
            | Request::Catalog { token }
            | Request::Job { token, .. }
            | Request::Submit { token, .. } => token,
        }
    }

    const fn operation(&self) -> &'static str {
        match self {
            Request::Authorize { .. } => "authorize",
            Request::Catalog { .. } => "catalog",
            Request::Job { .. } => "job",
            Request::Submit { .. } => "submit",
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token stays out of logs and panic messages.
        formatter
            .debug_struct("Request")
            .field("op", &self.operation())
            .finish_non_exhaustive()
    }
}

/// Read a request line. It must be strict JSON (no key twice, so no two
/// readers could understand it differently) and one of the requests exactly:
/// an unknown operation and an unknown, missing or mistyped field are refused.
pub fn decode(line: &[u8]) -> Result<Request, BrokerError> {
    let value =
        json::parse(line, MAX_REQUEST).map_err(|_| refuse(400, "Invalid broker request"))?;
    // serde would also read a request written as a list of its values.
    if !value.is_object() {
        return Err(refuse(400, "Unknown broker operation"));
    }
    serde_json::from_value(value).map_err(|_| refuse(400, "Unknown broker operation"))
}

/// The answer to [`Request::Catalog`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub actions: Vec<PublicAction>,
    pub jobs: Vec<JobView>,
}

/// The answer to [`Request::Submit`]: the job, and whether the request ID had
/// been accepted before, in which case nothing new was started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submitted {
    pub job: JobView,
    pub replayed: bool,
}

/// A refusal with the HTTP status the web service answers with.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct BrokerError {
    pub status: u16,
    pub message: String,
}

pub fn refuse(status: u16, message: &str) -> BrokerError {
    BrokerError {
        status,
        message: message.to_owned(),
    }
}

/// Bytes up to and including the first newline, or to the end of the stream.
pub fn read_line(stream: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut chunk = vec![0; 65536];
    while !data.ends_with(b"\n") {
        let room = (limit + 1 - data.len()).min(chunk.len());
        let read = stream.read(&mut chunk[..room])?;
        if read == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..read]);
        if data.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Message too large",
            ));
        }
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    fn submit() -> Request {
        Request::Submit {
            token: "admin-token".into(),
            action: "run_monitor".into(),
            request_id: "0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b".into(),
            confirmation: "RUN HEALTH CHECKS".into(),
        }
    }

    #[test]
    fn a_request_is_one_line_that_reads_back_and_shows_no_token() {
        let line = serde_json::to_string(&submit()).unwrap();
        assert_eq!(
            line,
            r#"{"op":"submit","token":"admin-token","action":"run_monitor","requestId":"0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b","confirmation":"RUN HEALTH CHECKS"}"#
        );
        assert_eq!(decode(format!("{line}\n").as_bytes()).unwrap(), submit());
        let job = Request::Job {
            token: "admin-token".into(),
            id: "a".repeat(32),
        };
        for request in [
            Request::Authorize {
                token: "admin-token".into(),
            },
            Request::Catalog {
                token: "admin-token".into(),
            },
            job,
            submit(),
        ] {
            let line = serde_json::to_vec(&request).unwrap();
            assert_eq!(decode(&line).unwrap(), request);
            assert_eq!(request.token(), "admin-token");
            assert!(!format!("{request:?}").contains("admin-token"));
        }
        assert_eq!(format!("{:?}", submit()), r#"Request { op: "submit", .. }"#);
    }

    #[test]
    fn only_the_four_requests_decode_and_only_exactly() {
        let id = "a".repeat(32);
        for request in [
            json!({"op": "authorize", "token": "admin-token", "extra": 1}),
            json!({"op": "authorize", "token": "admin-token", "subject": "1"}),
            json!({"op": "catalog", "token": "admin-token", "id": id}),
            json!({"op": "job", "token": "admin-token", "id": id, "extra": 1}),
            json!({"op": "submit", "token": "admin-token", "action": "a", "requestId": "r",
                   "confirmation": "C", "extra": 1}),
            json!({"op": "submit", "token": "admin-token", "action": "a", "request_id": "r",
                   "confirmation": "C"}),
            json!({"op": "submit", "token": "admin-token", "action": 1, "requestId": "r",
                   "confirmation": "C"}),
            json!({"op": "submit", "token": "admin-token"}),
            json!({"op": "job", "token": "admin-token", "id": 7}),
            json!({"op": "job", "token": "admin-token"}),
            json!({"op": "authorize"}),
            json!({"op": "authorize", "token": 7}),
            json!({"op": "Authorize", "token": "admin-token"}),
            json!({"op": "shell", "token": "admin-token"}),
            json!({"token": "admin-token"}),
            json!(["authorize", "admin-token"]),
            json!("authorize"),
        ] {
            let error = decode(request.to_string().as_bytes()).unwrap_err();
            assert_eq!(
                (error.status, error.message.as_str()),
                (400, "Unknown broker operation"),
                "{request}"
            );
        }
    }

    #[test]
    fn a_line_that_is_not_strict_json_is_no_request() {
        let twice = br#"{"op": "catalog", "token": "admin-token", "token": "other"}"#;
        let long = [vec![b' '; MAX_REQUEST], b"{}".to_vec()].concat();
        for line in [&b"{not json}"[..], b"", twice, &long] {
            let error = decode(line).unwrap_err();
            assert_eq!(
                (error.status, error.message.as_str()),
                (400, "Invalid broker request"),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[test]
    fn answers_keep_their_names_and_refuse_others() {
        let catalog = json!({
            "actions": [{
                "id": "run_monitor", "title": "Monitor", "description": "d",
                "confirmation": "RUN", "cooldownSeconds": 300,
            }],
            "jobs": [],
        });
        let read: Catalog = serde_json::from_value(catalog.clone()).unwrap();
        assert_eq!(read.actions[0].cooldown_seconds, 300);
        assert_eq!(serde_json::to_value(&read).unwrap(), catalog);
        let mut more = catalog;
        more["unit"] = json!("m.service");
        assert!(serde_json::from_value::<Catalog>(more).is_err());
        assert!(serde_json::from_value::<Submitted>(json!({"replayed": false})).is_err());
    }

    #[test]
    fn a_line_may_use_its_whole_limit() {
        let mut exact: &[u8] = &[b'x'; 100];
        assert_eq!(read_line(&mut exact, 100).unwrap().len(), 100);
        let mut over: &[u8] = &[b'x'; 101];
        assert!(read_line(&mut over, 100).is_err());
        let request = [vec![b'x'; 16000], b"\n".to_vec()].concat();
        assert_eq!(
            read_line(&mut request.as_slice(), MAX_REQUEST)
                .unwrap()
                .len(),
            16001
        );
        let answer = [vec![b'x'; 900_000], b"\n".to_vec()].concat();
        assert_eq!(
            read_line(&mut answer.as_slice(), MAX_ANSWER).unwrap().len(),
            900_001
        );
    }

    #[test]
    fn lines_end_at_the_newline_or_the_limit() {
        let mut input: &[u8] = b"{\"a\":1}\nrest";
        assert_eq!(read_line(&mut input, 100).unwrap(), b"{\"a\":1}\nrest");
        let mut unterminated: &[u8] = b"{}";
        assert_eq!(read_line(&mut unterminated, 100).unwrap(), b"{}");
        let mut long: &[u8] = &[b'x'; 200];
        assert_eq!(
            read_line(&mut long, 100).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
