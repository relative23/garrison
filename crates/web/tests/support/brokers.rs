//! Brokers that stand for each kind of failure of the broker's own, as the
//! web service meets them: a socket that is not there, a broker that closes
//! the connection unanswered, holds it, or answers what is no answer, a
//! request that cannot be sent, and fixed answers of a broker that failed
//! inside or granted what the web service cannot take.

use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use garrison_broker::client::{BrokerClient, CallError};
use garrison_broker::protocol::{BrokerError, Request, read_line};
use garrison_web::security::Broker;
use serde_json::{Value, json as value};

use super::grant;
use super::rights::Fixed;

/// A broker whose socket is not there.
pub(crate) fn gone(directory: &Path) -> Arc<dyn Broker> {
    Arc::new(BrokerClient::new(directory.join("gone.sock")))
}

/// What a broker does with each connection.
#[derive(Clone, Copy)]
enum Listening {
    /// Answers with this line once it has read the request.
    Answers(&'static [u8]),
    /// Closes it unanswered.
    Closes,
    /// Keeps it open and neither reads nor answers.
    Holds,
}

/// A client for a broker that listens on `name` in `directory` and does
/// what `listening` says.
fn listening(directory: &Path, name: &str, listening: Listening) -> BrokerClient {
    let path = directory.join(name);
    if !path.exists() {
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let mut held: Vec<UnixStream> = Vec::new();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                match listening {
                    Listening::Answers(line) => {
                        let _ = read_line(&mut stream, 65536);
                        let _ = stream.write_all(line);
                    }
                    Listening::Closes => {}
                    Listening::Holds => held.push(stream),
                }
            }
        });
    }
    BrokerClient::new(path).with_timeout(Duration::from_secs(1))
}

pub(crate) fn closing(directory: &Path) -> Arc<dyn Broker> {
    Arc::new(listening(directory, "closing.sock", Listening::Closes))
}

pub(crate) fn late(directory: &Path) -> Arc<dyn Broker> {
    Arc::new(listening(directory, "late.sock", Listening::Holds))
}

pub(crate) fn garbled(directory: &Path) -> Arc<dyn Broker> {
    Arc::new(listening(
        directory,
        "garbled.sock",
        Listening::Answers(b"not json\n"),
    ))
}

pub(crate) fn unstated(directory: &Path) -> Arc<dyn Broker> {
    Arc::new(listening(
        directory,
        "unstated.sock",
        Listening::Answers(b"{\"ok\": false}\n"),
    ))
}

/// A broker that answers each request that it cannot read it, as a broker of
/// another release would.
pub(crate) fn unreading(directory: &Path) -> Arc<dyn Broker> {
    let line = b"{\"ok\": false, \"status\": 400, \"error\": \"Unknown broker operation\"}\n";
    Arc::new(listening(
        directory,
        "unreading.sock",
        Listening::Answers(line),
    ))
}

/// A client whose requests are larger than the socket takes while the broker
/// reads none, so that a request cannot be sent within the client's time.
struct Oversized(BrokerClient);

impl Broker for Oversized {
    fn call(&self, _: &Request) -> Result<Value, CallError> {
        let token = "t".repeat(8 << 20);
        self.0.call(&Request::Authorize { token })
    }
}

pub(crate) fn unsent(directory: &Path) -> Arc<dyn Broker> {
    Arc::new(Oversized(listening(
        directory,
        "deaf.sock",
        Listening::Holds,
    )))
}

pub(crate) fn failing(_: &Path) -> Arc<dyn Broker> {
    Arc::new(Fixed(Err(CallError::Refused(BrokerError {
        status: 500,
        message: "Internal broker error".into(),
    }))))
}

pub(crate) fn ungranting(_: &Path) -> Arc<dyn Broker> {
    Arc::new(Fixed(Ok(value!({"subject": "1"}))))
}

/// A broker that grants an action the web service's configuration does not
/// have, as one restarted alone after an action was added to garrison.toml.
pub(crate) fn ahead(_: &Path) -> Arc<dyn Broker> {
    Arc::new(Fixed(Ok(grant(
        "1",
        &["dashboard", "actions"],
        &["run_new"],
    ))))
}

pub(crate) fn another(_: &Path) -> Arc<dyn Broker> {
    Arc::new(Fixed(Ok(grant("2", &["dashboard"], &[]))))
}
