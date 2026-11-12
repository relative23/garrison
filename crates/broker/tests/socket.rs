//! The broker on a real Unix socket: peer checks, the protocol and the client.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread;
use std::time::Duration;

use garrison_authz::{Error, Grant};
use garrison_broker::client::{BrokerClient, CallError};
use garrison_broker::protocol::{BrokerError, Catalog, Request, Submitted};
use garrison_broker::runner::{Outcome, Runner};
use garrison_broker::server::serve_on;
use garrison_broker::service::{Authorize, Broker};
use garrison_broker::store::{JobStatus, JobStore};
use garrison_core::config::Action;
use garrison_core::modules::ModuleId;
use serde_json::{Value, json};

/// `admin-token` is subject 1, allowed to run `run_monitor`.
struct OneUser;

impl Authorize for OneUser {
    fn authorize(&self, token: &str) -> Result<Grant, Error> {
        if token != "admin-token" {
            return Err(Error::InvalidToken("unknown".into()));
        }
        Ok(Grant {
            subject: "1".into(),
            email: "1@example.test".into(),
            modules: BTreeSet::from([ModuleId::Dashboard, ModuleId::Actions]),
            actions: BTreeSet::from(["run_monitor".to_owned()]),
            profiles: vec!["operator".into()],
            checked_at: "2026-10-29T00:00:00+00:00".into(),
        })
    }
}

fn monitor() -> Action {
    Action {
        id: "run_monitor".into(),
        title: "Run health checks".into(),
        description: "d".into(),
        confirmation: "RUN HEALTH CHECKS".into(),
        unit: "m.service".into(),
        operation: garrison_core::config::Operation::Start,
        cooldown_seconds: 300,
        timeout_seconds: 60,
        operator: true,
    }
}

struct Nothing;

impl Runner for Nothing {
    fn preflight(&self, _: &Action) -> Result<(), BrokerError> {
        Ok(())
    }

    fn still_running(&self, _: &Action) -> bool {
        false
    }

    fn run(&self, _: &Action) -> Outcome {
        Outcome {
            status: JobStatus::Failed,
            message: "never",
            may_still_run: false,
        }
    }
}

/// A broker listening on a fresh socket that accepts `uids`; accepted jobs
/// are kept, never run.
fn serve(uids: BTreeSet<u32>) -> (BrokerClient, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let store = JobStore::open(&directory.path().join("jobs.sqlite")).unwrap();
    let broker = Broker::new(
        Box::new(OneUser),
        vec![monitor()],
        store,
        Box::new(Nothing),
        Box::new(std::mem::forget),
    );
    let path = directory.path().join("b.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || serve_on(&listener, &broker, &uids));
    (
        BrokerClient::new(path).with_timeout(Duration::from_secs(2)),
        directory,
    )
}

fn own_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn authorize(token: &str) -> Request {
    Request::Authorize {
        token: token.into(),
    }
}

/// The answer line to a request line, also one the client cannot send.
fn answer_to(directory: &Path, line: &[u8]) -> std::io::Result<Value> {
    let mut stream = UnixStream::connect(directory.join("b.sock"))?;
    stream.write_all(line)?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer)?;
    Ok(serde_json::from_str(&answer).unwrap())
}

#[test]
fn only_allowed_peer_uids_get_an_answer() {
    let (client, _directory) = serve(BTreeSet::from([own_uid()]));
    let grant = client.call(&authorize("admin-token")).unwrap();
    assert_eq!(grant["subject"], "1");
    assert_eq!(grant["modules"], json!(["dashboard", "actions"]));
    let (stranger, _other) = serve(BTreeSet::from([own_uid() + 1]));
    assert_eq!(
        stranger.call(&authorize("admin-token")),
        Err(CallError::Unavailable(
            "The maintenance broker is unavailable"
        ))
    );
}

#[test]
fn refusals_keep_their_status() {
    let (client, directory) = serve(BTreeSet::from([own_uid()]));
    let refused = |request| match client.call(&request) {
        Err(CallError::Refused(error)) => (error.status, error.message),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        refused(authorize("forged")),
        (401, "Sign-in required again".into())
    );
    let job = Request::Job {
        token: "admin-token".into(),
        id: "7".into(),
    };
    assert_eq!(refused(job), (400, "Invalid job ID".into()));
    // What is no request of the protocol never reaches an operation.
    for request in [
        json!({"op": "authorize"}),
        json!({"op": "shell", "token": "admin-token"}),
        json!({"op": "authorize", "token": "admin-token", "subject": "1"}),
        json!({"op": "job", "token": "admin-token", "id": 7}),
    ] {
        assert_eq!(
            answer_to(directory.path(), format!("{request}\n").as_bytes()).unwrap(),
            json!({"ok": false, "status": 400, "error": "Unknown broker operation"}),
            "{request}"
        );
    }
    let catalog = client
        .call(&Request::Catalog {
            token: "admin-token".into(),
        })
        .unwrap();
    let catalog: Catalog = serde_json::from_value(catalog).unwrap();
    assert_eq!(catalog.actions[0].id, "run_monitor");
}

#[test]
fn malformed_and_oversized_requests_are_invalid() {
    let (client, directory) = serve(BTreeSet::from([own_uid()]));
    drop(client);
    let invalid = json!({"ok": false, "status": 400, "error": "Invalid broker request"});
    for body in [b"{not json}\n".to_vec(), vec![b'x'; 20_000]] {
        match answer_to(directory.path(), &body) {
            Ok(answer) => assert_eq!(answer, invalid),
            // The broker stops reading at its limit and closes; unread input
            // makes the kernel reset the connection.
            Err(error) => {
                assert!(body.len() > 16384, "{error}");
                assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
            }
        }
    }
}

#[test]
fn submissions_are_idempotent_and_pending_after_a_restart() {
    let (client, directory) = serve(BTreeSet::from([own_uid()]));
    let submit = |request_id: &str| {
        let request = Request::Submit {
            token: "admin-token".into(),
            action: "run_monitor".into(),
            request_id: request_id.into(),
            confirmation: "RUN HEALTH CHECKS".into(),
        };
        client
            .call(&request)
            .map(|answer| serde_json::from_value::<Submitted>(answer).unwrap())
    };
    let first = submit("0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b").unwrap();
    assert_eq!(
        (first.replayed, first.job.status),
        (false, JobStatus::Queued)
    );
    let again = submit("0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b").unwrap();
    assert!(again.replayed);
    assert_eq!(again.job.id, first.job.id);
    // A different request while the first is queued is refused.
    match submit("1b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b") {
        Err(CallError::Refused(error)) => assert_eq!(error.status, 409),
        result => panic!("{result:?}"),
    }
    // The broker restarts while the job is pending: it is never repeated.
    let reopened = JobStore::open(&directory.path().join("jobs.sqlite")).unwrap();
    let job = reopened.get(&first.job.id).unwrap().unwrap();
    assert_eq!(job.status, JobStatus::Uncertain);
    assert!(job.may_still_run);
}
