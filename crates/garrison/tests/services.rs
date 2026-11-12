//! The four services as processes: they start from the configuration, tell
//! systemd once they serve, answer on their sockets and stop cleanly on
//! SIGTERM, as systemd stops them.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::net::TcpListener;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use garrison_testing::{config_text, policy_document, write_private};
use serde_json::{Value, json};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn user_name() -> String {
    let uid = rustix::process::getuid().as_raw().to_string();
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap();
    passwd
        .lines()
        .find(|line| line.split(':').nth(2) == Some(uid.as_str()))
        .unwrap()
        .split(':')
        .next()
        .unwrap()
        .to_owned()
}

/// A configuration with free ports and this user as the broker's peer.
fn prepared(web: u16, ingest: u16) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let text = config_text(directory.path(), "http://127.0.0.1:9")
        .replace("[web]\n", &format!("[web]\nport = {web}\n"))
        .replace("[ingest]\n", &format!("[ingest]\nport = {ingest}\n"))
        .replace(
            "[broker]\n",
            &format!("[broker]\nallowed_peers = [\"{}\"]\n", user_name()),
        );
    std::fs::write(directory.path().join("garrison.toml"), text).unwrap();
    std::fs::create_dir_all(directory.path().join("credentials")).unwrap();
    write_private(
        &directory.path().join("credentials/webhook-signature-key"),
        b"signature-key-0123456789",
    );
    write_private(
        &directory.path().join("policy.json"),
        policy_document().to_string().as_bytes(),
    );
    directory
}

/// How long a service may take to report ready or to stop.
const PATIENCE: Duration = Duration::from_secs(10);

/// Start a service as systemd starts a `Type=notify` unit, with a socket on
/// which it reports that it serves.
fn start(directory: &Path, command: &str) -> (Child, UnixDatagram) {
    let path = directory.join("notify");
    let notify = UnixDatagram::bind(&path).unwrap();
    notify.set_read_timeout(Some(PATIENCE)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_garrison"))
        .arg("--config")
        .arg(directory.join("garrison.toml"))
        .arg(command)
        .env("NOTIFY_SOCKET", &path)
        .env_remove("CREDENTIALS_DIRECTORY")
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    (child, notify)
}

/// Wait until the service reports ready; from then on it must answer.
fn ready(notify: &UnixDatagram) {
    let mut message = [0; 64];
    let length = notify
        .recv(&mut message)
        .expect("the service did not report ready");
    assert_eq!(&message[..length], b"READY=1");
}

/// Wait for the process to end. One still running after `PATIENCE` is killed
/// and fails the test instead of letting it hang.
fn ended(mut child: Child, waiting_for: &str) -> ExitStatus {
    let deadline = Instant::now() + PATIENCE;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("{waiting_for}");
        }
        sleep(Duration::from_millis(50));
    }
}

fn stop(child: Child) -> Option<i32> {
    let pid = rustix::process::Pid::from_child(&child);
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    ended(child, "the service did not stop on SIGTERM").code()
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .proxy(None)
        .build()
        .into()
}

#[test]
fn the_ingest_service_stores_a_signed_batch_and_stops_cleanly() {
    let port = free_port();
    let directory = prepared(free_port(), port);
    let (child, notify) = start(directory.path(), "ingest");
    ready(&notify);
    let base = format!("http://127.0.0.1:{port}");
    let body = json!({"events": [{"id": "1", "createdAt": "2026-10-29T10:00:00Z", "type": "auth.failed", "data": {}}]}).to_string();
    let signature = garrison_ingest::app::signature(b"signature-key-0123456789", body.as_bytes());
    let mut answer = agent()
        .post(&format!("{base}/webhook"))
        .header("Content-Type", "application/json")
        .header("X-Signature", &signature)
        .send(&body)
        .unwrap();
    let stored: Value = serde_json::from_str(&answer.body_mut().read_to_string().unwrap()).unwrap();
    assert_eq!(
        stored,
        json!({"status": "stored", "stored": 1, "skipped": 0})
    );
    assert_eq!(stop(child), Some(0));
    assert!(directory.path().join("ingest/events.sqlite").is_file());
}

#[test]
fn the_web_service_answers_and_stops_cleanly() {
    let port = free_port();
    let directory = prepared(port, free_port());
    let (child, notify) = start(directory.path(), "web");
    ready(&notify);
    let base = format!("http://127.0.0.1:{port}");
    let mut session = agent().get(&format!("{base}/api/session")).call().unwrap();
    assert_eq!(session.status().as_u16(), 200);
    assert_eq!(
        session.body_mut().read_to_string().unwrap(),
        r#"{"session":null}"#
    );
    let page = agent().get(&format!("{base}/")).call().unwrap();
    assert_eq!(
        page.status().as_u16(),
        503,
        "no interface is built next to the test binary"
    );
    assert_eq!(stop(child), Some(0));
}

#[test]
fn the_broker_answers_its_peer_on_the_socket() {
    let directory = prepared(free_port(), free_port());
    let (child, notify) = start(directory.path(), "broker");
    ready(&notify);
    let socket = directory.path().join("broker.sock");
    let client = garrison_broker::client::BrokerClient::new(&socket);
    // Stalwart is not reachable here, so authorization is temporarily unavailable.
    let answer = client.call(&garrison_broker::protocol::Request::Authorize {
        token: "token-0123456789abcdef".into(),
    });
    match answer {
        Err(garrison_broker::client::CallError::Refused(error)) => {
            assert_eq!(
                (error.status, error.message.as_str()),
                (503, "Authorization is temporarily unavailable")
            );
        }
        other => panic!("{other:?}"),
    }
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&socket).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o660);
    stop(child);
}

#[test]
fn one_collection_run_writes_a_snapshot() {
    let directory = prepared(free_port(), free_port());
    let (child, _) = start(directory.path(), "collect");
    let status = ended(child, "the collection run did not end");
    assert!(status.success());
    let db = rusqlite::Connection::open(directory.path().join("collector/status.sqlite")).unwrap();
    let document: String = db
        .query_row("SELECT document FROM snapshots", [], |row| row.get(0))
        .unwrap();
    let document: Value = serde_json::from_str(&document).unwrap();
    assert_eq!(document["observations"][0]["id"], "host.resources");
}
