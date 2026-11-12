//! What the binary's tests share: running it on a prepared directory.

// Each test file uses a part of these helpers.
#![allow(dead_code, clippy::unwrap_used)]

use std::io::Read;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread::{self, JoinHandle, sleep};
use std::time::{Duration, Instant};

use garrison_testing::http::json as answer;
use garrison_testing::{config_text, policy_document, write_private};
use serde_json::{Value, json};

/// How long one run of the binary may take. A run that hangs is killed and
/// fails its test instead of stalling the suite.
const PATIENCE: Duration = Duration::from_secs(30);

pub(crate) fn run(directory: &Path, arguments: &[&str]) -> Output {
    finished(
        Command::new(env!("CARGO_BIN_EXE_garrison"))
            .arg("--config")
            .arg(directory.join("garrison.toml"))
            .args(arguments)
            .env_remove("CREDENTIALS_DIRECTORY"),
    )
}

/// Run `command` without input, as `Command::output` does, for at most
/// `PATIENCE`.
pub(crate) fn finished(command: &mut Command) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = drain(child.stdout.take().unwrap());
    let stderr = drain(child.stderr.take().unwrap());
    let deadline = Instant::now() + PATIENCE;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            let said = text(&stderr.join().unwrap());
            panic!("{command:?} still ran after {PATIENCE:?}: {said}");
        }
        sleep(Duration::from_millis(5));
    };
    Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    }
}

/// Read a pipe to its end on a thread of its own, so that a full pipe never
/// blocks the child.
fn drain(mut pipe: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut data = Vec::new();
        pipe.read_to_end(&mut data).unwrap();
        data
    })
}

pub(crate) fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A configuration in a fresh directory, with the standard policy.
pub(crate) fn prepared() -> tempfile::TempDir {
    let directory = against("http://127.0.0.1:9");
    write_private(
        &directory.path().join("policy.json"),
        policy_document().to_string().as_bytes(),
    );
    directory
}

/// A configuration whose Stalwart listens at `url`, with the broker's API key
/// but no policy yet.
pub(crate) fn against(url: &str) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("garrison.toml"),
        config_text(directory.path(), url),
    )
    .unwrap();
    garrison_testing::credentials(&garrison_testing::config(directory.path(), url));
    directory
}

/// One JMAP answer of the stub Stalwart.
pub(crate) fn respond(method: &str, list: &Value) -> String {
    answer(&json!({"methodResponses": [[method, {"list": list, "notFound": []}, "0"]]}))
}

/// A JMAP set of names, such as permissions or role IDs.
pub(crate) fn names(items: &[&str]) -> Value {
    items
        .iter()
        .map(|name| ((*name).to_owned(), json!(true)))
        .collect()
}
