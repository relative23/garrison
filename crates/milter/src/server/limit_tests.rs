//! What the filter does where the system refuses it something: memory for a
//! message's buffer, or a thread for a connection. Each runs in a child
//! process of this test binary, which lowers its own limits and no one
//! else's; the test that starts it reads what it said.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;

use rustix::process::{Resource, Rlimit, geteuid, getrlimit, setrlimit};

use super::tests::{MODERN, SETTINGS, answers_among, sent};
use super::*;
use crate::protocol::tests::{frame, opening};
use crate::scan::tests::message;

/// Set for the child process, which runs one of the ignored tests below.
const CHILD: &str = "GARRISON_MILTER_LIMIT_CHILD";

fn in_child() -> bool {
    std::env::var_os(CHILD).is_some()
}

/// Runs the ignored test `name` of this binary in a child process, and
/// gives back what it wrote to its output and to its errors.
fn child(name: &str) -> (String, String) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            name,
            "--include-ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stdout}\n{stderr}");
    // A name that matches no test runs nothing, and passes.
    assert!(stdout.contains("1 passed"), "{stdout}");
    (stdout, stderr)
}

/// The address space this process has, in bytes.
fn address_space() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status
        .lines()
        .find(|line| line.starts_with("VmSize:"))
        .unwrap();
    let kib: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    kib * 1024
}

/// The answers' letters.
fn letters(answers: &[(u8, Vec<u8>)]) -> String {
    answers
        .iter()
        .map(|(letter, _)| char::from(*letter))
        .collect()
}

#[test]
#[ignore = "run by the test after it, in a process of its own"]
fn with_little_memory() {
    if !in_child() {
        return;
    }
    garrison_core::logging::init(false);
    let settings = Settings {
        max_bytes: 256 << 20,
        ..SETTINGS
    };
    // A message of 160 MiB, then a small one, on one connection.
    let mut large = b"From: a@example.net\r\nTo: b@example.test\r\nSubject: Large\r\n\r\n".to_vec();
    large.resize(large.len() + (160 << 20), b'x');
    let mut frames = opening(MODERN);
    frames.extend(sent(&large, 65535));
    frames.extend(sent(&message("letter.txt", b"Nothing but text."), 1000));
    frames.extend(frame(b'Q', b""));
    drop(large);
    frames.shrink_to_fit();
    // From here, 64 MiB more address space than the process has now: the
    // large message's buffer cannot grow as far as the message.
    let before = getrlimit(Resource::As);
    let limit = Rlimit {
        current: Some(address_space() + (64 << 20)),
        maximum: before.maximum,
    };
    setrlimit(Resource::As, limit).unwrap();
    let answers = answers_among(frames, settings, &Shared::of(settings.max_bytes));
    setrlimit(Resource::As, before).unwrap();
    println!("child: answers {}", letters(&answers));
}

#[test]
fn a_message_the_system_has_no_memory_for_is_deferred_and_the_filter_goes_on() {
    let (stdout, stderr) = child("server::limit_tests::with_little_memory");
    // The opening, a temporary failure for the large message, and the
    // small one taken on the same connection.
    assert!(stdout.contains("child: answers Ota"), "{stdout}");
    assert!(
        stderr.contains("A message was not scanned: the messages being received fill"),
        "{stderr}"
    );
}

#[test]
#[ignore = "run by the test after it, in a process of its own"]
fn without_threads() {
    if !in_child() {
        return;
    }
    // Root is not bound by the number of processes.
    if geteuid().is_root() {
        println!("child: run as root");
        return;
    }
    garrison_core::logging::init(false);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || serve(&listener, SETTINGS));
    // From here, this user's processes are too many for one more thread.
    let before = getrlimit(Resource::Nproc);
    let none = Rlimit {
        current: Some(1),
        maximum: before.maximum,
    };
    setrlimit(Resource::Nproc, none).unwrap();
    let mut refused = TcpStream::connect(("127.0.0.1", port)).unwrap();
    refused
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let _ = refused.write_all(&opening(MODERN));
    let mut said = Vec::new();
    let _ = refused.read_to_end(&mut said);
    setrlimit(Resource::Nproc, before).unwrap();
    // The next connection has its thread and its answers.
    let mut taken = TcpStream::connect(("127.0.0.1", port)).unwrap();
    taken
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut frames = opening(MODERN);
    frames.extend(sent(&message("letter.txt", b"Nothing but text."), 1000));
    frames.extend(frame(b'Q', b""));
    taken.write_all(&frames).unwrap();
    let mut answered = Vec::new();
    taken.read_to_end(&mut answered).unwrap();
    println!(
        "child: refused said {} bytes, then {} bytes",
        said.len(),
        answered.len()
    );
}

#[test]
fn a_connection_without_a_thread_is_closed_and_said_and_the_next_one_is_answered() {
    let (stdout, stderr) = child("server::limit_tests::without_threads");
    if stdout.contains("child: run as root") {
        eprintln!("Not shown: root is not bound by RLIMIT_NPROC.");
        return;
    }
    assert!(
        stdout.contains("child: refused said 0 bytes, then "),
        "{stdout}"
    );
    assert!(!stdout.contains("then 0 bytes"), "{stdout}");
    assert!(
        stderr.contains("No thread for a connection of the mail server"),
        "{stderr}"
    );
}
