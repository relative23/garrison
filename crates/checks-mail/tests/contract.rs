//! The mail test against Stalwart: a test message that Stalwart defers is no
//! verdict on it.
//!
//! A milter that answers every message "not now", as a scanner that cannot
//! scan does (clamav-milter with its default `OnFail Defer` while clamd is
//! down), and a milter Stalwart cannot reach whose entry has
//! `tempFailOnError`, as `garrison stalwart setup` writes Garrison's filter
//! for `when_unreachable = "defer"`: Stalwart defers each test message at its
//! end, and the card says "not tested", Unknown.
//! Needs `GARRISON_LAB_SMTP` and `GARRISON_LAB_CALLBACK_HOST` besides the
//! lab variables, as `cargo xtask lab start` prints them; run with `cargo
//! test --workspace --test contract -- --ignored`.

// Helpers fail the test by panicking, like the test itself.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use garrison_checks::context::Provider;
use garrison_checks::testing::{Canned, context, table};
use garrison_checks_mail::providers::MailTest;
use garrison_core::observations::{Observation, State};
use garrison_milter::protocol::{self, Command, Reply};
use garrison_testing::lab::Lab;
use serde_json::json;

/// One test at a time: each sets Stalwart's milters for the lab as a whole.
fn one_at_a_time() -> MutexGuard<'static, ()> {
    static LAB: Mutex<()> = Mutex::new(());
    LAB.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A milter on `host` that answers every message's end with `reply`.
fn milter(host: &str, reply: Reply) -> u16 {
    let listener = TcpListener::bind((host, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let reply = reply.clone();
            std::thread::spawn(move || {
                while let Ok(Some(command)) = protocol::read(&mut stream) {
                    let answer = match command {
                        Command::Negotiate { .. } => Reply::Negotiate {
                            actions: 0,
                            protocol: 0,
                        },
                        Command::EndOfBody => reply.clone(),
                        Command::Quit => break,
                        Command::Abort | Command::Other(b'D') => continue,
                        _ => Reply::Continue,
                    };
                    if protocol::write(&mut stream, &answer).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Stalwart's milter entry to `port` on `host`, as setup writes it, read
/// again by Stalwart.
fn milter_entry(lab: &mut Lab, host: &str, port: u16) {
    lab.create(
        "MtaMilter",
        &json!({"host": host, "port": port, "tempFailOnError": true}),
    );
    reload(lab);
}

fn reload(lab: &Lab) {
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
    std::thread::sleep(Duration::from_secs(2));
}

/// The mail test's card, its tests sent to the lab's administrator.
fn tested(smtp: &str) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let runner = Canned(String::new());
    let provider = MailTest::new(&table(&format!(
        "type = \"mail-test\"\nrecipient = \"admin@example.test\"\nhost = \"{smtp}\""
    )))
    .unwrap();
    provider
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0)
}

fn results(observation: &Observation) -> Vec<String> {
    let rows = &observation.table.as_ref().unwrap().rows;
    rows.iter()
        .map(|row| row[2].as_str().unwrap().to_owned())
        .collect()
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_test_message_that_stalwart_defers_is_not_tested() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    // A scanner that cannot scan.
    let port = milter(&callback, Reply::TempFail);
    milter_entry(&mut lab, &callback, port);
    let deferred = tested(&smtp);
    eprintln!("a milter that defers: {:?}", results(&deferred));
    assert_eq!(deferred.state, State::Unknown, "{deferred:?}");
    for result in results(&deferred) {
        assert!(result.starts_with("not tested: 4"), "{result}");
    }
    // A milter that does not run, its entry left behind.
    let closed = TcpListener::bind((callback.as_str(), 0)).unwrap();
    let gone = closed.local_addr().unwrap().port();
    drop(closed);
    let (kind, entry) = lab.created.pop().unwrap();
    lab.call(&format!("x:{kind}/set"), &json!({"destroy": [entry]}));
    milter_entry(&mut lab, &callback, gone);
    let unreached = tested(&smtp);
    eprintln!("a milter that cannot be reached: {:?}", results(&unreached));
    assert_eq!(unreached.state, State::Unknown, "{unreached:?}");
    for result in results(&unreached) {
        assert!(result.starts_with("not tested: 4"), "{result}");
    }
}
