//! The time a run has for its checks: a test message is sent only while
//! there is time left, one the run had no time for waits for the next run,
//! and a session has a time for all of it.

use std::io::Write;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use garrison_testing::silent::Silent;

use super::tests::{SILENT, provider, results, server};
use super::*;
use crate::context::{Context, Deadline};
use crate::testing::{Canned, Remembered, config, now};

/// One collection `later` seconds after the tests' clock with `deadline`,
/// and how long it took.
fn collected(
    provider: &MailTest,
    memory: &Remembered,
    later: i64,
    deadline: Deadline,
) -> (Observation, Duration) {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = Context {
        now: time::Timestamp::from_second(now().as_second() + later).unwrap(),
        memory,
        deadline,
        ..crate::testing::context(&config, &runner)
    };
    let began = Instant::now();
    let observation = provider.collect(&context).unwrap().observations.remove(0);
    (observation, began.elapsed())
}

const NOT_SENT: &str = "not tested: not sent: the collection run's time was used up";

#[test]
fn a_server_that_never_greets_costs_one_wait_and_the_next_run_sends_the_rest() {
    // One listener for both runs: it never greets the first session.
    let (port, handle) = server([
        SILENT,
        "550 5.7.1 Message rejected as spam",
        "550 5.7.1 Message rejected as spam",
        "250 2.0.0 Message queued with id c.",
    ]);
    let provider = provider(port);
    let memory = Remembered::default();
    let (first, took) = collected(
        &provider,
        &memory,
        0,
        Deadline::within(Duration::from_secs(1)),
    );
    // The test file waited out a step; the spam text was not sent.
    assert!(took < Duration::from_secs(15), "{took:?}");
    assert_eq!(
        results(&first),
        ["not tested: the server was silent for 10 s", NOT_SENT]
    );
    assert_eq!(first.state, State::Unknown);
    // The next run, a minute later, sends what this one had no time for,
    // twice where it is refused, and the harmless message after it: four
    // sessions in all.
    let (next, _) = collected(&provider, &memory, 60, Deadline::NONE);
    assert_eq!(handle.join().unwrap().len(), 4);
    assert_eq!(
        results(&next),
        [
            "not tested: the server was silent for 10 s",
            "refused: 550 5.7.1 Message rejected as spam",
            "accepted"
        ]
    );
}

#[test]
fn a_refusal_the_run_had_no_time_to_compare_is_sent_again_with_its_harmless_message() {
    // The spam text's session uses up the run's time, so no harmless
    // message follows the test file's refusals.
    let (port, handle) = server([
        "550 5.7.1 Virus found",
        "550 5.7.1 Virus found",
        SILENT,
        "550 5.7.1 Virus found",
        "550 5.7.1 Virus found",
        "250 2.0.0 Message queued with id c.",
    ]);
    let provider = provider(port).within(Duration::from_secs(1));
    let memory = Remembered::default();
    let (first, _) = collected(
        &provider,
        &memory,
        0,
        Deadline::within(Duration::from_millis(500)),
    );
    let unsure = "not tested: refused, and no harmless message got through to compare: 550 5.7.1 \
                  Virus found";
    let late = "not tested: the request was not done in its time";
    assert_eq!(
        (first.state, results(&first)),
        (State::Unknown, vec![unsure, late, NOT_SENT])
    );
    // The next run sends the test file again with a harmless message of its
    // own, and the refusal counts.
    let (next, _) = collected(&provider, &memory, 60, Deadline::NONE);
    assert_eq!(
        results(&next),
        ["refused: 550 5.7.1 Virus found", late, "accepted"]
    );
    let sessions = handle.join().unwrap();
    assert_eq!(sessions.len(), 6);
    assert!(sessions[3].contains("EICAR"), "{}", sessions[3]);
    assert!(
        sessions[5].contains("Harmless message (control)"),
        "{}",
        sessions[5]
    );
}

#[test]
fn a_run_without_time_sends_nothing() {
    let silent = Silent::new();
    let provider = provider(silent.address.port());
    let (observation, _) = collected(
        &provider,
        &Remembered::default(),
        0,
        Deadline::within(Duration::ZERO),
    );
    assert_eq!(silent.finish(), 0);
    assert_eq!(results(&observation), [NOT_SENT, NOT_SENT]);
    assert_eq!(observation.state, State::Unknown);
}

#[test]
fn a_server_that_sends_a_line_now_and_then_does_not_hold_a_session_beyond_its_time() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            thread::spawn(move || {
                // A greeting that never ends: each line well within a step.
                while stream.write_all(b"220-mail.example.test\r\n").is_ok() {
                    thread::sleep(Duration::from_millis(300));
                }
            });
        }
    });
    let provider = provider(port).within(Duration::from_secs(2));
    let (done, observed) = mpsc::channel();
    thread::spawn(move || {
        let _ = done.send(collected(
            &provider,
            &Remembered::default(),
            0,
            Deadline::NONE,
        ));
    });
    let (observation, took) = observed
        .recv_timeout(Duration::from_secs(20))
        .expect("the sessions still wait after 20 s");
    // Two sessions of two seconds each.
    assert!(took < Duration::from_secs(8), "{took:?}");
    assert_eq!(
        results(&observation),
        [
            "not tested: the request was not done in its time",
            "not tested: the request was not done in its time"
        ]
    );
}

/// Stalwart takes five connections a second from one address and turns the
/// sixth away, and a run opens more: each session waits its pace first, so
/// five sessions take five paces at the least.
#[test]
fn every_session_waits_its_pace_before_it_begins() {
    let (port, handle) = server([
        "550 5.7.1 Virus found",
        "550 5.7.1 Virus found",
        "550 5.7.1 Spam",
        "550 5.7.1 Spam",
        "250 2.0.0 Message queued with id c.",
    ]);
    let provider = provider(port).paced(Duration::from_millis(40));
    let (observation, took) = collected(&provider, &Remembered::default(), 0, Deadline::NONE);
    assert_eq!(handle.join().unwrap().len(), 5);
    assert_eq!(results(&observation).len(), 3);
    assert!(took >= Duration::from_millis(200), "{took:?}");
}
