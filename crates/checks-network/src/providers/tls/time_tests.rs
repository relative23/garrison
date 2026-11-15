//! The time a run has for its checks: an endpoint is probed only while
//! there is time left, a listener that does not answer costs one probe, and
//! one that sends a byte now and then cannot hold a probe beyond its time.

use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use garrison_testing::silent::Silent;

use super::*;
use crate::context::Deadline;
use crate::testing::{Canned, config, table};

/// The observation of `endpoints` (host `localhost`) with `deadline`.
fn observed(ports: &[u16], deadline: Deadline) -> Observation {
    let listed: Vec<String> = ports
        .iter()
        .map(|port| format!("{{ host = \"localhost\", port = {port} }}"))
        .collect();
    let provider = Tls::new(&table(&format!(
        "type = \"tls\"\nendpoints = [{}]",
        listed.join(", ")
    )))
    .unwrap()
    .with_roots(RootCertStore::empty());
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = Context {
        deadline,
        ..crate::testing::context(&config, &runner)
    };
    provider.collect(&context).unwrap().observations.remove(0)
}

fn results(observation: &Observation) -> Vec<&str> {
    observation
        .table
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .map(|row| row[1].as_str().unwrap())
        .collect()
}

#[test]
fn an_endpoint_after_the_runs_time_is_named_and_not_probed() {
    let (first, second) = (Silent::new(), Silent::new());
    let ports = [first.address.port(), second.address.port()];
    let began = Instant::now();
    let observation = observed(&ports, Deadline::within(Duration::from_secs(1)));
    let took = began.elapsed();
    assert_eq!((first.finish(), second.finish()), (1, 0));
    // One probe waited out its step, not one for each endpoint.
    assert!(took < Duration::from_secs(9), "{took:?}");
    assert_eq!(results(&observation), ["failed", "not checked"]);
    assert_eq!(observation.state, State::Failed);
    assert_eq!(
        observation.findings,
        [
            format!("localhost:{} — TLS check failed (timed out).", ports[0]),
            format!(
                "Not checked in this run, as its time was used up: localhost:{}.",
                ports[1]
            ),
        ]
    );
}

#[test]
fn nothing_is_probed_once_the_runs_time_is_over() {
    let silent = Silent::new();
    let port = silent.address.port();
    let observation = observed(&[port], Deadline::within(Duration::ZERO));
    assert_eq!(silent.finish(), 0);
    assert_eq!(results(&observation), ["not checked"]);
    // Nothing was looked at: not known, and not in order.
    assert_eq!(observation.state, State::Unknown);
    assert_eq!(
        observation.findings,
        [format!(
            "Not checked in this run, as its time was used up: localhost:{port}."
        )]
    );
}

#[test]
fn a_listener_that_sends_a_byte_now_and_then_does_not_hold_a_probe_beyond_its_time() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // A greeting that never ends: each line comes well within a step.
        while stream.write_all(b"220-mail.example.test\r\n").is_ok() {
            thread::sleep(Duration::from_millis(500));
        }
    });
    let (done, probed) = mpsc::channel();
    let began = Instant::now();
    thread::spawn(move || {
        let roots = Arc::new(RootCertStore::empty());
        let _ = done.send(probe(
            "localhost",
            port,
            "127.0.0.1",
            true,
            &roots,
            crate::testing::now(),
        ));
    });
    let probed = probed
        .recv_timeout(Duration::from_secs(20))
        .expect("the probe still waits after 20 s");
    assert_eq!(probed, Err(Failure("timed out")));
    assert!(
        began.elapsed() < Duration::from_secs(13),
        "{:?}",
        began.elapsed()
    );
}
