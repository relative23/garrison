//! The time a run has for its checks: a resolver that does not answer is
//! asked once, and nothing is asked once that time is over.

use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use garrison_testing::http::{json as answer_json, serve};
use serde_json::json;

use super::tests::collected;
use super::*;
use crate::testing::{Canned, config, table};

#[test]
fn a_resolver_that_is_silent_is_asked_once_in_a_run_however_many_domains_there_are() {
    // It takes every question and answers none; the test counts them.
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let counting = {
        let done = std::sync::Arc::clone(&done);
        thread::spawn(move || {
            let (mut questions, mut buffer) = (0, [0u8; 512]);
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                questions += usize::from(socket.recv_from(&mut buffer).is_ok());
            }
            questions
        })
    };
    let domains: Vec<serde_json::Value> = (0..12)
        .map(|number| {
            let name = format!("d{number}.example.test");
            let zone =
                format!("{name}. IN MX 10 mail.{name}.\n{name}. IN TXT \"v=spf1 mx -all\"\n");
            json!({"id": format!("b{number}"), "name": name, "dnsZoneFile": zone})
        })
        .collect();
    let began = std::time::Instant::now();
    let observations = collected(&json!(domains), address);
    let took = began.elapsed();
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(counting.join().unwrap(), 1);
    // One question waited out its time, not one for each of 24 records.
    assert!(took < Duration::from_secs(8), "{took:?}");
    assert_eq!(observations.len(), 12);
    for observation in &observations {
        assert_eq!(observation.state, State::Unknown, "{}", observation.id);
    }
}

#[test]
fn nothing_is_asked_once_the_time_for_the_runs_checks_is_over() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    socket.set_nonblocking(true).unwrap();
    let stalwart = serve(vec![answer_json(&json!({
        "methodResponses": [["x:Domain/get", {"list": [
            {"id": "b", "name": "example.test", "dnsZoneFile": "example.test. IN MX 10 mail.example.test.\n"}
        ]}, "0"]]
    }))]);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&stalwart.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        deadline: crate::context::Deadline::within(Duration::ZERO),
        ..crate::testing::context(&config, &runner)
    };
    let provider = Dns::new(&table(&format!("type = \"dns\"\nresolver = \"{address}\""))).unwrap();
    let report = provider.collect(&context).unwrap();
    stalwart.requests();
    assert_eq!(report.observations[0].state, State::Unknown);
    let mut buffer = [0u8; 512];
    assert!(
        socket.recv_from(&mut buffer).is_err(),
        "no question was sent"
    );
}
