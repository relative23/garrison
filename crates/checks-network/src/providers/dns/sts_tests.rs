//! An MTA-STS policy is fetched over TLS, and its server's certificate is
//! judged at the run's time, as every check judges what it finds.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use garrison_core::observations::{Observation, State};
use garrison_core::time;
use garrison_testing::http::{json as answer_json, serve};
use garrison_testing::silent::Silent;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use serde_json::json;

use super::stand_in::{host, resolver, resolver_after, text};
use super::*;
use crate::context::Deadline;
use crate::testing::{Canned, Remembered, config, table};

/// A server on `localhost` with a certificate valid until 2026-11-13 00:00
/// UTC that answers one request with an MTA-STS policy naming the mail
/// host; its port and the authority it trusts.
fn policy_server() -> (u16, RootCertStore) {
    let certificates = garrison_testing::tls::certificates_until(2026, 11, 13);
    let mut roots = RootCertStore::empty();
    roots.add(certificates.ca.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificates.server], certificates.key)
            .unwrap();
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), stream);
        let mut request = [0u8; 2048];
        let _ = tls.read(&mut request);
        let policy = "version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 86400\n";
        let _ = write!(
            tls,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{policy}",
            policy.len()
        );
        let _ = tls.flush();
    });
    (port, roots)
}

/// The domain's card at a run of `at`, with its policy served as above.
fn domain_at(at: &str) -> Observation {
    let zone: BTreeMap<(String, u16), Vec<Vec<u8>>> = [
        (
            ("example.test", 15),
            vec![host(&[0, 10], "mail.example.test")],
        ),
        (("_mta-sts.example.test", 16), vec![text("v=STSv1; id=1")]),
    ]
    .into_iter()
    .map(|((name, kind), records)| ((name.to_owned(), kind), records))
    .collect();
    let (address, handle) = resolver(zone, None, 2);
    let (port, roots) = policy_server();
    let zone_file = "example.test. IN MX 10 mail.example.test.\n\
                     _mta-sts.example.test. IN TXT \"v=STSv1; id=1\"\n";
    let stalwart = serve(vec![answer_json(&domains_tests::domains_value(
        &serde_json::json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]),
    ))]);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&stalwart.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        now: time::parse(at).unwrap(),
        ..crate::testing::context(&config, &runner)
    };
    let provider = Dns {
        policy_url: Some(format!("https://localhost:{port}/.well-known/mta-sts.txt")),
        ..Dns::new(&table(&format!("type = \"dns\"\nresolver = \"{address}\"")))
            .unwrap()
            .with_roots(roots)
    };
    let mut observations = provider.collect(&context).unwrap().observations;
    stalwart.requests();
    handle.join().unwrap();
    observations.remove(0)
}

fn policy_result(domain: &Observation) -> serde_json::Value {
    domain.table.as_ref().unwrap().rows.last().unwrap()[5].clone()
}

#[test]
fn the_policy_servers_certificate_is_judged_at_the_runs_time() {
    // A run before the certificate's end reads the policy, whatever the
    // clock of this host says.
    let before = domain_at("2026-11-12T23:59:00Z");
    assert_eq!(policy_result(&before), json!("fits"));
    assert_eq!(before.state, State::Ok, "{:?}", before.findings);
    // A run after it finds the policy not readable.
    let after = domain_at("2026-11-13T00:01:00Z");
    assert_eq!(policy_result(&after), json!("not readable"));
    assert_eq!(after.state, State::Warning);
    assert!(
        after.findings[0].contains("the certificate expired at 2026-11-13T00:00:00+00:00"),
        "{:?}",
        after.findings
    );
}

/// The run's time ends after a domain's `_mta-sts` record was answered: its
/// policy is not fetched in that run, and the card says so.
#[test]
fn a_policy_the_runs_time_does_not_reach_is_not_fetched() {
    // Each answer comes 1.2 s after its question; the run's time for its
    // checks ends between the second question and its answer.
    let zone: BTreeMap<(String, u16), Vec<Vec<u8>>> = [
        (
            ("example.test", 15),
            vec![host(&[0, 10], "mail.example.test")],
        ),
        (("_mta-sts.example.test", 16), vec![text("v=STSv1; id=1")]),
    ]
    .into_iter()
    .map(|((name, kind), records)| ((name.to_owned(), kind), records))
    .collect();
    let (address, handle) = resolver_after(zone, None, 2, Duration::from_millis(1200));
    let policy_server = Silent::new();
    let zone_file = "example.test. IN MX 10 mail.example.test.\n\
                     _mta-sts.example.test. IN TXT \"v=STSv1; id=1\"\n";
    let stalwart = serve(vec![answer_json(&domains_tests::domains_value(
        &serde_json::json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]),
    ))]);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&stalwart.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        deadline: Deadline::within(Duration::from_secs(2)),
        ..crate::testing::context(&config, &runner)
    };
    let provider = Dns {
        policy_url: Some(format!("{}/.well-known/mta-sts.txt", policy_server.url)),
        ..Dns::new(&table(&format!("type = \"dns\"\nresolver = \"{address}\""))).unwrap()
    };
    let domain = provider.collect(&context).unwrap().observations.remove(0);
    stalwart.requests();
    handle.join().unwrap();
    assert_eq!(policy_server.finish(), 0, "the policy was not fetched");
    assert_eq!(policy_result(&domain), json!("not asked"));
    assert_eq!(domain.state, State::Partial, "{:?}", domain.findings);
    assert_eq!(
        domain.findings,
        ["Its MTA-STS policy was not fetched: the collection run's time was used up."]
    );
}

/// A policy fetched within the hour is taken from the status database, also
/// once the run's time is up: one that leaves the mail host out is a
/// warning beside the records that time left unasked, and is said first.
#[test]
fn a_kept_policy_that_leaves_the_mail_host_out_is_a_warning_beside_records_not_asked() {
    // Each answer comes 1.2 s after its question; the run's time for its
    // checks ends before the third record is asked.
    let zone: BTreeMap<(String, u16), Vec<Vec<u8>>> = [
        (("_mta-sts.example.test", 16), vec![text("v=STSv1; id=1")]),
        (
            ("example.test", 15),
            vec![host(&[0, 10], "mail.example.test")],
        ),
    ]
    .into_iter()
    .map(|((name, kind), records)| ((name.to_owned(), kind), records))
    .collect();
    let (address, handle) = resolver_after(zone, None, 2, Duration::from_millis(1200));
    let zone_file = "_mta-sts.example.test. IN TXT \"v=STSv1; id=1\"\n\
                     example.test. IN MX 10 mail.example.test.\n\
                     example.test. IN TXT \"v=spf1 mx -all\"\n";
    let stalwart = serve(vec![answer_json(&domains_tests::domains_value(
        &serde_json::json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]),
    ))]);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&stalwart.url);
    let runner = Canned(String::new());
    let memory = Remembered::default();
    let kept = json!({
        "at": crate::testing::now().as_second() - 60,
        "outcome": {"Ok": {"mode": "enforce", "hosts": ["other.example.test"], "max_age": 86400}},
        "record": ["v=STSv1; id=1"],
    });
    memory
        .0
        .borrow_mut()
        .insert("dns.sts.example.test".to_owned(), kept.to_string());
    let context = Context {
        native_key: Some("key".into()),
        deadline: Deadline::within(Duration::from_secs(2)),
        memory: &memory,
        ..crate::testing::context(&config, &runner)
    };
    let provider = Dns::new(&table(&format!("type = \"dns\"\nresolver = \"{address}\""))).unwrap();
    let domain = provider.collect(&context).unwrap().observations.remove(0);
    stalwart.requests();
    handle.join().unwrap();
    assert_eq!(policy_result(&domain), json!("leaves a mail host out"));
    assert_eq!(
        (domain.state, domain.findings.clone()),
        (
            State::Warning,
            vec![
                "The MTA-STS policy of example.test does not name mail.example.test: senders \
                 that honour it do not deliver there."
                    .to_owned(),
                "1 of its 3 records was not asked: the collection run's time was used up."
                    .to_owned(),
            ]
        )
    );
}

/// A policy the run had no time for is fetched in the next run, however
/// recently the one before was kept.
#[test]
fn a_policy_not_fetched_for_the_runs_time_is_fetched_in_the_next_run() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let memory = Remembered::default();
    let silent = Silent::new();
    let over = Context {
        deadline: Deadline::within(Duration::ZERO),
        memory: &memory,
        ..crate::testing::context(&config, &runner)
    };
    let url = format!("{}/.well-known/mta-sts.txt", silent.url);
    let record = ["v=STSv1; id=1".to_owned()];
    assert_eq!(
        sts::policy(&over, "example.test", &url, None, &record),
        None
    );
    assert_eq!(silent.finish(), 0, "nothing was fetched");
    let served = serve(vec![garrison_testing::http::answer(
        200,
        "version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 86400\n",
    )]);
    let next = Context {
        memory: &memory,
        ..crate::testing::context(&config, &runner)
    };
    let url = format!("{}/.well-known/mta-sts.txt", served.url);
    let read = sts::policy(&next, "example.test", &url, None, &record);
    served.requests();
    assert_eq!(read.unwrap().unwrap().mode, "enforce");
}

/// A policy file longer than the client reads is not read: what came
/// before the cut is no policy, and a policy cut before its `mx` lines
/// would seem to leave the mail host out.
#[test]
fn a_policy_longer_than_is_read_cannot_be_read() {
    let policy = format!(
        "version: STSv1\nmode: enforce\n{}mx: mail.example.test\nmax_age: 86400\n",
        "padding without a colon\n".repeat(13_000)
    );
    let answer = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{policy}",
        policy.len()
    );
    // The server answers whatever the client reads of it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/.well-known/mta-sts.txt",
        listener.local_addr().unwrap()
    );
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // The whole request first: a socket closed on what it did not read
        // is reset.
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if stream.read(&mut byte).unwrap_or(0) == 0 {
                break;
            }
            request.push(byte[0]);
        }
        let _ = stream.write_all(answer.as_bytes());
    });
    let zone: BTreeMap<(String, u16), Vec<Vec<u8>>> = [
        (
            ("example.test", 15),
            vec![host(&[0, 10], "mail.example.test")],
        ),
        (("_mta-sts.example.test", 16), vec![text("v=STSv1; id=1")]),
    ]
    .into_iter()
    .map(|((name, kind), records)| ((name.to_owned(), kind), records))
    .collect();
    let (address, handle) = resolver(zone, None, 2);
    let zone_file = "example.test. IN MX 10 mail.example.test.\n\
                     _mta-sts.example.test. IN TXT \"v=STSv1; id=1\"\n";
    let domain = tests::collected_with(
        &json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]),
        address,
        Some(url),
    )
    .remove(0);
    handle.join().unwrap();
    assert_eq!(policy_result(&domain), json!("not readable"));
    assert_eq!(
        (domain.state, domain.findings.clone()),
        (
            State::Warning,
            vec![
                "example.test publishes an MTA-STS record, but its policy could not be read: the \
                 answer is longer than the 256 KiB that are read."
                    .to_owned()
            ]
        )
    );
}

/// A policy is fetched once an hour, and at once where the domain's record
/// for it changed, as a sender takes a record with another id for a new
/// policy (RFC 8461, 3.1): a policy mended under a new id shows in the next
/// run, not an hour later.
#[test]
fn a_policy_is_fetched_again_once_its_record_changes() {
    let memory = Remembered::default();
    let leaves_out = "version: STSv1\nmode: enforce\nmx: other.example.test\nmax_age: 86400\n";
    let fits = "version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 86400\n";
    // Each run: when, the record's id, the policy where it is fetched, and
    // what the card says of it.
    for (later, id, policy, result) in [
        (0, 1, Some(leaves_out), "leaves a mail host out"),
        // The same record a minute later: the policy kept is used.
        (60, 1, None, "leaves a mail host out"),
        // Another id: the policy is fetched again.
        (120, 2, Some(fits), "fits"),
    ] {
        let record = format!("v=STSv1; id={id}");
        let zone: BTreeMap<(String, u16), Vec<Vec<u8>>> = [
            (
                ("example.test", 15),
                vec![host(&[0, 10], "mail.example.test")],
            ),
            (("_mta-sts.example.test", 16), vec![text(&record)]),
        ]
        .into_iter()
        .map(|((name, kind), records)| ((name.to_owned(), kind), records))
        .collect();
        let (address, handle) = resolver(zone, None, 2);
        let zone_file = format!(
            "example.test. IN MX 10 mail.example.test.\n\
             _mta-sts.example.test. IN TXT \"{record}\"\n"
        );
        let stalwart = serve(vec![answer_json(&domains_tests::domains_value(
            &serde_json::json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]),
        ))]);
        // Where no policy is due, a server that would never answer.
        let served = policy.map(|policy| serve(vec![garrison_testing::http::answer(200, policy)]));
        let silent = Silent::new();
        let url = served
            .as_ref()
            .map_or_else(|| silent.url.clone(), |served| served.url.clone());
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        config.deployment.stalwart_url.clone_from(&stalwart.url);
        let runner = Canned(String::new());
        let context = Context {
            native_key: Some("key".into()),
            now: time::Timestamp::from_second(crate::testing::now().as_second() + later).unwrap(),
            memory: &memory,
            ..crate::testing::context(&config, &runner)
        };
        let provider = Dns {
            policy_url: Some(format!("{url}/.well-known/mta-sts.txt")),
            ..Dns::new(&table(&format!("type = \"dns\"\nresolver = \"{address}\""))).unwrap()
        };
        let domain = provider.collect(&context).unwrap().observations.remove(0);
        stalwart.requests();
        handle.join().unwrap();
        if let Some(served) = served {
            served.requests();
        }
        assert_eq!(silent.finish(), 0, "{later}: nothing was fetched");
        assert_eq!(policy_result(&domain), json!(result), "{later}");
    }
}

/// The records at `_mta-sts` count as a set: a resolver that gives them in
/// another order, as one does that rotates the records of a name, changes
/// no record, and the policy kept within the hour is used.
#[test]
fn a_policy_is_not_fetched_again_for_its_records_in_another_order() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let memory = Remembered::default();
    let records = [
        "v=STSv1; id=20261124".to_owned(),
        "some-verification=abc".to_owned(),
    ];
    let served = serve(vec![garrison_testing::http::answer(
        200,
        "version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 86400\n",
    )]);
    let first = Context {
        memory: &memory,
        ..crate::testing::context(&config, &runner)
    };
    let url = format!("{}/.well-known/mta-sts.txt", served.url);
    let read = sts::policy(&first, "example.test", &url, None, &records);
    served.requests();
    assert_eq!(read.unwrap().unwrap().mode, "enforce");
    // A minute later, the same records the other way round.
    let silent = Silent::new();
    let later = Context {
        memory: &memory,
        now: time::Timestamp::from_second(crate::testing::now().as_second() + 60).unwrap(),
        ..crate::testing::context(&config, &runner)
    };
    let swapped = [records[1].clone(), records[0].clone()];
    let url = format!("{}/.well-known/mta-sts.txt", silent.url);
    let kept = sts::policy(&later, "example.test", &url, None, &swapped);
    assert_eq!(silent.finish(), 0, "the policy was fetched again");
    assert_eq!(kept.unwrap().unwrap().mode, "enforce");
}
