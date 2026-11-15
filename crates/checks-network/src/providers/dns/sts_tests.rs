//! An MTA-STS policy is fetched over TLS, and its server's certificate is
//! judged at the run's time, as every check judges what it finds.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use garrison_core::observations::{Observation, State};
use garrison_core::time;
use garrison_testing::http::{json as answer_json, serve};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use serde_json::json;

use super::stand_in::{host, resolver, text};
use super::*;
use crate::testing::{Canned, config, table};

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
    let stalwart = serve(vec![answer_json(
        &json!({"methodResponses": [["x:Domain/get",
        {"list": [{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]}, "0"]]}),
    )]);
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
        after.findings[0].contains("the certificate is not valid for this name"),
        "{:?}",
        after.findings
    );
}
