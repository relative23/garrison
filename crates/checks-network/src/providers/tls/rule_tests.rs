//! The rule of a card, held over every way an endpoint of the TLS check can
//! end without a verdict: a probe that fails, for whatever reason, an
//! endpoint the run's time left or that comes after the first 24, and what
//! the check could not learn of Stalwart's listeners and domains. For each
//! the card is not OK, and a finding names it; Stalwart's domains after the
//! first `max_domains` are named, and the card keeps the state of the
//! endpoints probed. A new way that ends OK or says nothing fails
//! here.

use std::net::TcpListener;
use std::thread;

use garrison_testing::http::{answer, json as answer_json, serve};
use garrison_testing::silent::Silent;

use super::tests::{CLOSED, listener, roots};
use super::*;
use crate::context::Deadline;
use crate::providers::dns::domains_tests::twenty_one_domains;
use crate::testing::{Canned, certificates, config, table};

/// The card of the endpoints `endpoints`, as `garrison.toml` writes them,
/// whose certificates come from `roots`, in a run with `deadline`.
fn named(endpoints: &str, roots: RootCertStore, deadline: Deadline) -> Observation {
    let provider = Tls::new(&table(&format!(
        "type = \"tls\"\nendpoints = [{endpoints}]"
    )))
    .unwrap()
    .with_roots(roots);
    card(&provider, Vec::new(), true, deadline)
}

/// The card of `provider` where Stalwart answers `answers`, with the
/// collector's key or without it.
fn card(provider: &Tls, answers: Vec<String>, key: bool, deadline: Deadline) -> Observation {
    let stalwart = (!answers.is_empty()).then(|| serve(answers));
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    if let Some(stalwart) = &stalwart {
        config.deployment.stalwart_url.clone_from(&stalwart.url);
    }
    let runner = Canned(String::new());
    let context = Context {
        native_key: key.then(|| "key".to_owned()),
        deadline,
        ..crate::testing::context(&config, &runner)
    };
    let observation = provider.collect(&context).unwrap().observations.remove(0);
    if let Some(stalwart) = stalwart {
        stalwart.requests();
    }
    observation
}

/// Stalwart's listeners, as it names them.
fn listeners(list: &Value) -> String {
    answer_json(&json!({"methodResponses": [["x:NetworkListener/get", {"list": list}, "0"]]}))
}

/// One domain whose mail host is `localhost`.
fn localhost() -> String {
    answer_json(&crate::providers::dns::domains_tests::domains_value(
        &serde_json::json!([
            {"id": "b", "name": "example.test", "dnsZoneFile": "example.test. IN MX 10 localhost.\n"}
        ]),
    ))
}

/// A way of an endpoint to end without a verdict: what it is, the card,
/// what a finding must hold, and whether the card keeps the state of the
/// endpoints probed.
type Way = (&'static str, Observation, String, bool);

/// The ways of endpoints the configuration names.
fn probed() -> Vec<Way> {
    let certificates = certificates();
    let trusted = || roots(&certificates);
    let at = |port: u16| format!("{{ host = \"localhost\", port = {port} }}");
    let none = Deadline::NONE;
    // A listener that answers TLS in plain text.
    let plain = TcpListener::bind("127.0.0.1:0").unwrap();
    let plain_port = plain.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = plain.accept() {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        }
    });
    let silent = Silent::new();
    let silent_port = silent.address.port();
    let refusing = listener(&certificates, Some("502 5.5.1 Not implemented\r\n"));
    let (misnamed, untrusted) = (listener(&certificates, None), listener(&certificates, None));
    let (good, left) = (listener(&certificates, None), listener(&certificates, None));
    let failed = |port: u16, why: &str| format!("localhost:{port} — TLS check failed ({why})");
    let ways = vec![
        (
            "a refused connection",
            named(&at(CLOSED), trusted(), none),
            failed(CLOSED, "connection refused"),
            false,
        ),
        (
            "a listener that says nothing",
            named(&at(silent_port), trusted(), none),
            failed(silent_port, "timed out"),
            false,
        ),
        (
            "a listener that speaks no TLS",
            named(&at(plain_port), trusted(), none),
            failed(plain_port, "TLS error"),
            false,
        ),
        (
            "STARTTLS refused",
            named(
                &format!("{{ host = \"localhost\", port = {refusing}, starttls = true }}"),
                trusted(),
                none,
            ),
            failed(refusing, "STARTTLS refused"),
            false,
        ),
        (
            "a certificate for another name",
            named(
                &format!("{{ host = \"mail.example.test\", port = {misnamed} }}"),
                trusted(),
                none,
            ),
            format!(
                "mail.example.test:{misnamed} — TLS check failed (certificate not valid for this \
                 name)"
            ),
            false,
        ),
        (
            "a certificate from no authority this host trusts",
            named(&at(untrusted), RootCertStore::empty(), none),
            failed(untrusted, "certificate not from a trusted authority"),
            false,
        ),
        (
            "the run's time",
            named(
                &format!("{}, {}", at(good), at(left)),
                trusted(),
                Deadline::within(Duration::ZERO),
            ),
            format!(
                "Not checked in this run, as its time was used up: localhost:{good}, \
                 localhost:{left}"
            ),
            false,
        ),
    ];
    // The probe of the listener that says nothing, and no other.
    assert_eq!(silent.finish(), 1);
    ways
}

/// The ways of endpoints the check asks Stalwart for.
fn from_stalwart() -> Vec<Way> {
    let certificates = certificates();
    let none = Deadline::NONE;
    let ports: Vec<u16> = (0..25).map(|_| listener(&certificates, None)).collect();
    let many: Vec<Value> = ports
        .iter()
        .map(|port| {
            json!({"protocol": "smtp", "bind": {format!("127.0.0.1:{port}"): true},
                   "useTls": true, "implicitTls": true})
        })
        .collect();
    let closed = json!([{"protocol": "smtp", "bind": {format!("[::]:{CLOSED}"): true},
                         "useTls": true, "implicitTls": true}]);
    let plain = json!([{"protocol": "http", "bind": {"[::]:8080": true},
                        "useTls": false, "implicitTls": false}]);
    let derived = Tls::new(&table("type = \"tls\""))
        .unwrap()
        .with_roots(roots(&certificates));
    vec![
        (
            "the endpoints after the first 24",
            card(
                &derived,
                vec![listeners(&json!(many)), localhost()],
                true,
                none,
            ),
            "make 25 endpoints; only the first 24 are checked".to_owned(),
            false,
        ),
        (
            "Stalwart's domains after the first max_domains",
            card(
                &derived,
                vec![listeners(&closed), answer_json(&twenty_one_domains())],
                true,
                none,
            ),
            "only the first 20 are checked".to_owned(),
            true,
        ),
        (
            "no key to ask Stalwart with",
            card(&derived, Vec::new(), false, none),
            "The endpoints are not known: the collector has no API key".to_owned(),
            false,
        ),
        (
            "Stalwart failed the request for its listeners",
            card(&derived, vec![answer(503, "")], true, none),
            "The endpoints are not known: Stalwart did not complete".to_owned(),
            false,
        ),
        (
            "no listener that speaks TLS",
            card(&derived, vec![listeners(&plain), localhost()], true, none),
            "Stalwart names no mail host with a listener that speaks TLS".to_owned(),
            false,
        ),
    ]
}

#[test]
fn every_endpoint_without_a_verdict_keeps_the_card_from_ok_and_is_named() {
    let mut broken = Vec::new();
    for (what, card, named, named_only) in probed().into_iter().chain(from_stalwart()) {
        let said = card.findings.iter().any(|finding| finding.contains(&named));
        if (card.state == State::Ok && !named_only) || !said {
            broken.push(format!(
                "{what} ({named}): {:?} {:?}",
                card.state, card.findings
            ));
        }
    }
    assert_eq!(broken, Vec::<String>::new());
}
