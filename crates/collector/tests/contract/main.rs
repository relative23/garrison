//! The collector's Stalwart calls and metric names work with the pinned release.
//!
//! `garrison stalwart setup` gives the collector an API key with Replace
//! permissions `REQUIRED_PERMISSIONS`; every call must succeed with that key
//! alone. The exporter always has the gauges the
//! collector reads; a counter appears with the first event since the server
//! started and counts the events since then, so a restart removes it again and
//! the collector counts a missing counter as zero. The lab triggers the
//! counters for queued, delivered and ingested messages and failed logins. Run
//! with `cargo test --workspace --test contract -- --ignored` and the
//! variables of `cargo xtask lab start`.

// Helpers fail the test by panicking, like the test itself.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_collector::command::SystemRunner;
use garrison_collector::providers::prometheus::parse;
use garrison_collector::providers::stalwart::{REQUIRED_PERMISSIONS, calls};
use garrison_collector::providers::{Prometheus, Stalwart};
use garrison_collector::{Context, Provider, Report};
use garrison_core::config::Deployment;
use garrison_core::observations::State;
use garrison_core::time;
use garrison_stalwart::http::{MAX_RESPONSE, Request};
use garrison_stalwart::jmap::JmapClient;
use garrison_testing::lab::{Lab, random_hex, unique};
use garrison_testing::smtp::Smtp;
use serde_json::{Value, json};

const GAUGES: [&str; 4] = [
    "stalwart_server_memory_bytes",
    "stalwart_smtp_active_connections",
    "stalwart_imap_active_connections",
    "stalwart_http_active_connections",
];
const COUNTERS: [&str; 12] = [
    "stalwart_queue_message_queued_total",
    "stalwart_queue_authenticated_message_queued_total",
    "stalwart_delivery_completed_total",
    "stalwart_message_ingest_ham_total",
    "stalwart_message_ingest_spam_total",
    "stalwart_milter_action_reject_total",
    "stalwart_milter_action_temp_fail_total",
    "stalwart_milter_action_connection_failure_total",
    "stalwart_milter_timeout_total",
    "stalwart_mta_hook_action_reject_total",
    "stalwart_auth_failed_total",
    "stalwart_security_authentication_ban_total",
];

/// One test at a time: the exporter test restarts the lab server.
fn one_at_a_time() -> MutexGuard<'static, ()> {
    static LAB: Mutex<()> = Mutex::new(());
    LAB.lock().unwrap_or_else(PoisonError::into_inner)
}

fn deployment(lab: &Lab) -> Deployment {
    Deployment {
        public_origin: "https://admin.example.test".into(),
        issuer: "https://mail.example.test".into(),
        stalwart_url: lab.url.clone(),
        admin_url: "https://admin.example.test/admin/".into(),
        links: Vec::new(),
    }
}

fn collect(
    provider: &dyn Provider,
    deployment: &Deployment,
    key: Option<String>,
    metrics: Option<(String, String)>,
) -> Report {
    let directory = tempfile::tempdir().unwrap();
    let context = Context {
        deployment,
        now: time::now(),
        native_key: key,
        metrics_credential: metrics,
        events_database: directory.path().join("events.sqlite"),
        runner: &SystemRunner,
        memory: &garrison_collector::context::Forgetful,
    };
    provider.collect(&context).unwrap()
}

/// The exporter's unlabelled series, polled until `ready` accepts them.
fn scrape_until(
    lab: &Lab,
    credential: &str,
    ready: impl Fn(&BTreeMap<String, f64>) -> bool,
) -> BTreeMap<String, f64> {
    let (url, token) = (
        format!("{}/metrics/prometheus", lab.url),
        format!("Basic {}", STANDARD.encode(credential)),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let values = Request::get(&url)
            .header("Authorization", &token)
            .timeout(Duration::from_secs(8))
            .send()
            .ok()
            .filter(|answer| answer.status == 200)
            .map(|answer| parse(&String::from_utf8_lossy(&answer.body)));
        if let Some(values) = values
            && (ready(&values) || Instant::now() > deadline)
        {
            return values;
        }
        assert!(Instant::now() < deadline, "the exporter did not answer");
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// With the collector's key the certificate check finds its endpoints.
fn the_key_reads_the_listeners(lab: &Lab, secret: &str) {
    // The same key reads which listeners speak TLS: the certificate check
    // finds its endpoints there. The lab's certificate is its own, so every
    // probe ends untrusted; that it was made is what counts here.
    let tls =
        garrison_collector::providers::Tls::new(&"type = \"tls\"".parse::<toml::Table>().unwrap())
            .unwrap();
    let report = collect(&tls, &deployment(lab), Some(secret.to_owned()), None);
    let certificates = &report.observations[0];
    assert_ne!(
        certificates.state,
        State::Unknown,
        "{:?}",
        certificates.findings
    );
    let endpoints: Vec<&str> = certificates
        .table
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .filter_map(|row| row[0].as_str())
        .collect();
    for port in [":25", ":465", ":993"] {
        assert!(
            endpoints.iter().any(|endpoint| endpoint.ends_with(port)),
            "{endpoints:?}"
        );
    }
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn the_collector_calls_need_only_the_required_permissions() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let permissions: Value = REQUIRED_PERMISSIONS
        .iter()
        .map(|name| (name.to_string(), json!(true)))
        .collect();
    let created = lab.call(
        "x:ApiKey/set",
        &json!({"create": {"k": {
            "description": format!("{} collector contract test", unique()),
            "permissions": {"@type": "Replace", "permissions": permissions},
            "expiresAt": null,
        }}}),
    );
    let key = &created["created"]["k"];
    lab.created
        .push(("ApiKey".into(), key["id"].as_str().unwrap().to_owned()));
    let secret = key["secret"].as_str().unwrap().to_owned();

    let client = JmapClient::new(&lab.url, &secret).with_timeout(Duration::from_secs(15));
    let requests = calls();
    let answers = client.call_many(&requests, MAX_RESPONSE).unwrap();
    // call_many yields None for a method Stalwart refused.
    let refused: Vec<&str> = requests
        .iter()
        .zip(&answers)
        .filter(|(_, answer)| answer.is_none())
        .map(|((method, _), _)| *method)
        .collect();
    assert!(refused.is_empty(), "{refused:?}");

    let provider = Stalwart::new(&"type = \"stalwart\"".parse().unwrap()).unwrap();
    let report = collect(&provider, &deployment(&lab), Some(secret), None);
    let mailboxes = report
        .observations
        .iter()
        .find(|observation| observation.id == "stalwart.mailboxes")
        .unwrap();
    assert!(
        matches!(mailboxes.state, State::Ok | State::Warning),
        "{mailboxes:?}"
    );
    let table = mailboxes.table.as_ref().unwrap();
    assert!(table.rows.iter().all(|row| row.len() == 4));
    let spam = report
        .observations
        .iter()
        .find(|o| o.id == "stalwart.spam")
        .unwrap();
    assert_eq!(spam.state, State::Ok);

    // The same key reads each domain with the records Stalwart names for it,
    // in the form the `dns` provider reads: `name IN TYPE data` lines with
    // the records mail depends on. The resolver asked here answers nothing,
    // so every row must still be there, without an answer.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dns = garrison_collector::providers::Dns::new(
        &format!(
            "type = \"dns\"\nresolver = \"{}\"",
            silent.local_addr().unwrap()
        )
        .parse()
        .unwrap(),
    )
    .unwrap();
    let report = collect(
        &dns,
        &deployment(&lab),
        Some(key["secret"].as_str().unwrap().to_owned()),
        None,
    );
    let domain = report
        .observations
        .iter()
        .find(|observation| observation.id == "dns.example.test")
        .unwrap_or_else(|| panic!("{:?}", report.observations));
    let rows = &domain.table.as_ref().unwrap().rows;
    let named = |kind: &str, needed: &str| {
        rows.iter()
            .filter(|row| row[1] == kind && row[2] == needed)
            .count()
    };
    assert!(named("MX", "needed") >= 1, "{rows:?}");
    // SPF and DMARC; the lab's domain has no DKIM key.
    assert!(named("TXT", "needed") >= 2, "{rows:?}");
    assert!(rows.iter().all(|row| row[5] == "no answer"), "{rows:?}");

    the_key_reads_the_listeners(&lab, key["secret"].as_str().unwrap());
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn the_exporter_counts_the_events_since_the_server_started() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let (name, secret) = (unique(), random_hex(18));
    let credential = format!("{name}:{secret}");
    lab.call(
        "x:Metrics/set",
        &json!({"update": {"singleton": {"prometheus": {
            "@type": "Enabled",
            "authUsername": name,
            "authSecret": {"@type": "Value", "secret": secret},
        }}}}),
    );
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
    let domain = lab.call("x:Domain/get", &json!({"ids": null, "properties": ["id"]}));
    let domain = domain["list"][0]["id"].as_str().unwrap().to_owned();
    lab.create(
        "Account",
        &json!({
            "@type": "User",
            "name": name,
            "domainId": domain,
            "credentials": {"0": {"@type": "Password", "secret": random_hex(18)}},
        }),
    );
    let gauges_only = |values: &BTreeMap<String, f64>| {
        GAUGES.iter().all(|gauge| values.contains_key(*gauge))
            && !COUNTERS.iter().any(|counter| values.contains_key(*counter))
    };

    // The counters start over with the server; the gauges are there at once.
    lab.restart();
    let started = scrape_until(&lab, &credential, gauges_only);
    assert!(gauges_only(&started), "{started:?}");
    let provider = Prometheus::new(&"type = \"prometheus\"".parse().unwrap()).unwrap();
    let report = collect(
        &provider,
        &deployment(&lab),
        None,
        Some((name.clone(), secret.clone())),
    );
    assert_eq!(report.gauges.len(), GAUGES.len(), "{report:?}");
    // The collector reads that as: no such event since the start.
    assert_eq!(report.observations[0].state, State::Ok, "{report:?}");
    assert_eq!(report.counters.len(), COUNTERS.len(), "{report:?}");
    assert!(
        report.counters.values().all(|value| *value == 0.0),
        "{report:?}"
    );

    // One message and one failed login: each counter appears with its count.
    let message = format!(
        "From: sender@example.org\r\nTo: {name}@example.test\r\nSubject: metrics contract\r\n\r\nHello."
    );
    Smtp::connect(&smtp).send(
        "sender@example.org",
        &format!("{name}@example.test"),
        &message,
    );
    let refused = Request::get(&format!("{}/jmap/session", lab.url))
        .header(
            "Authorization",
            &format!("Basic {}", STANDARD.encode(format!("{name}:wrong"))),
        )
        .timeout(Duration::from_secs(8))
        .send()
        .unwrap();
    assert_eq!(refused.status, 401);
    let counts = |values: &BTreeMap<String, f64>| {
        let ingested = ["ham", "spam"]
            .map(|kind| format!("stalwart_message_ingest_{kind}_total"))
            .iter()
            .filter_map(|counter| values.get(counter))
            .sum::<f64>();
        [
            values.get("stalwart_queue_message_queued_total").copied(),
            values.get("stalwart_delivery_completed_total").copied(),
            values.get("stalwart_auth_failed_total").copied(),
            // The lab's filter may take the test message for either.
            Some(ingested).filter(|total| *total > 0.0),
        ]
    };
    let counted = scrape_until(&lab, &credential, |values| {
        counts(values).iter().all(Option::is_some)
    });
    assert_eq!(counts(&counted), [Some(1.0); 4], "{counted:?}");

    // A restart removes them again.
    lab.restart();
    let restarted = scrape_until(&lab, &credential, gauges_only);
    assert!(gauges_only(&restarted), "{restarted:?}");
}

/// The newest delivered messages of the lab's administrator, as their
/// Message-ID and what Stalwart's filter wrote into `X-Spam-Result`.
fn delivered(lab: &Lab) -> Vec<(String, String)> {
    let admin = std::env::var("GARRISON_LAB_ADMIN").expect("GARRISON_LAB_ADMIN");
    let session = lab.http("/jmap/session", &admin, None);
    let account = session["primaryAccounts"]["urn:ietf:params:jmap:mail"]
        .as_str()
        .expect("the administrator has a mailbox")
        .to_owned();
    let answer = lab.http(
        "/jmap/",
        &admin,
        Some(&json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Email/query", {
                    "accountId": account,
                    "sort": [{"property": "receivedAt", "isAscending": false}],
                    "limit": 20,
                }, "0"],
                ["Email/get", {
                    "accountId": account,
                    "#ids": {"resultOf": "0", "name": "Email/query", "path": "/ids"},
                    "properties": ["messageId", "header:X-Spam-Result:asText"],
                }, "1"],
            ],
        })),
    );
    answer["methodResponses"][1][1]["list"]
        .as_array()
        .unwrap_or_else(|| panic!("{answer}"))
        .iter()
        .map(|message| {
            (
                message["messageId"][0]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                message["header:X-Spam-Result:asText"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect()
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn stalwart_takes_the_mail_tests_and_knows_the_spam_text_by_its_subject() {
    let _one = one_at_a_time();
    let lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let provider = garrison_collector::providers::MailTest::new(
        &format!("type = \"mail-test\"\nrecipient = \"admin@example.test\"\nhost = \"{smtp}\"")
            .parse()
            .unwrap(),
    )
    .unwrap();
    let report = collect(&provider, &deployment(&lab), None, None);
    let results = &report.observations[0];
    let rows = &results.table.as_ref().unwrap().rows;
    // The lab has no scanner, so the test file is accepted, and that is what
    // the test must say. The spam text is accepted with a queue ID; how it was
    // filed is the event history's to say, which this test does not have.
    assert_eq!(results.state, State::Failed, "{results:?}");
    assert_eq!(
        rows[0][2], "accepted: no scanner refused the test file",
        "{rows:?}"
    );
    assert_eq!(
        rows[1][2], "accepted; the event history does not show yet how it was filed",
        "{rows:?}"
    );

    // What the test stands on: Stalwart's filter takes the spam text for the
    // test where it is the whole subject, as the provider sends it, and not
    // where it stands only in the body. The lab files every stranger's mail as
    // spam, so the filter's own reasons are read, not where the mail went.
    let text = [
        "XJS*C4JDBQADN1.NSBN3*2IDNEN*",
        "GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL",
        "*C.34X",
    ]
    .concat();
    let control = format!("{}.control@admin.example.test", unique());
    Smtp::connect(&smtp).send(
        "",
        "admin@example.test",
        &format!(
            "From: Garrison mail test <admin@example.test>\r\nTo: <admin@example.test>\r\n\
             Subject: An ordinary subject\r\nDate: Thu, 29 Oct 2026 12:00:00 +0000\r\n\
             Message-ID: <{control}>\r\nMIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=us-ascii\r\n\r\n{text}"
        ),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let (sent, compared) = loop {
        let messages = delivered(&lab);
        // Newest first: the provider's message of this run.
        let sent = messages
            .iter()
            .find(|(id, _)| id.ends_with(".gtube@admin.example.test"));
        let compared = messages.iter().find(|(id, _)| *id == control);
        if let (Some(sent), Some(compared)) = (sent, compared) {
            break (sent.clone(), compared.clone());
        }
        assert!(Instant::now() < deadline, "not delivered: {messages:?}");
        std::thread::sleep(Duration::from_secs(1));
    };
    assert!(sent.1.contains("GTUBE_TEST"), "{sent:?}");
    assert!(!compared.1.contains("GTUBE_TEST"), "{compared:?}");
}

mod notification;
