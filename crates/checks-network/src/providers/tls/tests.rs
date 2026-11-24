use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::thread;

use rustls::{ServerConfig, ServerConnection};

use super::*;
use crate::testing::{Certificates, certificates, certificates_until, now};

/// A port that is closed for every test: no test can bind it (it is below
/// 1024) and nothing on a test host listens on it. A free port that a test
/// gives back can be bound by another test's server before the connection
/// is made, which answered a TLS probe with an HTTP test server.
pub(crate) const CLOSED: u16 = 9;

pub(crate) fn roots(certificates: &Certificates) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certificates.ca.clone()).unwrap();
    roots
}

fn trusted(certificates: &Certificates) -> Arc<RootCertStore> {
    Arc::new(roots(certificates))
}

/// A TLS listener for `localhost` that serves one connection; with
/// `smtp`, it first speaks SMTP up to STARTTLS (or refuses it).
pub(crate) fn listener(certificates: &Certificates, smtp: Option<&'static str>) -> u16 {
    listener_with(certificates, smtp, rustls::DEFAULT_VERSIONS, "127.0.0.1")
}

/// A TLS listener for `localhost` bound to `address` alone.
pub(crate) fn listener_on(certificates: &Certificates, address: &str) -> u16 {
    listener_with(certificates, None, rustls::DEFAULT_VERSIONS, address)
}

fn listener_with(
    certificates: &Certificates,
    smtp: Option<&'static str>,
    versions: &'static [&'static rustls::SupportedProtocolVersion],
    address: &str,
) -> u16 {
    let (server, key) = (certificates.server.clone(), certificates.key.clone_key());
    let socket = TcpListener::bind((address, 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = socket.accept().unwrap();
        if let Some(answer) = smtp {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            stream
                .write_all(b"220 mail.example.test ESMTP\r\n")
                .unwrap();
            reader.read_line(&mut line).unwrap();
            stream
                .write_all(b"250-mail.example.test\r\n250 STARTTLS\r\n")
                .unwrap();
            reader.read_line(&mut line).unwrap();
            stream.write_all(answer.as_bytes()).unwrap();
            if !answer.starts_with("220") {
                return;
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![server], key)
            .unwrap();
        let mut connection = ServerConnection::new(Arc::new(config)).unwrap();
        while connection.is_handshaking() {
            if connection.complete_io(&mut stream).is_err() {
                return;
            }
        }
        let _ = connection.complete_io(&mut stream);
    });
    port
}

#[test]
fn a_trusted_certificate_is_read() {
    let certificates = certificates();
    let port = listener(&certificates, None);
    let found = probe(
        "localhost",
        port,
        "127.0.0.1",
        false,
        &trusted(&certificates),
        now(),
    )
    .unwrap();
    assert_eq!(found.expires_at, "2036-10-26T00:00:00+00:00");
    assert_eq!(found.protocol, "TLSv1.3");
    // From 2026-10-29T12:00:00Z, the tests' time: 3649 whole days and a half.
    assert_eq!(found.days, 3649);
}

static TLS12_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];

#[test]
fn tls_1_2_is_named_as_such() {
    let certificates = certificates();
    let port = listener_with(&certificates, None, &TLS12_ONLY, "127.0.0.1");
    let found = probe(
        "localhost",
        port,
        "127.0.0.1",
        false,
        &trusted(&certificates),
        now(),
    )
    .unwrap();
    assert_eq!(found.protocol, "TLSv1.2");
}

#[test]
fn io_errors_are_named_for_operators() {
    for (kind, name) in [
        (io::ErrorKind::ConnectionRefused, "connection refused"),
        (io::ErrorKind::ConnectionReset, "connection reset"),
        (io::ErrorKind::TimedOut, "timed out"),
        (io::ErrorKind::WouldBlock, "timed out"),
        (io::ErrorKind::BrokenPipe, "connection failed"),
    ] {
        assert_eq!(failure(&io::Error::from(kind)), Failure(name), "{kind:?}");
    }
}

/// Hands out `chunks` in order, at most one chunk per read, as a socket does.
struct Chunks(std::collections::VecDeque<Vec<u8>>);

impl Read for Chunks {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Some(chunk) = self.0.front_mut() else {
            return Ok(0);
        };
        let count = chunk.len().min(buffer.len());
        buffer[..count].copy_from_slice(&chunk[..count]);
        chunk.drain(..count);
        if chunk.is_empty() {
            self.0.pop_front();
        }
        Ok(count)
    }
}

fn read_reply(chunks: Vec<Vec<u8>>) -> Result<String, Failure> {
    reply(&mut Chunks(chunks.into()))
}

#[test]
fn a_reply_ends_with_its_last_line_up_to_64_kib() {
    let lines = |text: &str| vec![text.as_bytes().to_vec()];
    assert_eq!(
        read_reply([lines("250-first\r\n"), lines("250 last\r\n")].concat()).unwrap(),
        "250 last"
    );
    assert_eq!(
        read_reply(lines("220 rea")),
        Err(Failure("SMTP connection closed"))
    );
    // A continued reply of exactly the limit may still end.
    let mut long = b"250-".to_vec();
    long.resize(MAX_REPLY - 2, b'x');
    long.extend_from_slice(b"\r\n");
    assert_eq!(
        read_reply(vec![long.clone(), b"250 end\r\n".to_vec()]).unwrap(),
        "250 end"
    );
    long.insert(4, b'x');
    assert_eq!(
        read_reply(vec![long, b"250 end\r\n".to_vec()]),
        Err(Failure("SMTP reply too long"))
    );
}

/// The certificate of one endpoint, judged at `now`.
fn judged_at(certificates: &Certificates, now: Timestamp) -> Observation {
    let port = listener(certificates, None);
    let provider = Tls::new(&crate::testing::table(&format!(
        "type = \"tls\"\nendpoints = [{{ host = \"localhost\", port = {port} }}]"
    )))
    .unwrap()
    .with_roots(roots(certificates));
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let runner = crate::testing::Canned(String::new());
    let context = Context {
        now,
        ..crate::testing::context(&config, &runner)
    };
    provider.collect(&context).unwrap().observations.remove(0)
}

/// The observation of one endpoint whose certificate expires `days` days
/// after the tests' time, at midnight.
fn expiring_in(days: i64) -> Observation {
    let expiry = now()
        .checked_add(time::SignedDuration::from_hours(24 * days))
        .unwrap();
    let text = time::isoformat(expiry);
    let date = &text[..10];
    let number = |range: std::ops::Range<usize>| date[range].parse::<u16>().unwrap();
    let year = i32::from(number(0..4));
    let (month, day) = (
        u8::try_from(number(5..7)).unwrap(),
        u8::try_from(number(8..10)).unwrap(),
    );
    judged_at(&certificates_until(year, month, day), now())
}

/// A certificate is judged at the run's time, not at the clock's: one that
/// ran out on 2026-11-13 is valid at the tests' 2026-10-29, and not after.
#[test]
fn a_certificate_is_judged_at_the_time_of_the_run() {
    let certificates = certificates_until(2026, 11, 13);
    let before = judged_at(&certificates, now());
    assert_eq!(before.state, State::Ok, "{:?}", before.findings);
    assert_eq!(before.fields[0].value, json!(14));
    let after = judged_at(&certificates, time::parse("2026-11-13T00:00:01Z").unwrap());
    assert_eq!(after.state, State::Failed);
    assert_eq!(after.findings.len(), 1);
    assert!(
        after.findings[0].ends_with(" — TLS check failed (certificate expired)."),
        "{:?}",
        after.findings
    );
}

#[test]
fn certificates_warn_when_fewer_than_14_days_remain() {
    // A certificate valid until midnight in 15 days has 14 whole days left.
    let calm = expiring_in(15);
    assert_eq!((calm.state, calm.findings.len()), (State::Ok, 0));
    let soon = expiring_in(14);
    assert_eq!(soon.state, State::Warning);
    assert_eq!(soon.findings.len(), 1);
    assert!(
        soon.findings[0].ends_with(" — certificate expires in 13 days."),
        "{:?}",
        soon.findings
    );
}

/// A notification carries a card's first finding: the probe that failed,
/// which makes the card Failed, comes before a certificate that expires
/// soon, whichever endpoint is named first.
#[test]
fn a_failed_probe_is_said_before_a_certificate_that_expires_soon() {
    let soon = certificates_until(2026, 11, 5);
    let port = listener(&soon, None);
    let provider = Tls::new(&crate::testing::table(&format!(
        "type = \"tls\"\nendpoints = [{{ host = \"localhost\", port = {port} }}, \
         {{ host = \"localhost\", port = {CLOSED} }}]"
    )))
    .unwrap()
    .with_roots(roots(&soon));
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let runner = crate::testing::Canned(String::new());
    let card = provider
        .collect(&crate::testing::context(&config, &runner))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(
        (card.state, card.findings),
        (
            State::Failed,
            vec![
                format!("localhost:{CLOSED} — TLS check failed (connection refused)."),
                format!("localhost:{port} — certificate expires in 6 days."),
            ]
        )
    );
}

#[test]
fn starttls_comes_before_the_handshake() {
    let certificates = certificates();
    let port = listener(&certificates, Some("220 2.0.0 Ready to start TLS\r\n"));
    let found = probe(
        "localhost",
        port,
        "127.0.0.1",
        true,
        &trusted(&certificates),
        now(),
    )
    .unwrap();
    assert_eq!(found.protocol, "TLSv1.3");
    let refusing = listener(&certificates, Some("502 5.5.1 Not implemented\r\n"));
    assert_eq!(
        probe(
            "localhost",
            refusing,
            "127.0.0.1",
            true,
            &trusted(&certificates),
            now()
        ),
        Err(Failure("STARTTLS refused"))
    );
}

#[test]
fn untrusted_or_misnamed_certificates_fail_verification() {
    let certificates = certificates();
    let untrusted = listener(&certificates, None);
    let empty = Arc::new(RootCertStore::empty());
    assert_eq!(
        probe("localhost", untrusted, "127.0.0.1", false, &empty, now()),
        Err(Failure("certificate not from a trusted authority"))
    );
    let misnamed = listener(&certificates, None);
    assert_eq!(
        probe(
            "mail.example.test",
            misnamed,
            "127.0.0.1",
            false,
            &trusted(&certificates),
            now()
        ),
        Err(Failure("certificate not valid for this name"))
    );
}

#[test]
fn closed_ports_are_refused_connections() {
    assert_eq!(
        probe(
            "localhost",
            CLOSED,
            "127.0.0.1",
            false,
            &trusted(&certificates()),
            now()
        ),
        Err(Failure("connection refused"))
    );
}

/// Without `endpoints`, Stalwart's listeners are probed under the mail hosts
/// of the first `max_domains` of its domains, and the check names the
/// domains after them.
#[test]
fn the_hosts_of_the_first_max_domains_domains_are_probed_and_the_rest_named() {
    use crate::providers::dns::domains_tests::{LEFT_OUT, twenty_one_domains, with_stalwart};
    use garrison_testing::http::{json as answer_json, serve};

    let listeners = serde_json::json!({"methodResponses": [["x:NetworkListener/get", {"list": [
        {"id": "a", "protocol": "smtp", "bind": {"[::]:9": true}, "useTls": true, "implicitTls": true}
    ]}, "0"]]});
    for (more, probed, named) in [
        ("", vec!["mail.example.test:9"], true),
        (
            "max_domains = 21",
            vec!["mail.example.test:9", "mx2.example.test:9"],
            false,
        ),
    ] {
        let stalwart = serve(vec![
            answer_json(&listeners),
            answer_json(&twenty_one_domains()),
        ]);
        let provider =
            Tls::new(&crate::testing::table(&format!("type = \"tls\"\n{more}"))).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::testing::config(directory.path());
        let runner = crate::testing::Canned(String::new());
        let context = with_stalwart(&mut config, &runner, &stalwart.url);
        let observation = provider.collect(&context).unwrap().observations.remove(0);
        stalwart.requests();
        let rows: Vec<&str> = observation
            .table
            .as_ref()
            .unwrap()
            .rows
            .iter()
            .map(|row| row[0].as_str().unwrap())
            .collect();
        assert_eq!(rows, probed, "{more}");
        assert_eq!(
            observation
                .findings
                .iter()
                .any(|finding| finding == LEFT_OUT),
            named,
            "{more}: {:?}",
            observation.findings
        );
    }
}

/// Stalwart's listeners under each mail host are probed up to 24 endpoints;
/// the card names how many more there are and is not in order for them.
#[test]
fn endpoints_after_the_first_24_are_named_and_keep_the_card_from_being_in_order() {
    use crate::providers::dns::domains_tests::with_stalwart;
    use garrison_testing::http::{json as answer_json, serve};

    let certificates = certificates();
    let ports: Vec<u16> = (0..25).map(|_| listener(&certificates, None)).collect();
    let listed: Vec<Value> = ports
        .iter()
        .map(|port| {
            serde_json::json!({"id": port.to_string(), "protocol": "smtp",
                "bind": {format!("127.0.0.1:{port}"): true}, "useTls": true, "implicitTls": true})
        })
        .collect();
    let stalwart = serve(vec![
        answer_json(
            &serde_json::json!({"methodResponses": [["x:NetworkListener/get", {"list": listed}, "0"]]}),
        ),
        answer_json(&crate::providers::dns::domains_tests::domains_value(
            &serde_json::json!([
                {"id": "b0", "name": "example.test", "dnsZoneFile": "example.test. IN MX 10 localhost.\n"}
            ]),
        )),
    ]);
    let provider = Tls::new(&crate::testing::table("type = \"tls\""))
        .unwrap()
        .with_roots(roots(&certificates));
    let directory = tempfile::tempdir().unwrap();
    let mut config = crate::testing::config(directory.path());
    let runner = crate::testing::Canned(String::new());
    let context = with_stalwart(&mut config, &runner, &stalwart.url);
    let observation = provider.collect(&context).unwrap().observations.remove(0);
    stalwart.requests();
    let results: Vec<&str> = observation
        .table
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .map(|row| row[1].as_str().unwrap())
        .collect();
    assert_eq!(results, ["valid"; 24]);
    assert_eq!(
        observation.findings,
        ["Stalwart's listeners and mail hosts make 25 endpoints; only the first 24 are checked."]
    );
    assert_eq!(observation.state, State::Partial);
}

#[test]
fn the_observation_reports_each_endpoint() {
    let certificates = certificates();
    let good = listener(&certificates, None);
    let bad = CLOSED;
    let provider = Tls::new(&crate::testing::table(&format!(
        "type = \"tls\"\nendpoints = [{{ host = \"localhost\", port = {good} }}, {{ host = \"localhost\", port = {bad} }}]"
    )))
    .unwrap();
    let provider = provider.with_roots(roots(&certificates));
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let runner = crate::testing::Canned(String::new());
    let report = provider
        .collect(&crate::testing::context(&config, &runner))
        .unwrap();
    let observation = &report.observations[0];
    assert_eq!(observation.state, State::Failed);
    assert_eq!(
        observation.findings,
        [format!(
            "localhost:{bad} — TLS check failed (connection refused)."
        )]
    );
    let rows = &observation.table.as_ref().unwrap().rows;
    assert_eq!(
        (rows[0][1].as_str(), rows[1][1].as_str()),
        (Some("valid"), Some("failed"))
    );
    assert!(report.gauges["tls_days"] > 3000.0);
}
