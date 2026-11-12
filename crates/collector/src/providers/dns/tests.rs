use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::thread;

use garrison_testing::http::{json as answer_json, serve};

use super::*;
use crate::context::Context;
use crate::testing::{Canned, config, table};

/// What Stalwart writes for a domain, shortened.
const ZONE: &str = r#"v1-ed25519._domainkey.example.test. IN TXT "v=DKIM1; k=ed25519; h=sha256; p=AAAAkey"
v1-rsa._domainkey.example.test. IN TXT (
    "v=DKIM1; k=rsa; h=sha256; p=MIIBpart1"
    "part2QIDAQAB"
)
_25._tcp.mail.example.test. IN TLSA 3 1 1 7B26323DAC
mail.example.test. IN TXT "v=spf1 a -all"
example.test. IN TXT "v=spf1 mx -all"
example.test. IN MX 10 mail.example.test.
_dmarc.example.test. IN TXT "v=DMARC1; p=reject; rua=mailto:postmaster@example.test"
_imaps._tcp.example.test. IN SRV 0 1 993 mail.example.test.
autoconfig.example.test. IN CNAME mail.example.test.
example.test. IN NS ns1.example.net.
not a record
"#;

#[test]
fn a_zone_file_is_read_record_by_record() {
    let records = expected(ZONE);
    let listed: Vec<(&str, &str, &str)> = records
        .iter()
        .map(|record| {
            (
                record.name.as_str(),
                record.kind.name(),
                record.value.as_str(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            (
                "v1-ed25519._domainkey.example.test",
                "TXT",
                "v=DKIM1; k=ed25519; h=sha256; p=AAAAkey"
            ),
            // The pieces of a long key are one text.
            (
                "v1-rsa._domainkey.example.test",
                "TXT",
                "v=DKIM1; k=rsa; h=sha256; p=MIIBpart1part2QIDAQAB"
            ),
            ("_25._tcp.mail.example.test", "TLSA", "3 1 1 7b26323dac"),
            ("mail.example.test", "TXT", "v=spf1 a -all"),
            ("example.test", "TXT", "v=spf1 mx -all"),
            ("example.test", "MX", "10 mail.example.test"),
            (
                "_dmarc.example.test",
                "TXT",
                "v=DMARC1; p=reject; rua=mailto:postmaster@example.test"
            ),
            (
                "_imaps._tcp.example.test",
                "SRV",
                "0 1 993 mail.example.test"
            ),
            ("autoconfig.example.test", "CNAME", "mail.example.test"),
        ]
    );
    let needed: Vec<bool> = records
        .iter()
        .map(|record| needed("example.test", record))
        .collect();
    assert_eq!(
        needed,
        [true, true, false, false, true, true, true, false, false]
    );
    assert_eq!(expected(""), []);
}

#[test]
fn what_is_found_is_held_against_what_stalwart_names() {
    let records = expected(ZONE);
    let of = |name: &str, kind: Kind| {
        records
            .iter()
            .find(|record| record.name == name && record.kind == kind)
            .unwrap()
    };
    let found =
        |texts: &[&str]| -> Vec<String> { texts.iter().map(|text| (*text).to_owned()).collect() };
    let mx = of("example.test", Kind::Mx);
    // Another preference is the operator's choice; another host is not.
    assert_eq!(
        verdict(mx, &found(&["5 MAIL.example.test"])),
        Verdict::Published
    );
    assert_eq!(
        verdict(mx, &found(&["10 mx.filter.example"])),
        Verdict::Differs
    );
    assert_eq!(verdict(mx, &[]), Verdict::Missing);
    let spf = of("example.test", Kind::Txt);
    assert_eq!(
        verdict(spf, &found(&["other=1", "v=spf1 mx -all"])),
        Verdict::Published
    );
    assert_eq!(
        verdict(spf, &found(&["v=spf1 mx include:_spf.example.net -all"])),
        Verdict::Differs
    );
    assert_eq!(
        verdict(spf, &found(&["google-site-verification=x"])),
        Verdict::Missing
    );
    // A DKIM record is the same if its key is, however it is spaced.
    let dkim = of("v1-rsa._domainkey.example.test", Kind::Txt);
    assert_eq!(
        verdict(dkim, &found(&["v=DKIM1; k=rsa; p=MIIBpart1part2QIDAQAB"])),
        Verdict::Published
    );
    assert_eq!(
        verdict(dkim, &found(&["v=DKIM1; k=rsa; p=OTHER"])),
        Verdict::Differs
    );
    let tlsa = of("_25._tcp.mail.example.test", Kind::Tlsa);
    assert_eq!(
        verdict(tlsa, &found(&["3 1 1 7b26323dac"])),
        Verdict::Published
    );
    assert_eq!(verdict(tlsa, &found(&["3 1 1 00"])), Verdict::Differs);
}

/// A resolver on a free port that answers from `zone`: `(name, type)` to texts.
/// Names it does not hold do not exist; `silent` is never answered.
pub(crate) fn resolver(
    zone: BTreeMap<(String, u16), Vec<Vec<u8>>>,
    silent: Option<&'static str>,
    questions: usize,
) -> (SocketAddr, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let handle = thread::spawn(move || {
        for _ in 0..questions {
            let mut buffer = [0; 512];
            let (length, client) = socket.recv_from(&mut buffer).unwrap();
            let question = &buffer[..length];
            // The name: labels from byte 12 to the zero.
            let mut name = Vec::new();
            let mut at = 12;
            while question[at] != 0 {
                let size = usize::from(question[at]);
                name.push(String::from_utf8_lossy(&question[at + 1..at + 1 + size]).into_owned());
                at += 1 + size;
            }
            let name = name.join(".");
            if Some(name.as_str()) == silent {
                continue;
            }
            let kind = u16::from_be_bytes([question[at + 1], question[at + 2]]);
            let mut message = question.to_vec();
            message[2] = 0x81;
            match zone.get(&(name, kind)) {
                Some(records) => {
                    message[3] = 0x80;
                    message[7] = u8::try_from(records.len()).unwrap();
                    for data in records {
                        message.extend_from_slice(&[0xc0, 12]);
                        message.extend_from_slice(&kind.to_be_bytes());
                        message.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                        message
                            .extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
                        message.extend_from_slice(data);
                    }
                }
                None => message[3] = 0x83,
            }
            socket.send_to(&message, client).unwrap();
        }
    });
    (address, handle)
}

fn text(value: &str) -> Vec<u8> {
    let mut data = vec![u8::try_from(value.len()).unwrap()];
    data.extend_from_slice(value.as_bytes());
    data
}

fn host(prefix: &[u8], name: &str) -> Vec<u8> {
    let mut data = prefix.to_vec();
    for label in name.split('.') {
        data.push(u8::try_from(label.len()).unwrap());
        data.extend_from_slice(label.as_bytes());
    }
    data.push(0);
    data
}

/// The provider's observations for Stalwart answering `domains` and a
/// resolver at `address`.
fn collected(domains: &serde_json::Value, address: SocketAddr) -> Vec<Observation> {
    collected_with(domains, address, None)
}

/// Like [`collected`], with an MTA-STS policy served at `policy`.
fn collected_with(
    domains: &serde_json::Value,
    address: SocketAddr,
    policy: Option<String>,
) -> Vec<Observation> {
    let stalwart = serve(vec![answer_json(&json!({
        "methodResponses": [["x:Domain/get", {"list": domains}, "0"]]
    }))]);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&stalwart.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        ..crate::testing::context(&config, &runner)
    };
    let provider = Dns {
        policy_url: policy,
        ..Dns::new(&table(&format!("type = \"dns\"\nresolver = \"{address}\""))).unwrap()
    };
    let report = provider.collect(&context).unwrap();
    stalwart.requests();
    report.observations
}

/// A domain that publishes a TLSA record and the record for an MTA-STS policy.
const TRANSPORT: &str = r#"example.test. IN MX 10 mail.example.test.
example.test. IN TXT "v=spf1 mx -all"
_mta-sts.example.test. IN TXT "v=STSv1; id=1"
_25._tcp.mail.example.test. IN TLSA 3 1 1 7B26323DAC
"#;

fn transport(tlsa: &[u8], policy: &str) -> Observation {
    let zone: BTreeMap<(String, u16), Vec<Vec<u8>>> = [
        (
            ("example.test", 15),
            vec![host(&[0, 10], "mail.example.test")],
        ),
        (("example.test", 16), vec![text("v=spf1 mx -all")]),
        (("_mta-sts.example.test", 16), vec![text("v=STSv1; id=1")]),
        (("_25._tcp.mail.example.test", 52), vec![tlsa.to_vec()]),
    ]
    .into_iter()
    .map(|((name, kind), records)| ((name.to_owned(), kind), records))
    .collect();
    let (address, handle) = resolver(zone, None, 4);
    let served = serve(vec![garrison_testing::http::answer(200, policy)]);
    let mut observations = collected_with(
        &json!([{"id": "b", "name": "example.test", "dnsZoneFile": TRANSPORT}]),
        address,
        Some(format!("{}/.well-known/mta-sts.txt", served.url)),
    );
    handle.join().unwrap();
    served.requests();
    observations.remove(0)
}

#[test]
fn a_wrong_tlsa_record_and_a_policy_that_leaves_the_mail_host_out_are_warnings() {
    let domain = transport(
        &[3, 1, 1, 0x00, 0x11],
        "version: STSv1\nmode: enforce\nmx: other.example.test\nmax_age: 86400\n",
    );
    assert_eq!(domain.state, State::Warning);
    assert_eq!(
        domain.findings,
        [
            "Not as Stalwart names them: TLSA _25._tcp.mail.example.test.",
            "A published TLSA record that is not the one of Stalwart's certificate makes senders \
             that check DANE refuse this server.",
            "The MTA-STS policy of example.test does not name mail.example.test: senders that \
             honour it do not deliver there.",
        ]
    );
    let rows = &domain.table.as_ref().unwrap().rows;
    assert_eq!(
        rows.last().unwrap(),
        json!([
            "mta-sts.example.test",
            "policy",
            "optional",
            "mx mail.example.test",
            "mode enforce; mx other.example.test; max_age 86400",
            "leaves a mail host out"
        ])
        .as_array()
        .unwrap()
    );
}

#[test]
fn the_tlsa_record_of_the_certificate_and_a_policy_that_names_the_mail_host_are_in_order() {
    let domain = transport(
        &[3, 1, 1, 0x7b, 0x26, 0x32, 0x3d, 0xac],
        "version: STSv1\r\nmode: enforce\r\nmx: mail.example.test\r\nmax_age: 86400\r\n",
    );
    assert_eq!(domain.state, State::Ok, "{:?}", domain.findings);
    assert_eq!(
        domain.table.as_ref().unwrap().rows.last().unwrap()[5],
        "fits"
    );
}

#[test]
fn a_domain_with_its_records_is_in_order_and_one_without_is_a_warning() {
    let zone: BTreeMap<(String, u16), Vec<Vec<u8>>> = [
        (
            ("v1-ed25519._domainkey.example.test", 16),
            vec![text("v=DKIM1; k=ed25519; h=sha256; p=AAAAkey")],
        ),
        (
            ("v1-rsa._domainkey.example.test", 16),
            vec![text("v=DKIM1; k=rsa; h=sha256; p=MIIBpart1part2QIDAQAB")],
        ),
        (("mail.example.test", 16), vec![text("v=spf1 a -all")]),
        // An SPF policy of the operator's own, and a mail host as named.
        (
            ("example.test", 16),
            vec![text("v=spf1 mx include:_spf.example.net -all")],
        ),
        (
            ("example.test", 15),
            vec![host(&[0, 20], "mail.example.test")],
        ),
        (
            ("_dmarc.example.test", 16),
            vec![text(
                "v=DMARC1; p=reject; rua=mailto:postmaster@example.test",
            )],
        ),
    ]
    .into_iter()
    .map(|((name, kind), records)| ((name.to_owned(), kind), records))
    .collect();
    let (address, handle) = resolver(zone, None, 9);
    let observations = collected(
        &json!([{"id": "b", "name": "Example.Test", "dnsZoneFile": ZONE}]),
        address,
    );
    handle.join().unwrap();
    let domain = &observations[0];
    assert_eq!(
        (domain.id.as_str(), domain.title.as_str()),
        ("dns.example.test", "DNS records of example.test")
    );
    assert_eq!(domain.state, State::Ok, "{:?}", domain.findings);
    let rows = &domain.table.as_ref().unwrap().rows;
    let results: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|row| {
            (
                row[1].as_str().unwrap(),
                row[2].as_str().unwrap(),
                row[5].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        results,
        [
            ("TXT", "needed", "published"),
            ("TXT", "needed", "published"),
            ("TLSA", "optional", "missing"),
            ("TXT", "optional", "published"),
            ("TXT", "needed", "differs"),
            ("MX", "needed", "published"),
            ("TXT", "needed", "published"),
            ("SRV", "optional", "missing"),
            ("CNAME", "optional", "missing"),
        ]
    );
    assert_eq!(rows[5][4], "20 mail.example.test");

    // Nothing published: every needed record is named.
    let (address, handle) = resolver(BTreeMap::new(), None, 9);
    let observations = collected(
        &json!([{"id": "b", "name": "example.test", "dnsZoneFile": ZONE}]),
        address,
    );
    handle.join().unwrap();
    assert_eq!(observations[0].state, State::Warning);
    assert_eq!(
        observations[0].findings,
        [
            "Not as Stalwart names them: TXT v1-ed25519._domainkey.example.test, \
          TXT v1-rsa._domainkey.example.test, TXT example.test, MX example.test, \
          TXT _dmarc.example.test."
        ]
    );
}

#[test]
fn a_resolver_that_does_not_answer_and_a_stalwart_that_gives_no_domains_are_unknown() {
    let zone = "example.test. IN MX 10 mail.example.test.\n";
    let (address, handle) = resolver(BTreeMap::new(), Some("example.test"), 1);
    let observations = collected(
        &json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone}]),
        address,
    );
    handle.join().unwrap();
    assert_eq!(observations[0].state, State::Unknown);
    assert_eq!(
        observations[0].findings,
        ["The resolver gave no answer for 1 of the needed records."]
    );
    // A domain Stalwart names no records for, and no domain at all.
    let silent = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let none = collected(&json!([{"id": "b", "name": "example.test"}]), silent);
    assert_eq!(
        none[0].findings,
        ["Stalwart names no records for this domain."]
    );
    let empty = collected(&json!([]), silent);
    assert_eq!(
        (empty[0].id.as_str(), empty[0].state),
        ("dns.records", State::Unknown)
    );
    // Without a key, and with a key that may not read domains.
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let provider = Dns::new(&table("type = \"dns\"")).unwrap();
    let keyless = provider
        .collect(&crate::testing::context(&config, &runner))
        .unwrap();
    assert_eq!(
        keyless.observations[0].findings,
        ["No API key is configured."]
    );
    let refused = Context {
        native_key: Some("key".into()),
        ..crate::testing::context(&config, &runner)
    };
    let denied = provider.collect(&refused).unwrap();
    assert!(denied.observations[0].findings[0].contains("garrison stalwart setup"));
}

#[test]
fn options_are_checked() {
    assert_eq!(
        Dns::new(&table("type = \"dns\"\nresolver = \"192.0.2.53\""))
            .unwrap()
            .resolver,
        Some("192.0.2.53:53".parse().unwrap())
    );
    for wrong in [
        "resolver = \"dns.example\"",
        "resolver = 53",
        "max_domains = 0",
        "zone = \"x\"",
    ] {
        assert!(
            Dns::new(&table(&format!("type = \"dns\"\n{wrong}"))).is_err(),
            "{wrong}"
        );
    }
}
