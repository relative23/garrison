//! The rule of a card, held over every way a part of the dns check's cards
//! can end without a verdict: a record not asked for the run's time, cut by
//! the limit of 60, answered with an error, malformed or cut off, not
//! answered, or not asked after the resolver was silent, needed or
//! optional; the MTA-STS policy whose record could not be read, that the
//! run's time left, or that cannot be read; and the domains, the resolver
//! and the key that the card "DNS records" stands in for. For each, the
//! card is not OK, and a finding names what was not checked. A new way that
//! ends OK or says nothing fails here.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use garrison_core::observations::{Observation, State};
use garrison_testing::http::{answer, json as answer_json, serve};

use super::stand_in::{Fault, host, resolver_after, resolver_faulty, text};
use super::*;
use crate::context::Deadline;
use crate::dns::Kind;
use crate::testing::{Canned, config, table};

pub(crate) const NEEDED: &str = "example.test. IN MX 10 mail.example.test.\n\
                      example.test. IN TXT \"v=spf1 mx -all\"\n";
pub(crate) const TLSA: &str = "_25._tcp.mail.example.test. IN TLSA 3 1 1 7B26323DAC\n";
pub(crate) const STS: &str = "_mta-sts.example.test. IN TXT \"v=STSv1; id=1\"\n";

pub(crate) type Zone = BTreeMap<(String, u16), Vec<Vec<u8>>>;

/// Every record of [`NEEDED`], [`TLSA`] and [`STS`] as published.
pub(crate) fn published() -> Zone {
    [
        (
            ("example.test", Kind::Mx),
            vec![host(&[0, 10], "mail.example.test")],
        ),
        (("example.test", Kind::Txt), vec![text("v=spf1 mx -all")]),
        (
            ("_mta-sts.example.test", Kind::Txt),
            vec![text("v=STSv1; id=1")],
        ),
        (
            ("_25._tcp.mail.example.test", Kind::Tlsa),
            vec![vec![3, 1, 1, 0x7b, 0x26, 0x32, 0x3d, 0xac]],
        ),
    ]
    .into_iter()
    .map(|((name, kind), records)| ((name.to_owned(), kind.code()), records))
    .collect()
}

/// The cards of the check for the domain whose zone file is `zone_file`,
/// where the resolver answers `answers` with `faults`, a policy is served
/// with `policy`, and the run has `deadline`.
pub(crate) fn cards(
    zone_file: &str,
    answers: Zone,
    faults: &[(&str, Kind, Fault)],
    policy: Option<String>,
    deadline: Deadline,
) -> Vec<Observation> {
    let faults = faults
        .iter()
        .map(|(name, kind, fault)| (((*name).to_owned(), kind.code()), *fault))
        .collect();
    let (address, stopping) = resolver_faulty(answers, faults);
    let observations = collect(zone_file, address, policy, deadline);
    stopping.questions();
    observations
}

/// The check's cards against Stalwart naming one domain with `zone_file`,
/// the resolver at `address`.
fn collect(
    zone_file: &str,
    address: SocketAddr,
    policy: Option<String>,
    deadline: Deadline,
) -> Vec<Observation> {
    let stalwart = serve(vec![answer_json(
        &json!({"methodResponses": [["x:Domain/get",
        {"list": [{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]}, "0"]]}),
    )]);
    let served = policy.map(|policy| serve(vec![policy]));
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&stalwart.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        deadline,
        ..crate::testing::context(&config, &runner)
    };
    let provider = Dns {
        policy_url: served
            .as_ref()
            .map(|served| format!("{}/.well-known/mta-sts.txt", served.url)),
        ..Dns::new(&table(&format!("type = \"dns\"\nresolver = \"{address}\""))).unwrap()
    };
    let observations = provider.collect(&context).unwrap().observations;
    stalwart.requests();
    if let Some(served) = served {
        served.requests();
    }
    observations
}

/// A way of a part to end without a verdict, the card it shows on, and
/// the words a finding of that card must hold to name it.
struct Way {
    what: &'static str,
    cards: Vec<Observation>,
    id: &'static str,
    named: &'static str,
}

/// The ways of each record, needed and optional, to be asked and get
/// nothing usable.
fn unusable() -> Vec<Way> {
    let malformed = |name: &str, kind: Kind| {
        let mut answers = published();
        // A text that claims 50 octets and holds one; TLSA data of one octet.
        let data = if kind == Kind::Txt {
            vec![50, b'v']
        } else {
            vec![3]
        };
        answers.insert((name.to_owned(), kind.code()), vec![data]);
        answers
    };
    let mut ways = Vec::new();
    for (name, kind, zone_file, named) in [
        (
            "example.test",
            Kind::Txt,
            NEEDED.to_owned(),
            "TXT example.test",
        ),
        (
            "_25._tcp.mail.example.test",
            Kind::Tlsa,
            format!("{NEEDED}{TLSA}"),
            "TLSA _25._tcp.mail.example.test",
        ),
        (
            "_mta-sts.example.test",
            Kind::Txt,
            format!("{NEEDED}{STS}"),
            "Its MTA-STS policy was not checked",
        ),
    ] {
        let none = Deadline::NONE;
        for (what, fault) in [
            ("SERVFAIL", Fault::Code(2)),
            ("NOTIMP", Fault::Code(4)),
            ("REFUSED", Fault::Code(5)),
            ("cut off", Fault::CutOff),
            ("silent", Fault::Silent),
        ] {
            ways.push(Way {
                what,
                cards: cards(&zone_file, published(), &[(name, kind, fault)], None, none),
                id: "dns.example.test",
                named,
            });
        }
        ways.push(Way {
            what: "malformed",
            cards: cards(&zone_file, malformed(name, kind), &[], None, none),
            id: "dns.example.test",
            named,
        });
    }
    // The resolver was silent for the MX record: the SPF record after it
    // is not asked.
    ways.push(Way {
        what: "not asked after the resolver was silent",
        cards: cards(
            NEEDED,
            published(),
            &[("example.test", Kind::Mx, Fault::Silent)],
            None,
            Deadline::NONE,
        ),
        id: "dns.example.test",
        named: "TXT example.test",
    });
    ways
}

/// The ways of the records, the policy, the domains, the resolver and the
/// key that are not a question that got nothing usable.
fn others() -> Vec<Way> {
    let none = Deadline::NONE;
    let mut sixty = String::new();
    for number in 0..60 {
        writeln!(sixty, "s{number}.example.test. IN CNAME mail.example.test.").unwrap();
    }
    let long_name = format!("{}.example.test", "a.".repeat(125));
    let leaves_out = "version: STSv1\nmode: enforce\nmx: other.example.test\nmax_age: 86400\n";
    vec![
        Way {
            what: "not asked for the run's time",
            cards: cards(
                NEEDED,
                published(),
                &[],
                None,
                Deadline::within(Duration::ZERO),
            ),
            id: "dns.example.test",
            named: "Not asked: the collection run's time was used up",
        },
        Way {
            what: "after the first 60",
            cards: cards(&format!("{sixty}{NEEDED}"), published(), &[], None, none),
            id: "dns.example.test",
            named: "only the first 60 are asked",
        },
        Way {
            what: "a needed record whose name is no DNS name",
            cards: cards(
                &format!("{NEEDED}{long_name}._domainkey.example.test. IN TXT \"v=DKIM1; p=A\"\n"),
                published(),
                &[],
                None,
                none,
            ),
            id: "dns.example.test",
            named: "is no DNS name",
        },
        Way {
            what: "a policy that cannot be read",
            cards: cards(
                &format!("{NEEDED}{STS}"),
                published(),
                &[],
                Some(answer(404, "")),
                none,
            ),
            id: "dns.example.test",
            named: "its policy could not be read",
        },
        Way {
            what: "a policy that leaves a mail host out",
            cards: cards(
                &format!("{NEEDED}{STS}"),
                published(),
                &[],
                Some(answer(200, leaves_out)),
                none,
            ),
            id: "dns.example.test",
            named: "does not name mail.example.test",
        },
        Way {
            what: "a policy that the run's time left",
            cards: policy_left_by_the_run(),
            id: "dns.example.test",
            named: "Its MTA-STS policy was not fetched",
        },
        Way {
            what: "a domain that Stalwart names no records for",
            cards: cards("", published(), &[], None, none),
            id: "dns.example.test",
            named: "Stalwart names no records for this domain",
        },
    ]
}

/// The run's time ends after the record for the policy was answered: its
/// policy is not fetched.
fn policy_left_by_the_run() -> Vec<Observation> {
    let (address, handle) = resolver_after(published(), None, 2, Duration::from_millis(1200));
    // Each answer comes 1.2 s after its question, the second after the
    // run's two seconds.
    let zone_file = format!("example.test. IN MX 10 mail.example.test.\n{STS}");
    let observations = collect(
        &zone_file,
        address,
        None,
        Deadline::within(Duration::from_secs(2)),
    );
    handle.join().unwrap();
    observations
}

/// The ways of the card "DNS records", which stands in where the domains,
/// the resolver or the key are not known, and for the domains after the
/// first `max_domains`.
fn stand_ins() -> Vec<Way> {
    let id = "dns.records";
    let three: Vec<serde_json::Value> = (0..3)
        .map(
            |number| json!({"id": format!("b{number}"), "name": format!("d{number}.example.test")}),
        )
        .collect();
    let domains = |list: serde_json::Value| {
        answer_json(&json!({"methodResponses": [["x:Domain/get", {"list": list}, "0"]]}))
    };
    let directory = tempfile::tempdir().unwrap();
    let resolv_conf = directory.path().join("resolv.conf");
    std::fs::write(&resolv_conf, "search example.test\n").unwrap();
    let run = |provider: &Dns, answers: Vec<String>, key: bool| {
        let stalwart = (!answers.is_empty()).then(|| serve(answers));
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        if let Some(stalwart) = &stalwart {
            config.deployment.stalwart_url.clone_from(&stalwart.url);
        }
        let runner = Canned(String::new());
        let context = Context {
            native_key: key.then(|| "key".to_owned()),
            ..crate::testing::context(&config, &runner)
        };
        let observations = provider.collect(&context).unwrap().observations;
        if let Some(stalwart) = stalwart {
            stalwart.requests();
        }
        observations
    };
    let plain = Dns::new(&table("type = \"dns\"\nresolver = \"127.0.0.1:9\"")).unwrap();
    let two = Dns::new(&table(
        "type = \"dns\"\nresolver = \"127.0.0.1:9\"\nmax_domains = 2",
    ))
    .unwrap();
    let no_resolver = Dns::new(&table("type = \"dns\""))
        .unwrap()
        .with_resolv_conf(&resolv_conf);
    vec![
        Way {
            what: "the domains after the first max_domains",
            cards: run(&two, vec![domains(json!(three))], true),
            id,
            named: "only the first 2 are checked",
        },
        Way {
            what: "no resolver",
            cards: run(
                &no_resolver,
                vec![domains(json!([{"id": "b", "name": "example.test"}]))],
                true,
            ),
            id,
            named: "names no resolver",
        },
        Way {
            what: "no key",
            cards: run(&plain, Vec::new(), false),
            id,
            named: "the collector has no API key",
        },
        Way {
            what: "Stalwart failed the request",
            cards: run(&plain, vec![answer(503, "")], true),
            id,
            named: "Stalwart did not complete",
        },
    ]
}

#[test]
fn every_part_without_a_verdict_keeps_its_card_from_ok_and_is_named() {
    let mut broken = Vec::new();
    for way in unusable().into_iter().chain(others()).chain(stand_ins()) {
        let Some(card) = way.cards.iter().find(|card| card.id == way.id) else {
            broken.push(format!("{}: no card {}", way.what, way.id));
            continue;
        };
        let named = card
            .findings
            .iter()
            .any(|finding| finding.contains(way.named));
        if card.state == State::Ok || !named {
            broken.push(format!(
                "{} ({}): {:?} {:?}",
                way.what, way.named, card.state, card.findings
            ));
        }
    }
    assert_eq!(broken, Vec::<String>::new());
}
