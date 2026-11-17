//! The rule of a card, held over every way a part of the reputation
//! check's cards can end without a verdict: a list that was asked about an
//! address and gave none (an error of the resolver, an answer malformed or
//! cut off, none at all, one a resolver rewrote, one of Spamhaus' errors),
//! that was not asked again after that, or not asked for the run's or the
//! lists' time or for want of a key; a reverse name, or where it leads,
//! that could not be read or was not asked; a mail host whose addresses
//! could not be read, that DNS cannot ask, or that a limit left out; and the
//! resolver, the key and Stalwart's mail hosts that no reading can do
//! without. For each, the card is not OK, and a finding names what was not
//! judged; Stalwart's domains after the first `max_domains` are named, and
//! the cards keep the state of the hosts asked (T-36). A new way that ends
//! OK or says nothing fails here.

use std::time::Duration;

use garrison_core::observations::{Observation, State};
use garrison_testing::http::{answer, json as answer_json, serve};

use super::tests::{V4, V6, Zone, address, listed, mail_host, pointer};
use super::*;
use crate::context::{Deadline, DqsKey};
use crate::providers::dns::domains_tests::twenty_one_domains;
use crate::providers::dns::stand_in::{Fault, resolver_faulty};
use crate::testing::{Canned, config, table};

/// One list for IPv4 addresses and one for IPv6, beside a second IPv4 list
/// that answers, so that what one list did not judge is no card without
/// any verdict.
const LISTS: &str =
    "lists = [\"a.example.org\", \"b.example.org\"]\nlists_ipv6 = [\"a.example.org\"]";

/// The cards of a check with `options` (its `type` added), where the
/// resolver answers `zone` with `faults`, the run has `deadline`, and
/// Stalwart answers `stalwart`.
fn cards(
    options: &str,
    zone: Zone,
    faults: &[((String, u16), Fault)],
    deadline: Deadline,
    stalwart: Vec<String>,
) -> Vec<Observation> {
    run(
        |resolver| provider(resolver, options),
        zone,
        faults,
        deadline,
        stalwart,
    )
}

fn provider(resolver: SocketAddr, options: &str) -> Reputation {
    Reputation::new(&table(&format!(
        "type = \"reputation\"\nresolver = \"{resolver}\"\n{options}"
    )))
    .unwrap()
}

/// The cards of the check `made` for the resolver, as [`cards`] says.
fn run(
    made: impl Fn(SocketAddr) -> Reputation,
    zone: Zone,
    faults: &[((String, u16), Fault)],
    deadline: Deadline,
    stalwart: Vec<String>,
) -> Vec<Observation> {
    let (resolver, stopping) = resolver_faulty(zone, faults.iter().cloned().collect());
    let server = (!stalwart.is_empty()).then(|| serve(stalwart));
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    if let Some(server) = &server {
        config.deployment.stalwart_url.clone_from(&server.url);
    }
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        deadline,
        dqs_key: DqsKey::Unset,
        ..crate::testing::context(&config, &runner)
    };
    let observations = made(resolver).collect(&context).unwrap().observations;
    stopping.questions();
    if let Some(server) = server {
        server.requests();
    }
    observations
}

/// A way of a part to end without a verdict, the card it shows on, and
/// the words a finding of that card must hold to name it.
struct Way {
    what: String,
    cards: Vec<Observation>,
    id: &'static str,
    named: String,
    /// Whether the card keeps the state of what was asked, and only names
    /// what was not.
    named_only: bool,
}

fn way(what: &str, cards: Vec<Observation>, id: &'static str, named: &str) -> Way {
    Way {
        what: what.to_owned(),
        cards,
        id,
        named: named.to_owned(),
        named_only: false,
    }
}

/// The question about `address` that `list` answers.
fn of_list(address: &str, list: &str) -> (String, u16) {
    (
        dns::reversed(address.parse().unwrap(), Some(list)),
        Kind::A.code(),
    )
}

/// The ways of a list to give no verdict about an address.
fn lists() -> Vec<Way> {
    let hosts = "hosts = [\"mail.example.test\"]";
    let options = format!("{hosts}\n{LISTS}");
    let none = Deadline::NONE;
    let mut ways = Vec::new();
    for (what, fault) in [
        ("SERVFAIL", Fault::Code(2)),
        ("NOTIMP", Fault::Code(4)),
        ("REFUSED", Fault::Code(5)),
        ("cut off", Fault::CutOff),
        ("silent", Fault::Silent),
    ] {
        for address in [V4, V6] {
            let faults = [(of_list(address, "a.example.org"), fault)];
            ways.push(way(
                &format!("a list, {what}, {address}"),
                cards(&options, mail_host(), &faults, none, Vec::new()),
                "reputation.blocklists",
                &format!("a.example.org gave no verdict for {address}"),
            ));
        }
    }
    let answered = |code: [u8; 4], list: &str| {
        let mut zone = mail_host();
        listed(&mut zone, V4, list, code);
        zone
    };
    let malformed = {
        let mut zone = mail_host();
        zone.insert(of_list(V4, "a.example.org"), vec![vec![127, 0, 2]]);
        zone
    };
    ways.push(way(
        "a list, malformed",
        cards(&options, malformed, &[], none, Vec::new()),
        "reputation.blocklists",
        "a.example.org gave no verdict for 203.0.113.5",
    ));
    ways.push(way(
        "a list, rewritten",
        cards(
            &options,
            answered([192, 0, 2, 80], "a.example.org"),
            &[],
            none,
            Vec::new(),
        ),
        "reputation.blocklists",
        "a.example.org gave no verdict for 203.0.113.5",
    ));
    ways.extend(codes());
    ways.extend(unasked_lists());
    ways
}

/// The answers of a list that are its own errors: no verdict.
fn codes() -> Vec<Way> {
    let hosts = "hosts = [\"mail.example.test\"]";
    let none = Deadline::NONE;
    let answered = |code: [u8; 4], list: &str| {
        let mut zone = mail_host();
        listed(&mut zone, V4, list, code);
        zone
    };
    let mut ways = Vec::new();
    for code in [252, 254, 255] {
        let spamhaus =
            format!("{hosts}\nlists = [\"zen.spamhaus.org\", \"b.example.org\"]\nlists_ipv6 = []");
        ways.push(way(
            &format!("Spamhaus, 127.255.255.{code}"),
            cards(
                &spamhaus,
                answered([127, 255, 255, code], "zen.spamhaus.org"),
                &[],
                none,
                Vec::new(),
            ),
            "reputation.blocklists",
            "zen.spamhaus.org gave no verdict for 203.0.113.5",
        ));
    }
    let keyed = "abcdefghijklmnopqrstuvwxyz.zen.dq.spamhaus.net";
    for code in [250, 251] {
        let dqs = format!("{hosts}\nlists = [\"{keyed}\", \"b.example.org\"]\nlists_ipv6 = []");
        ways.push(way(
            &format!("the Data Query Service, 127.255.255.{code}"),
            cards(
                &dqs,
                answered([127, 255, 255, code], keyed),
                &[],
                none,
                Vec::new(),
            ),
            "reputation.blocklists",
            "….zen.dq.spamhaus.net gave no verdict for 203.0.113.5",
        ));
    }
    ways
}

/// A list not asked: again after its question got no usable answer, for
/// the lists' time, or without its key.
fn unasked_lists() -> Vec<Way> {
    let hosts = "hosts = [\"mail.example.test\"]";
    let options = format!("{hosts}\n{LISTS}");
    let none = Deadline::NONE;
    let mut ways = Vec::new();
    // The list did not answer about the first address: not asked about the
    // second.
    let mut two = Zone::new();
    address(&mut two, "mail.example.test", V4);
    address(&mut two, "mail.example.test", "203.0.113.6");
    let faults = [(of_list(V4, "a.example.org"), Fault::Code(2))];
    ways.push(way(
        "a list not asked again",
        cards(&format!("{hosts}\n{LISTS}"), two, &faults, none, Vec::new()),
        "reputation.blocklists",
        "a.example.org gave no verdict for 203.0.113.5, 203.0.113.6",
    ));
    let impatient = |resolver| provider(resolver, &options).with_patience(Duration::ZERO);
    ways.push(way(
        "lists not asked for their time",
        run(impatient, mail_host(), &[], none, Vec::new()),
        "reputation.blocklists",
        "Not every list was asked: the lists took too long",
    ));
    let keyless =
        format!("{hosts}\nlists = [\"zen.dq.spamhaus.net\", \"b.example.org\"]\nlists_ipv6 = []");
    ways.push(way(
        "a list without its key",
        cards(&keyless, mail_host(), &[], none, Vec::new()),
        "reputation.blocklists",
        "written without their key were not asked",
    ));
    ways
}

/// The ways of an address's reverse name, and of where it leads, to be
/// read no verdict about.
fn reverse_names() -> Vec<Way> {
    let options = "hosts = [\"mail.example.test\"]\nlists = []\nlists_ipv6 = []";
    let none = Deadline::NONE;
    let ptr = |address: &str| {
        (
            dns::reversed(address.parse().unwrap(), None),
            Kind::Ptr.code(),
        )
    };
    let mut ways = Vec::new();
    for (what, fault) in [
        ("SERVFAIL", Fault::Code(2)),
        ("REFUSED", Fault::Code(5)),
        ("cut off", Fault::CutOff),
        ("silent", Fault::Silent),
    ] {
        ways.push(way(
            &format!("a reverse name, {what}"),
            cards(options, mail_host(), &[(ptr(V4), fault)], none, Vec::new()),
            "reputation.reverse",
            &format!("The reverse name of {V4} could not be read"),
        ));
    }
    // A silent resolver for the first address's reverse name: the next is
    // not asked.
    let mut two = Zone::new();
    address(&mut two, "mail.example.test", V4);
    address(&mut two, "mail.example.test", "203.0.113.6");
    ways.push(way(
        "a reverse name not asked after the resolver was silent",
        cards(options, two, &[(ptr(V4), Fault::Silent)], none, Vec::new()),
        "reputation.reverse",
        "The reverse name of 203.0.113.6 could not be read",
    ));
    // Where a reverse name leads could not be read.
    let mut relay = mail_host();
    pointer(&mut relay, V4, "relay.example.test");
    let back = ("relay.example.test".to_owned(), Kind::A.code());
    ways.push(way(
        "where a reverse name leads, SERVFAIL",
        cards(options, relay, &[(back, Fault::Code(2))], none, Vec::new()),
        "reputation.reverse",
        "whether that leads back to it could not be read",
    ));
    ways
}

/// A scenario: what it is, the cards it makes, what a finding must hold,
/// and whether the cards keep the state of what was asked.
type Scenario = (&'static str, Vec<Observation>, &'static str, bool);

/// The scenarios of a mail host, and of what every reading needs, without
/// a verdict.
fn host_scenarios() -> Vec<Scenario> {
    let none = Deadline::NONE;
    let single = "hosts = [\"mail.example.test\"]\nlists = [\"b.example.org\"]\nlists_ipv6 = []";
    let pair = "hosts = [\"mail.example.test\", \"mx2.example.test\"]\n\
                lists = [\"b.example.org\"]\nlists_ipv6 = []";
    let mx2 = ("mx2.example.test".to_owned(), Kind::A.code());
    let more_hosts: Vec<String> = (1..=9)
        .map(|number| format!("\"mx{number}.example.test\""))
        .collect();
    let mut thirteen = Zone::new();
    for last in 1..=13 {
        address(
            &mut thirteen,
            "mail.example.test",
            &format!("203.0.113.{last}"),
        );
    }
    let long = format!("{}{}.example.test", "a".repeat(60), ".b".repeat(97));
    let with_long = answer_json(&serde_json::json!({"methodResponses": [["x:Domain/get",
        {"list": [{"id": "b", "name": "example.test", "dnsZoneFile": format!(
            "example.test. IN MX 10 mail.example.test.\nexample.test. IN MX 20 {long}.\n"
        )}]}, "0"]]}));
    let of_stalwart = "lists = [\"b.example.org\"]\nlists_ipv6 = []";
    let scenarios = [
        (
            "a mail host's addresses, SERVFAIL",
            cards(
                pair,
                mail_host(),
                &[(mx2.clone(), Fault::Code(2))],
                none,
                Vec::new(),
            ),
            "The IPv4 addresses of mx2.example.test could not be read",
            false,
        ),
        (
            "a mail host the resolver is silent for",
            cards(pair, mail_host(), &[(mx2, Fault::Silent)], none, Vec::new()),
            "Not every address or list was asked: the resolver",
            false,
        ),
        (
            "the run's time",
            cards(
                single,
                mail_host(),
                &[],
                Deadline::within(Duration::ZERO),
                Vec::new(),
            ),
            "the collection run's time was used up",
            false,
        ),
        (
            "the mail hosts after the first eight",
            cards(
                &format!(
                    "hosts = [{}]\nlists = []\nlists_ipv6 = []",
                    more_hosts.join(", ")
                ),
                mail_host(),
                &[],
                none,
                Vec::new(),
            ),
            "only the first 8 are asked",
            false,
        ),
        (
            "the addresses after the first twelve",
            cards(single, thirteen, &[], none, Vec::new()),
            "only the first 12 are asked",
            false,
        ),
        (
            "a mail host that DNS cannot ask",
            cards(of_stalwart, mail_host(), &[], none, vec![with_long]),
            "is no DNS name, so it was not asked",
            false,
        ),
        (
            "Stalwart's domains after the first max_domains",
            cards(
                of_stalwart,
                mail_host(),
                &[],
                none,
                vec![answer_json(&twenty_one_domains())],
            ),
            "only the first 20 are checked",
            true,
        ),
        (
            "Stalwart did not give the mail hosts",
            cards(of_stalwart, mail_host(), &[], none, vec![answer(503, "")]),
            "Nothing could be asked: Stalwart did not complete",
            false,
        ),
    ];
    scenarios.into()
}

/// The ways of a mail host and of what every reading needs: each holds for
/// both cards.
fn hosts() -> Vec<Way> {
    let mut ways = Vec::new();
    for (what, cards, named, named_only) in host_scenarios() {
        for id in ["reputation.blocklists", "reputation.reverse"] {
            ways.push(Way {
                named_only,
                ..way(what, cards.clone(), id, named)
            });
        }
    }
    ways
}

#[test]
fn every_part_without_a_verdict_keeps_its_card_from_ok_and_is_named() {
    let mut broken = Vec::new();
    for way in lists().into_iter().chain(reverse_names()).chain(hosts()) {
        let Some(card) = way.cards.iter().find(|card| card.id == way.id) else {
            broken.push(format!("{}: no card {}", way.what, way.id));
            continue;
        };
        let named = card
            .findings
            .iter()
            .any(|finding| finding.contains(&way.named));
        if (card.state == State::Ok && !way.named_only) || !named {
            broken.push(format!(
                "{} ({}): {:?} {:?}",
                way.what, way.named, card.state, card.findings
            ));
        }
    }
    assert_eq!(broken, Vec::<String>::new());
}
