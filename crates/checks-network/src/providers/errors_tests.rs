//! The rule of an error's words, held over every card that words one of the
//! DNS client's errors: each kind reads as the client says it, after the
//! card's own frame, on its row and in its finding. An error code, an answer
//! that is malformed or cut off, and one cut off over UDP whose question
//! over TCP failed are answers that cannot be used; none reads as no
//! answer, and no answer reads as none of them.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use garrison_core::observations::Observation;
use garrison_testing::http::{json as answer_json, serve};

use super::dns::stand_in::{Fault, host, resolver_faulty, text};
use super::{Dns, Reputation};
use crate::context::{Context, Provider};
use crate::dns::{self, Kind};
use crate::testing::{Canned, config, table};

type Zone = BTreeMap<(String, u16), Vec<Vec<u8>>>;

/// How a question fails: by the stand-in's fault, or by data no resolver
/// can give.
#[derive(Clone, Copy, Debug)]
enum Failure {
    Fault(Fault),
    Malformed,
}

const FAILURES: [Failure; 7] = [
    Failure::Fault(Fault::Silent),
    Failure::Fault(Fault::Code(2)),
    Failure::Fault(Fault::Code(4)),
    Failure::Fault(Fault::Code(5)),
    Failure::Fault(Fault::CutOff),
    Failure::Fault(Fault::Closed),
    Failure::Malformed,
];

/// What the client says of `failure`, asked of `resolver`.
fn words(failure: Failure, resolver: SocketAddr) -> String {
    match failure {
        Failure::Fault(Fault::Silent) => dns::Error::NoAnswer {
            server: resolver,
            why: "no answer within 3 s".to_owned(),
        },
        Failure::Fault(Fault::Code(code)) => dns::Error::Code(code),
        Failure::Fault(Fault::CutOff) => dns::Error::CutOff,
        Failure::Fault(Fault::Closed) => dns::Error::NoTcpAnswer {
            why: "the resolver closed the connection before it answered".to_owned(),
        },
        Failure::Malformed => dns::Error::Malformed,
    }
    .to_string()
}

/// The cards of `provider` where the resolver answers `zone` and fails the
/// question `asked` with `failure`, `malformed` standing in for its answer
/// where it is malformed; Stalwart, at `stalwart`, names the domains.
fn cards(
    provider: impl Fn(SocketAddr) -> Box<dyn Provider>,
    mut zone: Zone,
    asked: (&str, Kind),
    failure: Failure,
    malformed: Vec<u8>,
    stalwart: Option<String>,
) -> (Vec<Observation>, SocketAddr) {
    let question = (asked.0.to_owned(), asked.1.code());
    let faults = match failure {
        Failure::Fault(fault) => BTreeMap::from([(question, fault)]),
        Failure::Malformed => {
            zone.insert(question, vec![malformed]);
            BTreeMap::new()
        }
    };
    let (resolver, stopping) = resolver_faulty(zone, faults);
    let stalwart = stalwart.map(|answer| serve(vec![answer]));
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    if let Some(stalwart) = &stalwart {
        config.deployment.stalwart_url.clone_from(&stalwart.url);
    }
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        ..crate::testing::context(&config, &runner)
    };
    let observations = provider(resolver).collect(&context).unwrap().observations;
    stopping.questions();
    if let Some(stalwart) = stalwart {
        stalwart.requests();
    }
    (observations, resolver)
}

/// The text of the cell `column` of the row of `card` whose first cells
/// are `first`.
fn cell(card: &Observation, first: &[&str], column: usize) -> String {
    let row = card
        .table
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .find(|row| first.iter().zip(row.iter()).all(|(want, got)| got == want))
        .unwrap_or_else(|| panic!("no row {first:?} on {}", card.id));
    row[column].as_str().unwrap_or_default().to_owned()
}

/// What the dns check says of its needed SPF record, for each failure:
/// the row and the finding.
fn dns_card() -> Vec<(String, String)> {
    let zone_file = "example.test. IN MX 10 mail.example.test.\n\
                     example.test. IN TXT \"v=spf1 mx -all\"\n";
    let zone: Zone = BTreeMap::from([
        (
            ("example.test".to_owned(), Kind::Mx.code()),
            vec![host(&[0, 10], "mail.example.test")],
        ),
        (
            ("example.test".to_owned(), Kind::Txt.code()),
            vec![text("v=spf1 mx -all")],
        ),
    ]);
    let stalwart = answer_json(&crate::providers::dns::domains_tests::domains_value(
        &serde_json::json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]),
    ));
    let mut said = Vec::new();
    for failure in FAILURES {
        let dns = |resolver: SocketAddr| -> Box<dyn Provider> {
            Box::new(
                Dns::new(&table(&format!(
                    "type = \"dns\"\nresolver = \"{resolver}\""
                )))
                .unwrap(),
            )
        };
        let (cards, resolver) = cards(
            dns,
            zone.clone(),
            ("example.test", Kind::Txt),
            failure,
            vec![50, b'v'],
            Some(stalwart.clone()),
        );
        let words = words(failure, resolver);
        let row = cell(&cards[0], &["example.test", "TXT"], 5);
        let expected_row = match failure {
            Failure::Fault(Fault::Silent) => "no answer".to_owned(),
            _ => format!("not read: {words}"),
        };
        let finding = format!("TXT example.test could not be read: {words}.");
        said.push((row, expected_row));
        said.push((cards[0].findings.join(" "), finding));
    }
    said
}

const V4: &str = "203.0.113.5";

/// The mail host with its address and reverse name, and the reverse name
/// `relay.example.test` beside, which leads back to it.
fn reputation_zone(reverse: &str) -> Zone {
    let pointer = |name: &str| {
        let mut data = Vec::new();
        for label in name.split('.') {
            data.push(u8::try_from(label.len()).unwrap());
            data.extend_from_slice(label.as_bytes());
        }
        data.push(0);
        data
    };
    let v4 = vec![203, 0, 113, 5];
    BTreeMap::from([
        (
            ("mail.example.test".to_owned(), Kind::A.code()),
            vec![v4.clone()],
        ),
        (("relay.example.test".to_owned(), Kind::A.code()), vec![v4]),
        (
            (dns::reversed(V4.parse().unwrap(), None), Kind::Ptr.code()),
            vec![pointer(reverse)],
        ),
    ])
}

/// A question of the reputation check that fails, and where its words show.
struct Place {
    name: String,
    kind: Kind,
    /// The check's `hosts`.
    hosts: &'static str,
    /// The reverse name of the mail host's address.
    reverse: &'static str,
    /// The data of a malformed answer.
    malformed: Vec<u8>,
    id: &'static str,
    /// The first cells of the row that words it, and its column: none
    /// where no row does.
    row: Vec<&'static str>,
    column: usize,
    row_frame: &'static str,
    finding_frame: String,
}

/// The places of the reputation check where an answer fails.
fn places() -> Vec<Place> {
    let hosts_one = "hosts = [\"mail.example.test\"]";
    vec![
        Place {
            name: dns::reversed(V4.parse().unwrap(), Some("a.example.org")),
            kind: Kind::A,
            hosts: hosts_one,
            reverse: "mail.example.test",
            malformed: vec![127, 0, 2],
            id: "reputation.blocklists",
            row: vec![V4, "a.example.org"],
            column: 2,
            row_frame: "no verdict: ",
            finding_frame: format!("a.example.org gave no verdict for {V4}: "),
        },
        Place {
            name: dns::reversed(V4.parse().unwrap(), None),
            kind: Kind::Ptr,
            hosts: hosts_one,
            reverse: "mail.example.test",
            malformed: vec![5, b'a'],
            id: "reputation.reverse",
            row: vec![V4],
            column: 3,
            row_frame: "not read: ",
            finding_frame: format!("The reverse name of {V4} could not be read: "),
        },
        Place {
            name: "relay.example.test".to_owned(),
            kind: Kind::A,
            hosts: hosts_one,
            reverse: "relay.example.test",
            malformed: vec![192, 0, 2],
            id: "reputation.reverse",
            row: vec![V4],
            column: 3,
            row_frame: "not followed back: ",
            finding_frame: format!(
                "{V4} names relay.example.test; whether that leads back to it could not be read: "
            ),
        },
        Place {
            name: "mx2.example.test".to_owned(),
            kind: Kind::A,
            hosts: "hosts = [\"mail.example.test\", \"mx2.example.test\"]",
            reverse: "mail.example.test",
            malformed: vec![192, 0, 2],
            id: "reputation.blocklists",
            row: Vec::new(),
            column: 0,
            row_frame: "",
            finding_frame: "The IPv4 addresses of mx2.example.test could not be read: ".to_owned(),
        },
    ]
}

/// What the reputation check says at `place` for `failure`: its row and its
/// finding, each against what it should say.
fn said_at(place: &Place, failure: Failure) -> Vec<(String, String)> {
    let options = format!(
        "{}\nlists = [\"a.example.org\", \"b.example.org\"]\nlists_ipv6 = []",
        place.hosts
    );
    let reputation = |resolver: SocketAddr| -> Box<dyn Provider> {
        Box::new(
            Reputation::new(&table(&format!(
                "type = \"reputation\"\nresolver = \"{resolver}\"\n{options}"
            )))
            .unwrap(),
        )
    };
    let (cards, resolver) = cards(
        reputation,
        reputation_zone(place.reverse),
        (&place.name, place.kind),
        failure,
        place.malformed.clone(),
        None,
    );
    let words = words(failure, resolver);
    let card = cards.iter().find(|card| card.id == place.id).unwrap();
    let mut said = Vec::new();
    if !place.row.is_empty() {
        said.push((
            cell(card, &place.row, place.column),
            format!("{}{words}", place.row_frame),
        ));
    }
    // A mail host the resolver did not answer for ends the questions.
    let finding = match failure {
        Failure::Fault(Fault::Silent) if place.name == "mx2.example.test" => {
            format!("Not every address or list was asked: {words}.")
        }
        _ => format!("{}{words}.", place.finding_frame),
    };
    let found = card.findings.iter().find(|said| **said == finding);
    said.push((
        found
            .cloned()
            .unwrap_or_else(|| format!("{:?}", card.findings)),
        finding,
    ));
    said
}

/// What the reputation check says at each place for each failure.
fn reputation_cards() -> Vec<(String, String)> {
    let mut said = Vec::new();
    for place in places() {
        for failure in FAILURES {
            said.extend(said_at(&place, failure));
        }
    }
    said
}

#[test]
fn every_card_words_each_kind_of_error_as_the_client_says_it() {
    let mismatched: Vec<(String, String)> = dns_card()
        .into_iter()
        .chain(reputation_cards())
        .filter(|(got, expected)| !got.contains(expected.as_str()))
        .collect();
    assert_eq!(mismatched, Vec::<(String, String)>::new());
}
