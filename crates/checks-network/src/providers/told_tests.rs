//! The rule of a card that is told. A notification carries a card's title
//! and its first finding, so a card that is a warning or failed says first
//! what made it so. Held over every card the checks of this crate report:
//! each way a card is told, beside what else it says; a card that is never
//! told is named with why. A card of these checks that is in neither list
//! fails here. (A policy beside records the run's time left is held by
//! `dns/sts_tests.rs`, which needs a run that ends between two answers.)

use std::collections::BTreeSet;
use std::fmt::Write as _;

use garrison_core::observations::{Observation, State};
use garrison_testing::http::answer;
use serde_json::json;

use super::dns::rule_tests::{NEEDED, STS, TLSA, cards, published};
use super::dns::stand_in::{Fault, host};
use super::tls::tests::{CLOSED, listener, roots};
use super::{Dns, Reputation, Tls};
use crate::context::{Context, Deadline, Provider};
use crate::dns::Kind;
use crate::testing::{Canned, Remembered, certificates, certificates_until, config, now, table};

/// A way of a card to be told: the card, and the words its first finding
/// holds where it names what made the card's state.
struct Told {
    what: &'static str,
    card: Observation,
    cause: &'static str,
}

/// The card `id` among `cards`.
fn the(cards: Vec<Observation>, id: &str) -> Observation {
    cards
        .into_iter()
        .find(|card| card.id == id)
        .unwrap_or_else(|| panic!("no card {id}"))
}

/// The ways of a domain's DNS card: a record not as Stalwart names it, and
/// an MTA-STS policy that stops senders beside what keeps the card from
/// being in order otherwise.
fn domain() -> Vec<Told> {
    let id = "dns.example.test";
    let none = Deadline::NONE;
    let leaves_out = || {
        answer(
            200,
            "version: STSv1\nmode: enforce\nmx: other.example.test\nmax_age: 86400\n",
        )
    };
    let servfail = Fault::Code(2);
    let mut other_host = published();
    other_host.insert(
        ("example.test".to_owned(), Kind::Mx.code()),
        vec![host(&[0, 10], "other.example.test")],
    );
    let mut sixty = String::new();
    for number in 0..60 {
        writeln!(sixty, "s{number}.example.test. IN CNAME mail.example.test.").unwrap();
    }
    let long_name = format!("{}example.test", "a.".repeat(125));
    let not_named = "The MTA-STS policy of example.test does not name mail.example.test";
    let told = |what, cards: Vec<Observation>, cause| Told {
        what,
        card: the(cards, id),
        cause,
    };
    vec![
        told(
            "a mail host not as Stalwart names it, beside an unread TLSA record and a policy",
            cards(
                &format!("{NEEDED}{STS}{TLSA}"),
                other_host,
                &[("_25._tcp.mail.example.test", Kind::Tlsa, servfail)],
                Some(leaves_out()),
                none,
            ),
            "Not as Stalwart names them: MX example.test",
        ),
        told(
            "a policy that leaves the mail host out, beside an unread SPF record",
            cards(
                &format!("{NEEDED}{STS}"),
                published(),
                &[("example.test", Kind::Txt, servfail)],
                Some(leaves_out()),
                none,
            ),
            not_named,
        ),
        told(
            "a policy that cannot be read, beside an unread TLSA record",
            cards(
                &format!("{NEEDED}{STS}{TLSA}"),
                published(),
                &[("_25._tcp.mail.example.test", Kind::Tlsa, servfail)],
                Some(answer(404, "")),
                none,
            ),
            "its policy could not be read",
        ),
        told(
            "a policy that leaves the mail host out, beside the records after the first 60",
            cards(
                &format!("{NEEDED}{STS}{sixty}"),
                published(),
                &[],
                Some(leaves_out()),
                none,
            ),
            not_named,
        ),
        told(
            "a policy that leaves the mail host out, beside a record that is no DNS name",
            cards(
                &format!("{NEEDED}{STS}{long_name}. IN TLSA 3 1 1 7B26323DAC\n"),
                published(),
                &[],
                Some(leaves_out()),
                none,
            ),
            not_named,
        ),
    ]
}

/// The card of the TLS check for `endpoints`, whose certificates come from
/// `certificates`' authority.
fn tls(endpoints: &[u16], certificates: &crate::testing::Certificates) -> Observation {
    let listed: Vec<String> = endpoints
        .iter()
        .map(|port| format!("{{ host = \"localhost\", port = {port} }}"))
        .collect();
    let provider = Tls::new(&table(&format!(
        "type = \"tls\"\nendpoints = [{}]",
        listed.join(", ")
    )))
    .unwrap()
    .with_roots(roots(certificates));
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    the(
        provider
            .collect(&crate::testing::context(&config, &runner))
            .unwrap()
            .observations,
        "tls.endpoints",
    )
}

/// The ways of the TLS card: a probe that failed after a certificate that
/// expires soon, and such a certificate beside one in order.
fn endpoints() -> Vec<Told> {
    let soon = certificates_until(2026, 11, 5);
    let lasting = certificates();
    vec![
        Told {
            what: "a probe that failed after a certificate that expires soon",
            card: tls(&[listener(&soon, None), CLOSED], &soon),
            cause: "TLS check failed (connection refused)",
        },
        Told {
            what: "a certificate that expires soon",
            card: tls(&[listener(&soon, None)], &soon),
            cause: "certificate expires in 6 days",
        },
        Told {
            what: "a probe that failed beside a certificate in order",
            card: tls(&[listener(&lasting, None), CLOSED], &lasting),
            cause: "TLS check failed (connection refused)",
        },
    ]
}

/// The ways of the reputation cards, from one reading kept a minute ago
/// that holds everything a reading can say beside a listing and an address
/// without a reverse name.
fn reputation() -> Vec<Told> {
    let options = "type = \"reputation\"\nresolver = \"127.0.0.1:9\"\n\
                   hosts = [\"mail.example.test\"]\n\
                   lists = [\"a.example.org\", \"b.example.org\"]\n\
                   lists_ipv6 = [\"a.example.org\"]";
    let servfail = "the resolver could not answer (SERVFAIL)";
    let reading = json!({
        "at": now().as_second() - 60,
        "hosts": ["mail.example.test", "mx2.example.test"],
        "addresses": [
            {"host": "mail.example.test", "address": "203.0.113.5", "pointer": null,
             "confirmed": false,
             "lists": [["a.example.org", {"Listed": "127.0.0.2"}],
                       ["b.example.org", {"Unanswered": servfail}]]},
            {"host": "mail.example.test", "address": "2001:db8::5",
             "pointer": "mail.example.test", "confirmed": true, "unread": servfail,
             "lists": [["a.example.org", {"Unasked": "the lists took too long"}]]},
        ],
        "problem": null,
        "rest": "Stalwart has 21 domains; only the first 20 are checked (`max_domains`).",
        "cut": "the collection run's time was used up",
        "left_out": ["There are 9 mail hosts; only the first 8 are asked."],
        "keyless": "collector.dqs_key is not set",
        "hosts_unread": [format!("The IPv6 addresses of mx2.example.test could not be read: {servfail}.")],
        "lists_unasked": true,
        "made": {"resolver": "127.0.0.1:9", "hosts": ["mail.example.test"], "max_domains": null,
                 "lists": ["a.example.org", "b.example.org"], "lists_ipv6": ["a.example.org"]},
    });
    let memory = Remembered::default();
    memory
        .0
        .borrow_mut()
        .insert("reputation.read".to_owned(), reading.to_string());
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = Context {
        memory: &memory,
        ..crate::testing::context(&config, &runner)
    };
    let cards = Reputation::new(&table(options))
        .unwrap()
        .collect(&context)
        .unwrap()
        .observations;
    vec![
        Told {
            what: "a listing beside all a reading can leave unjudged",
            card: the(cards.clone(), "reputation.blocklists"),
            cause: "203.0.113.5 is listed on a.example.org",
        },
        Told {
            what: "an address without a reverse name beside one that could not be read",
            card: the(cards, "reputation.reverse"),
            cause: "203.0.113.5 has no reverse name",
        },
    ]
}

/// The cards of these checks that are never a warning or failed, and why.
const NEVER_TOLD: [(&str, &str); 1] = [(
    "dns.records",
    "it stands in where the domains, the resolver or the key are not known, and for the \
     domains after the first max_domains: Unknown only",
)];

#[test]
fn every_card_that_is_told_says_first_what_made_it_so() {
    let mut broken = Vec::new();
    let mut covered: BTreeSet<String> = NEVER_TOLD.iter().map(|(id, _)| (*id).to_owned()).collect();
    for way in domain().into_iter().chain(endpoints()).chain(reputation()) {
        covered.insert(way.card.id.clone());
        let told = matches!(way.card.state, State::Warning | State::Failed);
        let first = way.card.findings.first().map_or("", String::as_str);
        if !told || !first.contains(way.cause) {
            broken.push(format!(
                "{}: {:?} {:?}",
                way.what, way.card.state, way.card.findings
            ));
        }
    }
    assert_eq!(broken, Vec::<String>::new());
    // Every card of the checks is in one list or the other; a domain's card
    // stands for each domain's.
    let none = table("type = \"dns\"");
    let mut ids: BTreeSet<String> = [
        Dns::new(&none).unwrap().ids(),
        Reputation::new(&table("type = \"reputation\""))
            .unwrap()
            .ids(),
        Tls::new(&table("type = \"tls\"")).unwrap().ids(),
    ]
    .concat()
    .into_iter()
    .collect();
    ids.insert("dns.example.test".to_owned());
    assert_eq!(covered, ids);
}
