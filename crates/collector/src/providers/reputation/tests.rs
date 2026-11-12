use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use crate::providers::dns::tests::resolver as stand_in;
use crate::testing::{Canned, Remembered, config, now, table};

type Zone = BTreeMap<(String, u16), Vec<Vec<u8>>>;

fn address(zone: &mut Zone, name: &str, address: &str) {
    let (kind, data) = match address.parse::<IpAddr>().unwrap() {
        IpAddr::V4(address) => (Kind::A, address.octets().to_vec()),
        IpAddr::V6(address) => (Kind::Aaaa, address.octets().to_vec()),
    };
    zone.entry((name.to_owned(), kind.code()))
        .or_default()
        .push(data);
}

/// A name as DNS writes it: each label with its length, then a zero.
fn pointer(zone: &mut Zone, address: &str, name: &str) {
    let mut data = Vec::new();
    for label in name.split('.') {
        data.push(u8::try_from(label.len()).unwrap());
        data.extend_from_slice(label.as_bytes());
    }
    data.push(0);
    let reverse = dns::reversed(address.parse().unwrap(), None);
    zone.insert((reverse, Kind::Ptr.code()), vec![data]);
}

/// The answer of a list for an address.
fn listed(zone: &mut Zone, address: &str, list: &str, code: [u8; 4]) {
    let name = dns::reversed(address.parse().unwrap(), Some(list));
    zone.insert((name, Kind::A.code()), vec![code.to_vec()]);
}

const V4: &str = "203.0.113.5";
const V6: &str = "2001:db8::5";

/// A mail host with both kinds of address, each with its reverse name.
fn mail_host() -> Zone {
    let mut zone = Zone::new();
    address(&mut zone, "mail.example.test", V4);
    address(&mut zone, "mail.example.test", V6);
    pointer(&mut zone, V4, "mail.example.test");
    pointer(&mut zone, V6, "mail.example.test");
    zone
}

fn provider(resolver: SocketAddr, more: &str) -> Reputation {
    Reputation::new(&table(&format!(
        "type = \"reputation\"\nresolver = \"{resolver}\"\nhosts = [\"mail.example.test\"]\n{more}"
    )))
    .unwrap()
}

/// The two observations `later` seconds after the tests' clock.
fn observed(provider: &Reputation, memory: &Remembered, later: i64) -> (Observation, Observation) {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = Context {
        now: time::Timestamp::from_second(now().as_second() + later).unwrap(),
        memory,
        ..crate::testing::context(&config, &runner)
    };
    let mut observations = provider.collect(&context).unwrap().observations;
    assert_eq!(observations.len(), 2);
    let reverse = observations.remove(1);
    (observations.remove(0), reverse)
}

fn rows(observation: &Observation) -> Vec<String> {
    let table = observation.table.as_ref().unwrap();
    table
        .rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|cell| cell.as_str().unwrap_or("-").to_owned())
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .collect()
}

#[test]
fn a_clean_server_with_fitting_reverse_names_is_in_order() {
    let (resolver, _) = stand_in(mail_host(), None, 64);
    let (blocklists, reverse) = observed(&provider(resolver, ""), &Remembered::default(), 0);
    assert_eq!(
        (blocklists.state, blocklists.findings.len()),
        (State::Ok, 0)
    );
    assert_eq!(blocklists.id, "reputation.blocklists");
    // Four lists for the IPv4 address, the one that lists IPv6 for the other.
    assert_eq!(
        rows(&blocklists),
        [
            "203.0.113.5 | zen.spamhaus.org | not listed",
            "203.0.113.5 | bl.spamcop.net | not listed",
            "203.0.113.5 | psbl.surriel.com | not listed",
            "203.0.113.5 | bl.mailspike.net | not listed",
            "2001:db8::5 | zen.spamhaus.org | not listed",
        ]
    );
    assert_eq!((reverse.state, reverse.findings.len()), (State::Ok, 0));
    assert_eq!(
        rows(&reverse),
        [
            "203.0.113.5 | mail.example.test | mail.example.test | fits",
            "2001:db8::5 | mail.example.test | mail.example.test | fits",
        ]
    );
    assert_eq!(reverse.modules, [ModuleId::DnsTls].into());
}

#[test]
fn a_listing_of_the_ipv6_address_is_a_failure_and_names_the_list() {
    let mut zone = mail_host();
    listed(&mut zone, V6, "zen.spamhaus.org", [127, 0, 0, 2]);
    let (resolver, _) = stand_in(zone, None, 64);
    let (blocklists, _) = observed(&provider(resolver, ""), &Remembered::default(), 0);
    assert_eq!(blocklists.state, State::Failed);
    assert_eq!(
        blocklists.findings,
        ["2001:db8::5 is listed on zen.spamhaus.org (127.0.0.2)."]
    );
    assert_eq!(
        rows(&blocklists)[4],
        "2001:db8::5 | zen.spamhaus.org | listed (127.0.0.2)"
    );
}

#[test]
fn a_list_that_gives_this_resolver_no_verdict_is_no_listing() {
    let mut zone = mail_host();
    listed(&mut zone, V4, "zen.spamhaus.org", [127, 255, 255, 254]);
    let (resolver, _) = stand_in(zone, None, 64);
    let (blocklists, _) = observed(&provider(resolver, ""), &Remembered::default(), 0);
    assert_eq!(
        (blocklists.state, blocklists.findings.len()),
        (State::Ok, 0)
    );
    assert_eq!(
        rows(&blocklists)[0],
        "203.0.113.5 | zen.spamhaus.org | no verdict: the list gives this resolver no verdict; it refuses public resolvers"
    );
    // Where no list gives one, nothing is known.
    let mut zone = mail_host();
    listed(&mut zone, V4, "only.example.org", [127, 255, 255, 254]);
    let (resolver, handle) = stand_in(zone, Some("5.113.0.203.only.example.org"), 64);
    drop(handle);
    let alone = provider(resolver, "lists = [\"only.example.org\"]\nlists_ipv6 = []");
    let (blocklists, _) = observed(&alone, &Remembered::default(), 0);
    assert_eq!(blocklists.state, State::Unknown);
    assert_eq!(blocklists.findings, ["No list gave a verdict."]);
}

#[test]
fn a_list_that_is_down_is_asked_once_and_not_for_every_address() {
    let mut zone = Zone::new();
    for last in 5..9 {
        address(&mut zone, "mail.example.test", &format!("203.0.113.{last}"));
    }
    // The stand-in never answers the first address's question to the list.
    let (resolver, _) = stand_in(zone, Some("5.113.0.203.down.example.org"), 64);
    let provider = provider(
        resolver,
        "lists = [\"down.example.org\", \"up.example.org\"]\nlists_ipv6 = []",
    );
    let began = Instant::now();
    let (blocklists, _) = observed(&provider, &Remembered::default(), 0);
    // One wait for the list, not four.
    assert!(
        began.elapsed() < Duration::from_secs(8),
        "{:?}",
        began.elapsed()
    );
    let rows = rows(&blocklists);
    assert!(
        rows[0].starts_with("203.0.113.5 | down.example.org | no verdict: the resolver "),
        "{}",
        rows[0]
    );
    assert_eq!(
        rows[2],
        "203.0.113.6 | down.example.org | no verdict: the list did not answer before"
    );
    assert_eq!(rows[3], "203.0.113.6 | up.example.org | not listed");
    assert_eq!(blocklists.state, State::Ok);
}

#[test]
fn reverse_names_that_are_missing_or_do_not_fit_are_warnings() {
    let mut zone = Zone::new();
    address(&mut zone, "mail.example.test", V4);
    address(&mut zone, "mail.example.test", V6);
    address(&mut zone, "mail.example.test", "203.0.113.6");
    // One address is named by the provider's default, one by a name that
    // leads elsewhere, one not at all.
    pointer(&mut zone, V4, "host-5.provider.example");
    address(&mut zone, "host-5.provider.example", V4);
    pointer(&mut zone, "203.0.113.6", "other.example.test");
    address(&mut zone, "other.example.test", "198.51.100.1");
    let (resolver, _) = stand_in(zone, None, 64);
    let (_, reverse) = observed(
        &provider(resolver, "lists = []\nlists_ipv6 = []"),
        &Remembered::default(),
        0,
    );
    assert_eq!(reverse.state, State::Warning);
    assert_eq!(
        reverse.findings,
        [
            "203.0.113.5 names host-5.provider.example, which is none of the mail hosts.",
            "203.0.113.6 names other.example.test, which does not lead back to it.",
            "2001:db8::5 has no reverse name.",
        ]
    );
    assert_eq!(
        rows(&reverse)[2],
        "2001:db8::5 | mail.example.test | - | no reverse name"
    );
}

#[test]
fn the_lists_are_asked_every_six_hours_and_a_silent_resolver_is_unknown() {
    let (resolver, _) = stand_in(mail_host(), None, 11);
    let provider = provider(resolver, "");
    let memory = Remembered::default();
    let (first, _) = observed(&provider, &memory, 0);
    // Eleven questions were all the stand-in answers: a second reading would hang.
    let (kept, _) = observed(&provider, &memory, EVERY - 1);
    assert_eq!(rows(&kept), rows(&first));
    assert_eq!(kept.fields[1].value, first.fields[1].value);

    let (resolver, _) = resolver_that_never_answers();
    let silent = Reputation::new(&table(&format!(
        "type = \"reputation\"\nresolver = \"{resolver}\"\nhosts = [\"mail.example.test\"]"
    )))
    .unwrap();
    let memory = Remembered::default();
    let (blocklists, reverse) = observed(&silent, &memory, 0);
    assert_eq!(
        (blocklists.state, reverse.state),
        (State::Unknown, State::Unknown)
    );
    assert!(
        blocklists.findings[0].starts_with("Nothing could be asked: the resolver "),
        "{:?}",
        blocklists.findings
    );
    assert_eq!(blocklists.findings, reverse.findings);
}

/// A socket nobody reads: a question to it gets no answer.
fn resolver_that_never_answers() -> (SocketAddr, std::net::UdpSocket) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    (socket.local_addr().unwrap(), socket)
}

#[test]
fn options_are_checked() {
    let all = Reputation::new(&table("type = \"reputation\"")).unwrap();
    assert_eq!(
        (all.lists.len(), all.lists_ipv6.len(), all.hosts.len()),
        (4, 1, 0)
    );
    for wrong in [
        "hosts = [\"mail example\"]",
        "hosts = \"mail.example.test\"",
        "lists = [\"zen.spamhaus.org\", \"zen.spamhaus.org\"]",
        "lists = [\"localhost\"]",
        "resolver = \"resolver.example\"",
        "list = []",
    ] {
        assert!(
            Reputation::new(&table(&format!("type = \"reputation\"\n{wrong}"))).is_err(),
            "{wrong}"
        );
    }
}

#[test]
fn addresses_are_reversed_for_their_own_tree_and_for_a_list() {
    let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    assert_eq!(dns::reversed(v4, None), "5.113.0.203.in-addr.arpa");
    assert_eq!(
        dns::reversed(v4, Some("zen.spamhaus.org")),
        "5.113.0.203.zen.spamhaus.org"
    );
    let v6: IpAddr = "2001:db8::5".parse::<Ipv6Addr>().unwrap().into();
    assert_eq!(
        dns::reversed(v6, None),
        "5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    );
}
