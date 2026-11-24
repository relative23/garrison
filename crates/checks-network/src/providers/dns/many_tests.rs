//! Stalwart's domains as many as it has: the checks read the first
//! `max_domains` of them, with their zone files, and count the rest, so
//! that neither the number of domains nor the size of their zone files
//! makes a request too large for them. Stalwart gives a request for all of
//! its domains the first 500 alone (measured on 1.1.0).

use garrison_core::observations::State;
use serde_json::{Value, json};

use super::*;
use crate::testing::objects::objects;
use crate::testing::{Canned, config, table};

/// `count` domains, each with `zone` as its zone file.
fn domains(count: usize, zone: impl Fn(&str) -> String) -> Vec<Value> {
    (0..count)
        .map(|number| {
            let name = format!("d{number}.example.test");
            json!({"id": format!("b{number}"), "name": name, "dnsZoneFile": zone(&name)})
        })
        .collect()
}

/// The mail hosts the other checks take, and what they say of the rest.
type Hosts = Result<(Vec<String>, Option<String>), String>;

/// The dns check's cards, and the mail hosts the other checks take, where
/// Stalwart has `domains`.
fn read(domains: Vec<Value>) -> (Vec<Observation>, Hosts) {
    let stalwart = objects("Domain", domains);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&stalwart.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        ..crate::testing::context(&config, &runner)
    };
    // Port 9 takes no questions: the resolver is asked once and no more.
    let provider = Dns::new(&table("type = \"dns\"\nresolver = \"127.0.0.1:9\"")).unwrap();
    let cards = provider.collect(&context).unwrap().observations;
    let hosts = mail_hosts(&context, 20, "");
    stalwart.requests();
    (cards, hosts)
}

#[test]
fn domains_beyond_the_500_of_one_request_are_counted() {
    let (cards, hosts) = read(domains(600, |name| {
        format!("{name}. IN MX 10 mail.{name}.\n")
    }));
    let left_out = "Stalwart has 600 domains; only the first 20 are checked (`max_domains`).";
    assert_eq!(cards.len(), 21);
    assert_eq!(
        (cards[20].id.as_str(), cards[20].findings.clone()),
        ("dns.records", vec![left_out.to_owned()])
    );
    let (hosts, rest) = hosts.unwrap();
    assert_eq!((hosts.len(), rest.as_deref()), (20, Some(left_out)));
}

#[test]
fn zone_files_of_more_than_a_mebibyte_in_all_are_read() {
    // 300 zone files of some 4 KB: 1.2 MB together, 80 KB for the first 20.
    let long = "a".repeat(4000);
    let (cards, hosts) = read(domains(300, |name| {
        format!("{name}. IN MX 10 mail.{name}.\n{name}. IN TXT \"{long}\"\n")
    }));
    let ids: Vec<&str> = cards.iter().map(|card| card.id.as_str()).collect();
    assert_eq!(ids.len(), 21, "{:?}", cards[0].findings);
    assert_eq!(ids[0], "dns.d0.example.test");
    assert_eq!(cards[0].state, State::Unknown);
    assert_eq!(
        cards[20].findings,
        ["Stalwart has 300 domains; only the first 20 are checked (`max_domains`)."]
    );
    assert_eq!(hosts.unwrap().0.len(), 20);
}
