//! A name in the options that DNS can never ask is refused, so that
//! check-config names it: a label longer than 63 octets, or a name longer
//! than 253 octets as it is asked, a list's zone with the reversed address
//! before it.

use garrison_core::observations::State;
use garrison_testing::http::{json as answer_json, serve};
use serde_json::json;

use super::tests::{V4, mail_host, rows};
use super::*;
use crate::providers::dns::domains_tests::with_stalwart;
use crate::providers::dns::stand_in::resolver as stand_in;
use crate::testing::{Canned, config, table};

/// The options with `more`; the refusal's words where they are refused.
fn refused(more: &str) -> Option<String> {
    Reputation::new(&table(&format!("type = \"reputation\"\n{more}")))
        .err()
        .map(|error| error.0)
}

/// A name of `octets` octets, of labels no longer than 63.
fn name_of(octets: usize) -> String {
    let mut name = String::new();
    while name.len() + 51 + 5 < octets {
        name.push_str(&"a".repeat(50));
        name.push('.');
    }
    name.push_str(&"b".repeat(octets - name.len() - 5));
    name.push_str(".test");
    assert_eq!(name.len(), octets);
    name
}

#[test]
fn a_label_longer_than_dns_takes_is_refused_and_the_list_named() {
    let label = |octets| format!("{}.zen.spamhaus.org", "k".repeat(octets));
    assert_eq!(refused(&format!("lists = [\"{}\"]", label(63))), None);
    assert_eq!(
        refused(&format!("lists = [\"{}\"]", label(64))),
        Some(format!(
            "providers[reputation].lists names {}, which DNS cannot ask: it has a label of 64 \
             octets, and DNS takes 63 at the most",
            label(64)
        ))
    );
    // A zone of Spamhaus' Data Query Service is named without its key.
    let dqs = format!("{}.zen.dq.spamhaus.net", "k".repeat(64));
    assert_eq!(
        refused(&format!("lists_ipv6 = [\"{dqs}\"]")),
        Some(
            "providers[reputation].lists_ipv6 names ….zen.dq.spamhaus.net, which DNS cannot ask: \
             it has a label of 64 octets, and DNS takes 63 at the most"
                .to_owned()
        )
    );
    let host = format!("{}.example.test", "m".repeat(70));
    assert_eq!(
        refused(&format!("hosts = [\"{host}\"]")),
        Some(format!(
            "providers[reputation].hosts names {host}, which DNS cannot ask: it has a label of 70 \
             octets, and DNS takes 63 at the most"
        ))
    );
}

/// A list's zone is asked with the reversed address before it: up to 16
/// octets for an IPv4 address (`255.255.255.255.`), 64 for an IPv6 address
/// (32 digits, each with a dot). A mail host's name is asked as it is.
#[test]
fn a_name_too_long_to_ask_as_it_is_asked_is_refused_and_named() {
    for (key, longest, before) in [
        (
            "lists",
            237,
            "with an IPv4 address before it, as the list is asked, a question has up to",
        ),
        (
            "lists_ipv6",
            189,
            "with an IPv6 address before it, as the list is asked, a question has",
        ),
        ("hosts", 253, "it has"),
    ] {
        let fits = name_of(longest);
        assert_eq!(refused(&format!("{key} = [\"{fits}\"]")), None, "{key}");
        let long = name_of(longest + 1);
        assert_eq!(
            refused(&format!("{key} = [\"{long}\"]")),
            Some(format!(
                "providers[reputation].{key} names {long}, which DNS cannot ask: {before} 254 \
                 octets, and DNS takes 253 at the most"
            )),
            "{key}"
        );
    }
}

/// Stalwart may name a mail host longer than DNS takes, which the options
/// cannot refuse: no resolver can be asked for its addresses, so it is left
/// out and named, and the hosts beside it are asked.
#[test]
fn a_mail_host_of_stalwarts_that_is_no_dns_name_is_left_out_and_named() {
    let long = name_of(254);
    let zone =
        format!("example.test. IN MX 10 mail.example.test.\nexample.test. IN MX 20 {long}.\n");
    let stalwart = serve(vec![answer_json(&json!({"methodResponses": [[
        "x:Domain/get",
        {"list": [{"id": "b", "name": "example.test", "dnsZoneFile": zone}]},
        "0"
    ]]}))]);
    let (resolver, _) = stand_in(mail_host(), None, 64);
    let provider = Reputation::new(&table(&format!(
        "type = \"reputation\"\nresolver = \"{resolver}\"\nlists = [\"list.example.test\"]\n\
         lists_ipv6 = []"
    )))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let runner = Canned(String::new());
    let context = with_stalwart(&mut config, &runner, &stalwart.url);
    let observations = provider.collect(&context).unwrap().observations;
    stalwart.requests();
    let said = format!("{long} is no DNS name, so it was not asked.");
    for observation in &observations {
        assert!(
            observation.findings.contains(&said),
            "{}: {:?}",
            observation.id,
            observation.findings
        );
    }
    let blocklists = &observations[0];
    assert_eq!(
        blocklists.state,
        State::Partial,
        "{:?}",
        blocklists.findings
    );
    assert!(
        rows(blocklists).iter().any(|row| row.starts_with(V4)),
        "{:?}",
        rows(blocklists)
    );
}

/// What the options take is what the DNS client asks: the longest zone of
/// a list, with the longest address before it, and the longest mail host
/// are names of 255 octets in a question, and one octet more, which the
/// options refuse, is no DNS name to the client either.
#[test]
fn the_longest_names_the_options_take_are_questions_the_client_asks() {
    for (key, longest, before) in [
        ("lists", 237, Some("255.255.255.255")),
        ("lists_ipv6", 189, Some("2001:db8::5")),
        ("hosts", 253, None),
    ] {
        let asked = |name: &str| match before {
            Some(address) => dns::reversed(address.parse().unwrap(), Some(name)),
            None => name.to_owned(),
        };
        let fits = name_of(longest);
        assert_eq!(refused(&format!("{key} = [\"{fits}\"]")), None, "{key}");
        assert!(dns::is_name(&asked(&fits)), "{key}");
        let long = name_of(longest + 1);
        assert!(refused(&format!("{key} = [\"{long}\"]")).is_some(), "{key}");
        assert!(!dns::is_name(&asked(&long)), "{key}");
    }
}
