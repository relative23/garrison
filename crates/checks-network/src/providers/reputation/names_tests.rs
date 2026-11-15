//! A name in the options that DNS can never ask is refused, so that
//! check-config names it: a label longer than 63 octets, or a name longer
//! than 253 octets as it is asked, a list's zone with the reversed address
//! before it.

use super::*;
use crate::testing::table;

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
