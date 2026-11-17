//! What the dns check leaves out by a limit, it says: it asks the first 60
//! records Stalwart names for a domain. An answer is read whole, however
//! many records it holds.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::stand_in::{host, resolver, text};
use super::tests::collected;
use super::*;

/// An apex with seventy verification tokens before its SPF policy: the
/// policy is found, as it is where the answer holds it alone.
#[test]
fn a_policy_after_many_other_texts_is_found() {
    let mut texts: Vec<Vec<u8>> = (0..70)
        .map(|number| text(&format!("token-{number}")))
        .collect();
    texts.push(text("v=spf1 mx -all"));
    let zone = BTreeMap::from([
        (
            ("example.test".to_owned(), Kind::Mx.code()),
            vec![host(&[0, 10], "mail.example.test")],
        ),
        (("example.test".to_owned(), Kind::Txt.code()), texts),
    ]);
    let (address, handle) = resolver(zone, None, 2);
    let zone_file = "example.test. IN MX 10 mail.example.test.\n\
                     example.test. IN TXT \"v=spf1 mx -all\"\n";
    let observations = collected(
        &json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]),
        address,
    );
    handle.join().unwrap();
    let domain = &observations[0];
    assert_eq!(
        (domain.state, domain.findings.clone()),
        (State::Ok, Vec::<String>::new())
    );
}

/// Stalwart may name more records for a domain than the check asks, as for
/// many DKIM selectors or TLSA records: the first 60 are asked, and the
/// card says how many there are and is not in order for the others. Every
/// MX record still names a mail host, for the checks that ask about them.
#[test]
fn records_after_the_first_sixty_are_named_and_keep_the_card_from_being_in_order() {
    // Sixty optional records that are not published, then the MX record.
    let mut zone_file = String::new();
    for number in 0..60 {
        writeln!(
            zone_file,
            "s{number}.example.test. IN CNAME mail.example.test."
        )
        .unwrap();
    }
    zone_file.push_str("example.test. IN MX 10 mail.example.test.\n");
    let (address, handle) = resolver(BTreeMap::new(), None, 60);
    let observations = collected(
        &json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]),
        address,
    );
    assert_eq!(handle.join().unwrap().len(), 60);
    let domain = &observations[0];
    assert_eq!(domain.table.as_ref().unwrap().rows.len(), 60);
    assert_eq!(
        (domain.state, domain.findings.clone()),
        (
            State::Partial,
            vec![
                "Stalwart names 61 records for this domain; only the first 60 are asked."
                    .to_owned()
            ]
        )
    );
    assert_eq!(mx_hosts(&expected(&zone_file)), ["mail.example.test"]);
}
