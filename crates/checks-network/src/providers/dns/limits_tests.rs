//! What the dns check leaves out by a limit, it says. An answer is read
//! whole, however many records it holds.

use std::collections::BTreeMap;

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
