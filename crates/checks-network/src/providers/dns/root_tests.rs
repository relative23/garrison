//! A record the resolver answers that names the root is shown as `.`, as a
//! zone file writes it, and not as nothing: a null MX, which says that the
//! domain takes no mail, and an SRV record of a service that is not
//! offered.

use std::collections::BTreeMap;

use super::stand_in::resolver;
use super::tests::collected;
use super::*;
use crate::dns::Kind;

#[test]
fn a_record_that_names_the_root_is_shown_as_a_dot() {
    let zone_file = "example.test. IN MX 10 mail.example.test.\n\
                     _imaps._tcp.example.test. IN SRV 0 1 993 mail.example.test.\n";
    let published = BTreeMap::from([
        (
            ("example.test".to_owned(), Kind::Mx.code()),
            vec![vec![0, 0, 0]],
        ),
        (
            ("_imaps._tcp.example.test".to_owned(), Kind::Srv.code()),
            vec![vec![0, 0, 0, 0, 0, 0, 0]],
        ),
    ]);
    let (address, handle) = resolver(published, None, 2);
    let observations = collected(
        &json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]),
        address,
    );
    assert_eq!(handle.join().unwrap().len(), 2);
    let domain = &observations[0];
    let shown: Vec<Vec<&str>> = domain
        .table
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .map(|row| {
            [&row[1], &row[4], &row[5]]
                .map(|cell| cell.as_str().unwrap())
                .to_vec()
        })
        .collect();
    assert_eq!(
        shown,
        [["MX", "0 .", "differs"], ["SRV", "0 0 0 .", "differs"]]
    );
    // A null MX is no mail host of Stalwart's.
    assert_eq!(
        (domain.state, domain.findings.clone()),
        (
            State::Warning,
            vec!["Not as Stalwart names them: MX example.test.".to_owned()]
        )
    );
}
