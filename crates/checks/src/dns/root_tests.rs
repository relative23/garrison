//! A record whose name is the root, which has no label, reads as `.`, the
//! way a zone file writes it, and never as no name at all: a reverse name
//! or a CNAME that names the root, a null MX (RFC 7505), an SRV record of a
//! service that is not offered (RFC 2782).

use super::tests::{FINE, asked};
use super::*;

#[test]
fn a_record_that_names_the_root_reads_as_a_dot() {
    let read: Vec<(Kind, Result<Option<Answer>, Error>)> = [
        (Kind::Ptr, vec![0]),
        (Kind::Cname, vec![0]),
        (Kind::Mx, vec![0, 0, 0]),
        (Kind::Srv, vec![0, 0, 0, 0, 0, 0, 0]),
    ]
    .into_iter()
    .map(|(kind, data)| (kind, asked(kind, FINE, &[(kind.code(), data)])))
    .collect();
    let written = |text: &str| Ok(Some(Answer::Records(vec![text.to_owned()])));
    assert_eq!(
        read,
        [
            (Kind::Ptr, written(".")),
            (Kind::Cname, written(".")),
            (Kind::Mx, written("0 .")),
            (Kind::Srv, written("0 0 0 .")),
        ]
    );
}
