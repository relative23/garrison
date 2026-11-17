//! An answer the dns check cannot use, an error code of the resolver or an
//! answer that is malformed or cut off, is named as what it is, on its row
//! and in a finding, and keeps the card from being in order: a needed
//! record that could not be read leaves it Unknown, an optional one, such
//! as a TLSA record or the record of an MTA-STS policy, Partial where it
//! would be OK. A policy whose record could not be read is not checked, and
//! the card says so.

use std::collections::BTreeMap;

use super::stand_in::{Fault, host, resolver_faulty, text};
use super::tests::collected_with;
use super::*;
use crate::dns::Kind;

/// The needed records of a domain, its MX and SPF records, as Stalwart
/// names them, and beside them a TLSA record and the record for an MTA-STS
/// policy.
const NEEDED: &str = "example.test. IN MX 10 mail.example.test.\n\
                      example.test. IN TXT \"v=spf1 mx -all\"\n";
const OPTIONAL: &str = "_mta-sts.example.test. IN TXT \"v=STSv1; id=1\"\n\
                        _25._tcp.mail.example.test. IN TLSA 3 1 1 7B26323DAC\n";

/// Every record as published.
fn published() -> BTreeMap<(String, u16), Vec<Vec<u8>>> {
    [
        (
            ("example.test", Kind::Mx),
            vec![host(&[0, 10], "mail.example.test")],
        ),
        (("example.test", Kind::Txt), vec![text("v=spf1 mx -all")]),
        (
            ("_mta-sts.example.test", Kind::Txt),
            vec![text("v=STSv1; id=1")],
        ),
        (
            ("_25._tcp.mail.example.test", Kind::Tlsa),
            vec![vec![3, 1, 1, 0x7b, 0x26, 0x32, 0x3d, 0xac]],
        ),
    ]
    .into_iter()
    .map(|((name, kind), records)| ((name.to_owned(), kind.code()), records))
    .collect()
}

/// The card of the domain whose zone file is `zone_file`, where the
/// resolver answers `answers` and gives `faults`, and a policy is served
/// with `policy` where one is fetched.
fn card(
    zone_file: &str,
    answers: BTreeMap<(String, u16), Vec<Vec<u8>>>,
    faults: &[(&str, Kind, Fault)],
    policy: Option<&str>,
) -> Observation {
    let faults = faults
        .iter()
        .map(|(name, kind, fault)| (((*name).to_owned(), kind.code()), *fault))
        .collect();
    let (address, stopping) = resolver_faulty(answers, faults);
    let served = policy.map(|policy| {
        garrison_testing::http::serve(vec![garrison_testing::http::answer(200, policy)])
    });
    let observations = collected_with(
        &json!([{"id": "b", "name": "example.test", "dnsZoneFile": zone_file}]),
        address,
        served
            .as_ref()
            .map(|served| format!("{}/.well-known/mta-sts.txt", served.url)),
    );
    stopping.questions();
    if let Some(served) = served {
        served.requests();
    }
    observations.into_iter().next().unwrap()
}

fn results(card: &Observation) -> Vec<String> {
    card.table
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .map(|row| row[5].as_str().unwrap().to_owned())
        .collect()
}

/// Each kind of answer that cannot be used is named in its own words, as
/// the client gives them: not as no answer.
#[test]
fn a_needed_record_that_cannot_be_read_is_named_with_why() {
    let malformed = {
        let mut answers = published();
        // A text that claims 50 octets and holds one.
        answers.insert(
            ("example.test".to_owned(), Kind::Txt.code()),
            vec![vec![50, b'v']],
        );
        answers
    };
    for (answers, fault, words) in [
        (
            published(),
            Some(Fault::Code(2)),
            "the resolver could not answer (SERVFAIL)",
        ),
        (
            published(),
            Some(Fault::Code(5)),
            "the resolver refused the question",
        ),
        (
            published(),
            Some(Fault::Code(4)),
            "the resolver answered with error 4",
        ),
        (
            published(),
            Some(Fault::CutOff),
            "the resolver's answer is cut off",
        ),
        (malformed, None, "the resolver's answer is malformed"),
    ] {
        let faults: Vec<(&str, Kind, Fault)> = fault
            .map(|fault| ("example.test", Kind::Txt, fault))
            .into_iter()
            .collect();
        let domain = card(NEEDED, answers, &faults, None);
        assert_eq!(
            results(&domain),
            ["published".to_owned(), format!("not read: {words}")],
            "{words}"
        );
        assert_eq!(
            (domain.state, domain.findings.clone()),
            (
                State::Unknown,
                vec![format!("TXT example.test could not be read: {words}.")]
            ),
            "{words}"
        );
    }
}

/// A TLSA record and the record for an MTA-STS policy are a matter of
/// choice, but one that cannot be read is not known to be in order: the
/// card is Partial, names both, and says that the policy was not checked.
#[test]
fn an_optional_record_that_cannot_be_read_keeps_the_card_from_being_in_order() {
    let servfail = Fault::Code(2);
    let domain = card(
        &format!("{NEEDED}{OPTIONAL}"),
        published(),
        &[
            ("_mta-sts.example.test", Kind::Txt, servfail),
            ("_25._tcp.mail.example.test", Kind::Tlsa, servfail),
        ],
        None,
    );
    let words = "the resolver could not answer (SERVFAIL)";
    assert_eq!(
        results(&domain),
        [
            "published".to_owned(),
            "published".to_owned(),
            format!("not read: {words}"),
            format!("not read: {words}"),
        ]
    );
    assert_eq!(
        (domain.state, domain.findings.clone()),
        (
            State::Partial,
            vec![
                format!(
                    "TXT _mta-sts.example.test, TLSA _25._tcp.mail.example.test could not be \
                     read: {words}."
                ),
                "Its MTA-STS policy was not checked, since the record for it could not be read."
                    .to_owned(),
            ]
        )
    );
}

/// A resolver that does not answer an optional record's question leaves
/// that record unread as well, and is asked nothing more in the run.
#[test]
fn an_optional_record_the_resolver_does_not_answer_keeps_the_card_from_being_in_order() {
    let tlsa = "_25._tcp.mail.example.test. IN TLSA 3 1 1 7B26323DAC\n";
    let (address, stopping) = resolver_faulty(
        published(),
        BTreeMap::from([(
            ("_25._tcp.mail.example.test".to_owned(), Kind::Tlsa.code()),
            Fault::Silent,
        )]),
    );
    let observations = collected_with(
        &json!([{"id": "b", "name": "example.test", "dnsZoneFile": format!("{NEEDED}{tlsa}")}]),
        address,
        None,
    );
    assert_eq!(stopping.questions().len(), 3);
    let domain = &observations[0];
    assert_eq!(results(domain), ["published", "published", "no answer"]);
    assert_eq!(
        (domain.state, domain.findings.clone()),
        (
            State::Partial,
            vec![format!(
                "TLSA _25._tcp.mail.example.test could not be read: the resolver {address} did \
                 not answer: no answer within 3 s."
            )]
        )
    );
}
