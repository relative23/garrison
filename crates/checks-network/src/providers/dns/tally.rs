//! What the questions about a domain's records came to, and the state of
//! its card and what the card says from that.

use garrison_core::observations::State;

use super::zone::{Expected, Verdict, needed};
use super::{MOST_RECORDS, RUN_OVER, sts};
use crate::dns::{self, Kind};

/// What the questions about a domain's records came to.
#[derive(Debug, Default)]
pub(super) struct Tally {
    /// The records Stalwart names for the domain that are asked.
    pub(super) records: usize,
    /// The records it names after the first [`MOST_RECORDS`], not asked.
    pub(super) left: usize,
    /// The records that are not as Stalwart names them.
    pub(super) open: Vec<String>,
    /// The needed records the resolver gave no answer for.
    pub(super) unanswered: usize,
    /// The records not asked, as the run's time for its checks was over.
    pub(super) unasked: usize,
    /// What is said of the records whose name is no DNS name.
    pub(super) nameless: Vec<String>,
}

impl Tally {
    /// What the verdict on `record` of the domain `name` adds, and whether
    /// the record is not as Stalwart names it.
    pub(super) fn counted(&mut self, name: &str, record: &Expected, verdict: Verdict) -> bool {
        let needed = needed(name, record);
        let counts = match verdict {
            Verdict::Missing => needed,
            // An SPF or DMARC policy of the operator's own is in order;
            // another DKIM key or mail host is not what Stalwart uses.
            Verdict::Differs => {
                // A TLSA record is a matter of choice, but one that is
                // published and wrong makes senders that check DANE refuse.
                record.kind == Kind::Tlsa
                    || needed && (record.kind == Kind::Mx || record.name.contains("._domainkey."))
            }
            Verdict::Unanswered => {
                self.unanswered += usize::from(needed);
                false
            }
            Verdict::Unasked => {
                self.unasked += 1;
                false
            }
            Verdict::NoName => {
                self.nameless.push(format!(
                    "{}, so its {} record was not asked.",
                    dns::no_name(&record.name),
                    record.kind.name()
                ));
                needed
            }
            Verdict::Published => false,
        };
        if counts {
            self.open
                .push(format!("{} {}", record.kind.name(), record.name));
        }
        counts
    }
}

/// The state of a domain and what to say of it: the records that are not as
/// Stalwart names them, those that were not asked, then what the MTA-STS
/// policy leaves open. What was asked counts; what was not keeps the domain
/// from being in order. A record whose name is no DNS name can never be
/// published, so a needed one is not as Stalwart names it.
pub(super) fn summed(tally: &Tally, policy: sts::Outcome) -> (State, Vec<String>) {
    let (mut state, mut findings) = if tally.records == 0 {
        (
            State::Unknown,
            vec!["Stalwart names no records for this domain.".to_owned()],
        )
    } else if !tally.open.is_empty() {
        (
            State::Warning,
            vec![format!(
                "Not as Stalwart names them: {}.",
                tally.open.join(", ")
            )],
        )
    } else if tally.unanswered > 0 {
        (
            State::Unknown,
            vec![format!(
                "The resolver gave no answer for {} of the needed records.",
                tally.unanswered
            )],
        )
    } else if tally.unasked == tally.records {
        (State::Unknown, Vec::new())
    } else if tally.unasked > 0 || tally.left > 0 {
        (State::Partial, Vec::new())
    } else {
        (State::Ok, Vec::new())
    };
    findings.extend(tally.nameless.iter().cloned());
    if tally.unasked > 0 && tally.unasked == tally.records {
        findings.push(format!("Not asked: {RUN_OVER}."));
    } else if tally.unasked > 0 {
        findings.push(format!(
            "{} of its {} records {} not asked: {RUN_OVER}.",
            tally.unasked,
            tally.records,
            if tally.unasked == 1 { "was" } else { "were" }
        ));
    }
    if tally.left > 0 {
        findings.push(format!(
            "Stalwart names {} records for this domain; only the first {MOST_RECORDS} are asked.",
            tally.records + tally.left
        ));
    }
    if tally.open.iter().any(|record| record.starts_with("TLSA ")) {
        findings.push(
            "A published TLSA record that is not the one of Stalwart's certificate makes \
             senders that check DANE refuse this server."
                .to_owned(),
        );
    }
    match policy {
        sts::Outcome::Fits => {}
        sts::Outcome::Finding(finding) => {
            if state == State::Ok {
                state = State::Warning;
            }
            findings.push(finding);
        }
        sts::Outcome::Unasked => {
            if state == State::Ok {
                state = State::Partial;
            }
            findings.push(format!("Its MTA-STS policy was not fetched: {RUN_OVER}."));
        }
    }
    (state, findings)
}
