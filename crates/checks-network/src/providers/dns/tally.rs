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
    /// The records the resolver gave nothing usable for: each, why, and
    /// whether mail depends on it.
    pub(super) unread: Vec<(String, String, bool)>,
    /// The records not asked, as the run's time for its checks was over.
    pub(super) unasked: usize,
    /// What is said of the records whose name is no DNS name.
    pub(super) nameless: Vec<String>,
    /// Whether the record for the domain's MTA-STS policy could not be
    /// read, so that the policy was not checked.
    pub(super) policy_unread: bool,
}

impl Tally {
    /// What the verdict on `record` of the domain `name` adds, with why the
    /// resolver gave nothing usable where it did not.
    pub(super) fn counted(
        &mut self,
        name: &str,
        record: &Expected,
        verdict: Verdict,
        why: Option<&str>,
    ) {
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
            // Not known to be in order, optional as it may be.
            Verdict::Unanswered | Verdict::Unread => {
                let label = format!("{} {}", record.kind.name(), record.name);
                self.unread
                    .push((label, why.unwrap_or_default().to_owned(), needed));
                self.policy_unread |=
                    record.kind == Kind::Txt && record.name == format!("_mta-sts.{name}");
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
    }

    /// What is said of the records the resolver gave nothing usable for:
    /// those of one reason together, in the reason's words.
    fn unread_said(&self) -> Vec<String> {
        let mut reasons: Vec<(&str, Vec<&str>)> = Vec::new();
        for (record, why, _) in &self.unread {
            match reasons.iter_mut().find(|(known, _)| known == why) {
                Some((_, records)) => records.push(record),
                None => reasons.push((why, vec![record])),
            }
        }
        reasons
            .into_iter()
            .map(|(why, records)| format!("{} could not be read: {why}.", records.join(", ")))
            .collect()
    }
}

/// The state of a domain and what to say of it: the records that are not as
/// Stalwart names them, those that could not be read or were not asked,
/// then what the MTA-STS policy leaves open. What was asked and answered
/// counts; what was not keeps the domain from being in order, optional as
/// it may be: Unknown for a needed record, Partial for an optional one. A
/// policy that stops senders is a warning beside either, and where it makes
/// the warning it is said first, as a notification carries a card's first
/// finding. A record whose name is no DNS name can never be published, so a
/// needed one is not as Stalwart names it.
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
    } else if tally.unread.iter().any(|(_, _, needed)| *needed) || tally.unasked == tally.records {
        (State::Unknown, Vec::new())
    } else if tally.unasked > 0 || tally.left > 0 || !tally.unread.is_empty() {
        (State::Partial, Vec::new())
    } else {
        (State::Ok, Vec::new())
    };
    findings.extend(tally.unread_said());
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
    if tally.policy_unread {
        findings.push(
            "Its MTA-STS policy was not checked, since the record for it could not be read."
                .to_owned(),
        );
    }
    match policy {
        sts::Outcome::Fits => {}
        sts::Outcome::Finding(finding) => {
            // Senders that honour the policy stop, whatever else could not
            // be read or asked.
            if state == State::Warning {
                findings.push(finding);
            } else {
                state = State::Warning;
                findings.insert(0, finding);
            }
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
