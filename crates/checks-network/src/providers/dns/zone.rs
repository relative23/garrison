//! The records Stalwart names for a domain, read from the zone file it
//! writes, and how what a resolver answers stands to each of them.

use crate::dns::Kind;

/// The most records of one domain that are read.
const MOST_RECORDS: usize = 60;

/// One record Stalwart names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Expected {
    pub(super) name: String,
    pub(super) kind: Kind,
    pub(super) value: String,
}

pub(super) fn plain(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// The records of a zone file as Stalwart writes it: `name IN TYPE data`,
/// where a long text stands in brackets over several lines.
pub(super) fn expected(zone: &str) -> Vec<Expected> {
    let mut entries: Vec<String> = Vec::new();
    let mut open = false;
    for line in zone.lines() {
        if open {
            if let Some(last) = entries.last_mut() {
                last.push(' ');
                last.push_str(line.trim());
            }
        } else {
            entries.push(line.trim().to_owned());
        }
        // Brackets inside a quoted text do not occur in what Stalwart writes.
        open = (open || line.contains('(')) && !line.contains(')');
    }
    let mut records = Vec::new();
    for entry in entries {
        let mut words = entry.splitn(4, char::is_whitespace);
        let (Some(name), Some("IN"), Some(kind), Some(data)) =
            (words.next(), words.next(), words.next(), words.next())
        else {
            continue;
        };
        let Some(kind) = Kind::named(kind) else {
            continue;
        };
        let value = match kind {
            // The quoted pieces of a text, joined as a resolver joins them.
            Kind::Txt => data.split('"').skip(1).step_by(2).collect::<String>(),
            Kind::Mx | Kind::Srv | Kind::Cname | Kind::Ptr => plain(data.trim()),
            Kind::Tlsa => data.trim().to_ascii_lowercase(),
            Kind::A | Kind::Aaaa => data.trim().to_owned(),
        };
        if !value.is_empty() && records.len() < MOST_RECORDS {
            records.push(Expected {
                name: plain(name),
                kind,
                value,
            });
        }
    }
    records
}

/// The targets of the MX records among `records`.
pub(super) fn mx_hosts(records: &[Expected]) -> Vec<String> {
    records
        .iter()
        .filter(|record| record.kind == Kind::Mx)
        .filter_map(|record| {
            record
                .value
                .split_whitespace()
                .nth(1)
                .map(str::to_lowercase)
        })
        .collect()
}

/// Whether mail for `domain` depends on the record.
pub(super) fn needed(domain: &str, record: &Expected) -> bool {
    match record.kind {
        Kind::Mx => true,
        Kind::Txt => {
            (record.name == domain && record.value.starts_with("v=spf1"))
                || record.name.contains("._domainkey.")
                || record.name.starts_with("_dmarc.")
        }
        _ => false,
    }
}

/// The part of a DKIM record that must be the same: its key.
fn key(text: &str) -> Option<String> {
    text.split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("p="))
        .map(|key| key.split_whitespace().collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    Published,
    /// Another record of the same purpose is published.
    Differs,
    Missing,
    /// The resolver gave no answer.
    Unanswered,
}

impl Verdict {
    pub(super) fn label(self) -> &'static str {
        match self {
            Verdict::Published => "published",
            Verdict::Differs => "differs",
            Verdict::Missing => "missing",
            Verdict::Unanswered => "no answer",
        }
    }
}

/// How what was found stands to the record Stalwart names.
pub(super) fn verdict(record: &Expected, found: &[String]) -> Verdict {
    let same = |candidate: &String| match record.kind {
        // The preference is the operator's; the host is what counts.
        Kind::Mx => {
            candidate.split_whitespace().last().map(plain)
                == record.value.split_whitespace().last().map(plain)
        }
        Kind::Txt if record.name.contains("._domainkey.") => {
            key(candidate).is_some() && key(candidate) == key(&record.value)
        }
        Kind::Txt => candidate.trim() == record.value.trim(),
        Kind::Tlsa => candidate.eq_ignore_ascii_case(&record.value),
        _ => plain(candidate) == record.value,
    };
    if found.iter().any(same) {
        return Verdict::Published;
    }
    // A record of the same purpose with other content: an SPF or DMARC policy
    // of the operator's own, another DKIM key, another mail host.
    let purpose = record.value.split([';', ' ']).next().unwrap_or_default();
    let alike = |candidate: &String| match record.kind {
        Kind::Txt => candidate.starts_with(purpose),
        _ => true,
    };
    if found.iter().any(alike) {
        Verdict::Differs
    } else {
        Verdict::Missing
    }
}
