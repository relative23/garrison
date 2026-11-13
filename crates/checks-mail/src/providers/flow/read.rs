//! Reading a week of the event history for the mail-flow summaries: how many
//! events of each kind each day had, and from the events themselves the
//! domains behind them.

use std::collections::{BTreeMap, HashMap, HashSet};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(super) const DAY: i64 = 86_400;
pub(super) const DAYS: i64 = 7;
/// The newest events of one type whose fields are read.
const MAX_EVENTS: usize = 50_000;
/// The rows of each list.
pub(super) const ROWS: usize = 20;

/// Every type whose events are counted by day.
pub(super) const COUNTED: [&str; 27] = [
    "message-ingest.ham",
    "message-ingest.spam",
    "spam.train-completed",
    "milter.action-accept",
    "milter.action-reject",
    "milter.action-discard",
    "milter.action-temp-fail",
    "milter.action-reply-code",
    "milter.action-connection-failure",
    "milter.timeout",
    "milter.io-error",
    "milter.disconnected",
    "smtp.spf-ehlo-pass",
    "smtp.spf-ehlo-fail",
    "smtp.spf-from-pass",
    "smtp.spf-from-fail",
    "smtp.dkim-pass",
    "smtp.dkim-fail",
    "smtp.dmarc-pass",
    "smtp.dmarc-fail",
    "smtp.arc-pass",
    "smtp.arc-fail",
    "smtp.iprev-pass",
    "smtp.iprev-fail",
    "delivery.start-tls",
    "delivery.start-tls-unavailable",
    "delivery.start-tls-error",
];

/// A week of the history as the summaries need it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct Week {
    /// The first second of each day, oldest first; the last one is today (UTC).
    pub(super) days: Vec<i64>,
    /// For each counted type that occurred, its events on each of the days.
    pub(super) counts: BTreeMap<String, Vec<u64>>,
    /// Recipient domains with their ham and spam.
    pub(super) filed: Vec<(String, u64, u64)>,
    /// Sender domains with their SPF and DMARC failures.
    pub(super) failing: Vec<(String, u64, u64)>,
    /// Mail that came in on port 25 with and without STARTTLS.
    pub(super) inbound: (u64, u64),
    /// Sender domains whose mail came in without TLS.
    pub(super) plain_in: Vec<(String, u64)>,
    /// Hosts that were delivered to without TLS.
    pub(super) plain_out: Vec<(String, u64)>,
    pub(super) last_training: Option<i64>,
    /// More events of a type were recorded than were read.
    pub(super) truncated: bool,
}

impl Week {
    /// The events of `kind` on each day; zeros where there were none.
    pub(super) fn of(&self, kind: &str) -> Vec<u64> {
        self.counts
            .get(kind)
            .cloned()
            .unwrap_or_else(|| vec![0; self.days.len()])
    }

    /// The events of `kinds` over the whole week.
    pub(super) fn sum(&self, kinds: &[&str]) -> u64 {
        kinds
            .iter()
            .map(|kind| self.of(kind).iter().sum::<u64>())
            .sum()
    }
}

fn domain(address: &str) -> Option<String> {
    let (_, domain) = address.trim_matches(['<', '>']).rsplit_once('@')?;
    let domain = domain.trim_end_matches('.').to_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// The busiest first, by name among equals; at most the rows of a list.
fn ranked<T: Clone>(found: HashMap<String, T>, weight: impl Fn(&T) -> u64) -> Vec<(String, T)> {
    let mut rows: Vec<(String, T)> = found.into_iter().collect();
    rows.sort_by(|left, right| {
        weight(&right.1)
            .cmp(&weight(&left.1))
            .then_with(|| left.0.cmp(&right.0))
    });
    rows.truncate(ROWS);
    rows
}

/// The fields of the newest events of `kind` since `since`, with their span.
fn events(
    db: &Connection,
    kind: &str,
    since: i64,
    truncated: &mut bool,
) -> rusqlite::Result<Vec<(Option<String>, Value)>> {
    let mut statement = db.prepare_cached(
        "SELECT span_id,fields FROM events WHERE type=?1 AND created_at>=?2 ORDER BY seq DESC LIMIT ?3",
    )?;
    let limit = i64::try_from(MAX_EVENTS + 1).unwrap_or(i64::MAX);
    let mut rows = statement.query((kind, since, limit))?;
    let mut found = Vec::new();
    while let Some(row) = rows.next()? {
        if found.len() == MAX_EVENTS {
            *truncated = true;
            break;
        }
        let text: String = row.get(1)?;
        if let Ok(fields) = serde_json::from_str::<Value>(&text) {
            found.push((row.get(0)?, fields));
        }
    }
    Ok(found)
}

/// Whether a failed check was a failure of the sender, not a sender without
/// a record: `spf.fail` and `dmarc.fail` are, `spf.none` is not. An event
/// without an outcome, as older releases stored it, counts.
fn failed(fields: &Value) -> bool {
    fields["result"]
        .as_str()
        .is_none_or(|result| result.contains("fail"))
}

/// How many events of each counted type each day had, and the last
/// training run.
fn counted(db: &Connection, week: &mut Week, since: i64) -> rusqlite::Result<()> {
    // The index holds type and time, so the counts need no event's fields.
    let marks = vec!["?"; COUNTED.len()].join(",");
    let mut statement = db.prepare(&format!(
        "SELECT type,(created_at-?1)/{DAY},count(*) FROM events WHERE created_at>=?1 \
         AND type IN ({marks}) GROUP BY 1,2"
    ))?;
    let mut values: Vec<rusqlite::types::Value> = vec![since.into()];
    values.extend(COUNTED.iter().map(|kind| (*kind).to_owned().into()));
    let mut rows = statement.query(rusqlite::params_from_iter(values))?;
    while let Some(row) = rows.next()? {
        let (kind, day, count): (String, i64, i64) = (row.get(0)?, row.get(1)?, row.get(2)?);
        let slots = week
            .counts
            .entry(kind)
            .or_insert_with(|| vec![0; week.days.len()]);
        if let Some(slot) = usize::try_from(day).ok().and_then(|day| slots.get_mut(day)) {
            *slot = u64::try_from(count).unwrap_or(0);
        }
    }
    drop(rows);
    drop(statement);
    week.last_training = db.query_row(
        "SELECT MAX(created_at) FROM events WHERE type='spam.train-completed'",
        [],
        |row| row.get(0),
    )?;
    Ok(())
}

/// Mail with and without TLS, coming in and going out.
fn transit(
    db: &Connection,
    week: &mut Week,
    since: i64,
    truncated: &mut bool,
) -> rusqlite::Result<()> {
    // Mail on port 25: a session that said STARTTLS before its MAIL FROM had TLS.
    let secured: HashSet<String> = events(db, "smtp.start-tls", since, truncated)?
        .into_iter()
        .filter_map(|(span, _)| span)
        .collect();
    let mut plain_in: HashMap<String, u64> = HashMap::new();
    for (span, fields) in events(db, "smtp.mail-from", since, truncated)? {
        if fields["localPort"].as_i64() != Some(25) {
            continue;
        }
        if span.is_some_and(|span| secured.contains(&span)) {
            week.inbound.0 += 1;
        } else {
            week.inbound.1 += 1;
            let sender = fields["from"].as_str().and_then(domain);
            *plain_in
                .entry(sender.unwrap_or_else(|| "(no sender)".to_owned()))
                .or_default() += 1;
        }
    }
    week.plain_in = ranked(plain_in, |count| *count);
    let mut plain_out: HashMap<String, u64> = HashMap::new();
    for kind in ["delivery.start-tls-unavailable", "delivery.start-tls-error"] {
        for (_, fields) in events(db, kind, since, truncated)? {
            let host = fields["hostname"]
                .as_str()
                .or_else(|| fields["domain"].as_str());
            *plain_out
                .entry(host.unwrap_or("(unknown host)").to_lowercase())
                .or_default() += 1;
        }
    }
    week.plain_out = ranked(plain_out, |count| *count);
    Ok(())
}

/// Read the week that ends at `now`. `accounts` maps an account's number to
/// the domain of its address.
pub(super) fn week(
    db: &Connection,
    now: i64,
    accounts: &HashMap<i64, String>,
) -> rusqlite::Result<Week> {
    let today = now - now.rem_euclid(DAY);
    let since = today - (DAYS - 1) * DAY;
    let days: Vec<i64> = (0..DAYS).map(|day| since + day * DAY).collect();
    let mut week = Week {
        days,
        ..Week::default()
    };

    counted(db, &mut week, since)?;

    let mut truncated = false;
    let mut filed: HashMap<String, (u64, u64)> = HashMap::new();
    for (kind, spam) in [("message-ingest.ham", false), ("message-ingest.spam", true)] {
        for (_, fields) in events(db, kind, since, &mut truncated)? {
            let domain = fields["accountId"]
                .as_i64()
                .and_then(|id| accounts.get(&id))
                .map_or("unknown", String::as_str);
            let entry = filed.entry(domain.to_owned()).or_default();
            if spam {
                entry.1 += 1;
            } else {
                entry.0 += 1;
            }
        }
    }
    week.filed = ranked(filed, |(ham, spam)| ham + spam)
        .into_iter()
        .map(|(domain, (ham, spam))| (domain, ham, spam))
        .collect();

    let mut failing: HashMap<String, (u64, u64)> = HashMap::new();
    for (_, fields) in events(db, "smtp.spf-from-fail", since, &mut truncated)? {
        if let Some(domain) = fields["from"]
            .as_str()
            .and_then(domain)
            .filter(|_| failed(&fields))
        {
            failing.entry(domain).or_default().0 += 1;
        }
    }
    for (_, fields) in events(db, "smtp.dmarc-fail", since, &mut truncated)? {
        if let Some(domain) = fields["domain"].as_str().filter(|_| failed(&fields)) {
            failing.entry(domain.to_lowercase()).or_default().1 += 1;
        }
    }
    week.failing = ranked(failing, |(spf, dmarc)| spf + dmarc)
        .into_iter()
        .map(|(domain, (spf, dmarc))| (domain, spf, dmarc))
        .collect();

    transit(db, &mut week, since, &mut truncated)?;
    week.truncated = truncated;
    Ok(week)
}
