//! Reading a week of the event history for the mail-flow summaries: how many
//! events of each kind each day had, and from the events themselves the
//! domains behind them.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::Connection;
use rusqlite::types::ValueRef;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::providers::history;

pub(super) const DAY: i64 = 86_400;
pub(super) const DAYS: i64 = 7;

/// How much of the week the lists take: the newest events of each type
/// whose fields are read, the rows each list shows, and the first of
/// Stalwart's accounts whose domains name the mail by domain. The counts by
/// day and the numbers of mail with and without TLS count every event of
/// the week.
#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub(super) events: usize,
    pub(super) rows: usize,
    pub(super) accounts: usize,
}

impl Limits {
    /// The accounts as many as the `stalwart` check reads at the most.
    pub(super) const WEEK: Limits = Limits {
        events: 50_000,
        rows: 20,
        accounts: 20_000,
    };
}

/// Every type whose events are counted by day.
pub(super) const COUNTED: [&str; 28] = [
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
    "milter.frame-too-large",
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

/// What a milter answered a message, but a deferral, as Stalwart records it.
const VERDICTS: [&str; 4] = [
    "milter.action-accept",
    "milter.action-reject",
    "milter.action-discard",
    "milter.action-reply-code",
];

/// Whether an event's time and fields are as the receiver writes them: a
/// whole second and a JSON object in text. `json_type` fails on text that
/// is no JSON, so it is asked only of valid JSON.
const READABLE: &str = "typeof(m.created_at) = 'integer' AND CASE WHEN typeof(m.fields) = 'text' \
                        AND json_valid(m.fields) THEN json_type(m.fields) = 'object' ELSE 0 END";
/// Mail that came in on port 25, of the week's MAIL FROMs: the port is a
/// field of the event.
const PORT_25: &str = "CASE WHEN typeof(m.created_at) = 'integer' AND typeof(m.fields) = 'text' \
                       AND json_valid(m.fields) THEN CASE WHEN json_type(m.fields) = 'object' THEN \
                       json_extract(m.fields, '$.localPort') END END = 25";
/// The MAIL FROMs of the week, whose first second is `?1`.
const MAIL_FROM: &str = "m.type = 'smtp.mail-from' AND m.created_at >= ?1";
/// Whether the session of such mail said STARTTLS in the week, as one that
/// did before its MAIL FROM had TLS.
const SECURED: &str = "EXISTS (SELECT 1 FROM events s WHERE s.span_id = m.span_id AND \
                       s.type = 'smtp.start-tls' AND s.created_at >= ?1)";

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
    /// The types of which the lists read only the newest events, where more
    /// were recorded in the week.
    #[serde(default)]
    pub(super) cut: BTreeSet<String>,
    /// How many rows each list has in all, by the list's name, where it has
    /// more than it shows.
    #[serde(default)]
    pub(super) listed: BTreeMap<String, usize>,
    /// Events left out of the counts and lists, as a value in them is of
    /// another type than the receiver writes: a time that is no whole
    /// second, fields that are no JSON object.
    #[serde(default)]
    pub(super) unreadable: u64,
    /// Whether a milter deferred every message that the milters answered
    /// since yesterday (UTC), and there was one.
    #[serde(default)]
    pub(super) deferred_all: bool,
}

impl Week {
    /// Whether it has the shape a reading gives it, which the cards rely on:
    /// a count for each of its days in every kind.
    pub(super) fn whole(&self) -> bool {
        self.counts
            .values()
            .all(|days| days.len() == self.days.len())
    }

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

/// The busiest first, by name among equals; at most the rows of a list. How
/// many rows the list has in all goes to `listed` under `list`, where it has
/// more.
fn ranked<T: Clone>(
    found: HashMap<String, T>,
    weight: impl Fn(&T) -> u64,
    list: &str,
    listed: &mut BTreeMap<String, usize>,
    limits: &Limits,
) -> Vec<(String, T)> {
    let all = found.len();
    let mut rows: Vec<(String, T)> = found.into_iter().collect();
    rows.sort_by(|left, right| {
        weight(&right.1)
            .cmp(&weight(&left.1))
            .then_with(|| left.0.cmp(&right.0))
    });
    rows.truncate(limits.rows);
    if all > limits.rows {
        listed.insert(list.to_owned(), all);
    }
    rows
}

/// The fields of the newest events of `kind` since `since`, as many as
/// `limits` take; `kind` goes to the week's cuts where there are more. An
/// event whose fields cannot be read is counted as left out, one whose time
/// is no whole second is left out here as `counted` counts it.
fn events(
    db: &Connection,
    kind: &str,
    since: i64,
    limits: &Limits,
    week: &mut Week,
) -> rusqlite::Result<Vec<Value>> {
    let mut statement = db.prepare_cached(
        "SELECT created_at,fields FROM events WHERE type=?1 AND created_at>=?2 ORDER BY seq DESC \
         LIMIT ?3",
    )?;
    let limit = i64::try_from(limits.events + 1).unwrap_or(i64::MAX);
    let mut rows = statement.query((kind, since, limit))?;
    let mut found = Vec::new();
    let mut read = 0;
    while let Some(row) = rows.next()? {
        if read == limits.events {
            week.cut.insert(kind.to_owned());
            break;
        }
        read += 1;
        if !matches!(row.get_ref(0)?, ValueRef::Integer(_)) {
            continue;
        }
        match history::fields(row.get_ref(1)?) {
            Some(fields) => found.push(fields),
            None => week.unreadable += 1,
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
/// training run; an event whose time is no whole second is counted as left
/// out.
fn counted(db: &Connection, week: &mut Week, since: i64) -> rusqlite::Result<()> {
    // The index holds type and time, so the counts need no event's fields.
    let marks = vec!["?"; COUNTED.len()].join(",");
    let mut statement = db.prepare(&format!(
        "SELECT type,CASE WHEN typeof(created_at)='integer' THEN (created_at-?1)/{DAY} END,\
         count(*) FROM events WHERE created_at>=?1 AND type IN ({marks}) GROUP BY 1,2"
    ))?;
    let mut values: Vec<rusqlite::types::Value> = vec![since.into()];
    values.extend(COUNTED.iter().map(|kind| (*kind).to_owned().into()));
    let mut rows = statement.query(rusqlite::params_from_iter(values))?;
    while let Some(row) = rows.next()? {
        let (kind, day, count): (String, Option<i64>, i64) =
            (row.get(0)?, row.get(1)?, row.get(2)?);
        let Some(day) = day else {
            week.unreadable += u64::try_from(count).unwrap_or(0);
            continue;
        };
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
        "SELECT MAX(created_at) FROM events WHERE type='spam.train-completed' AND \
         typeof(created_at)='integer'",
        [],
        |row| row.get(0),
    )?;
    Ok(())
}

/// Whether a milter deferred every message that the milters answered since
/// `since`, and there was one. Stalwart records each milter's answer under
/// the message's session, and asks none after a deferral (measured with
/// Stalwart 1.2.0); the history does not name the milter, so a message is
/// told by its session, and an answer without one is a message of its own.
fn deferred_all(db: &Connection, since: i64) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS (SELECT 1 FROM events WHERE type = 'milter.action-temp-fail' AND \
         created_at >= ?1 AND typeof(created_at) = 'integer') AND NOT EXISTS (SELECT 1 FROM \
         events a WHERE a.type IN (?2, ?3, ?4, ?5) AND a.created_at >= ?1 AND \
         typeof(a.created_at) = 'integer' AND (a.span_id IS NULL OR NOT EXISTS (SELECT 1 FROM \
         events d WHERE d.span_id = a.span_id AND d.type = 'milter.action-temp-fail')))",
        (since, VERDICTS[0], VERDICTS[1], VERDICTS[2], VERDICTS[3]),
        |row| row.get(0),
    )
}

/// Mail with and without TLS, coming in and going out.
fn transit(db: &Connection, week: &mut Week, since: i64, limits: &Limits) -> rusqlite::Result<()> {
    // Both numbers of incoming mail count all of it in one query, so that
    // they are of one and the same stretch of time.
    let (secured, all, unreadable): (i64, i64, i64) = db.query_row(
        &format!(
            "SELECT coalesce(sum(CASE WHEN {PORT_25} THEN {SECURED} END), 0), \
             coalesce(sum({PORT_25}), 0), coalesce(sum(NOT ({READABLE})), 0) FROM events m \
             WHERE {MAIL_FROM}"
        ),
        [since],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    week.inbound = (
        u64::try_from(secured).unwrap_or(0),
        u64::try_from(all - secured).unwrap_or(0),
    );
    week.unreadable += u64::try_from(unreadable).unwrap_or(0);
    // The sender domains of the newest of what came in without TLS.
    let mut statement = db.prepare(&format!(
        "SELECT m.fields FROM events m WHERE {MAIL_FROM} AND {PORT_25} AND NOT {SECURED} \
         ORDER BY m.seq DESC LIMIT ?2"
    ))?;
    let limit = i64::try_from(limits.events + 1).unwrap_or(i64::MAX);
    let mut rows = statement.query((since, limit))?;
    let mut plain_in: HashMap<String, u64> = HashMap::new();
    let mut read = 0;
    while let Some(row) = rows.next()? {
        if read == limits.events {
            week.cut.insert("smtp.mail-from".to_owned());
            break;
        }
        read += 1;
        let text: String = row.get(0)?;
        let sender = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|fields| fields["from"].as_str().and_then(domain));
        *plain_in
            .entry(sender.unwrap_or_else(|| "(no sender)".to_owned()))
            .or_default() += 1;
    }
    drop(rows);
    drop(statement);
    week.plain_in = ranked(
        plain_in,
        |count| *count,
        "plain_in",
        &mut week.listed,
        limits,
    );
    let mut plain_out: HashMap<String, u64> = HashMap::new();
    for kind in ["delivery.start-tls-unavailable", "delivery.start-tls-error"] {
        for fields in events(db, kind, since, limits, week)? {
            let host = fields["hostname"]
                .as_str()
                .or_else(|| fields["domain"].as_str());
            *plain_out
                .entry(host.unwrap_or("(unknown host)").to_lowercase())
                .or_default() += 1;
        }
    }
    week.plain_out = ranked(
        plain_out,
        |count| *count,
        "plain_out",
        &mut week.listed,
        limits,
    );
    Ok(())
}

/// Read the week that ends at `now`, its lists within `limits`. `accounts`
/// maps an account's number to the domain of its address.
pub(super) fn week(
    db: &Connection,
    now: i64,
    accounts: &HashMap<i64, String>,
    limits: &Limits,
) -> rusqlite::Result<Week> {
    let today = now - now.rem_euclid(DAY);
    let since = today - (DAYS - 1) * DAY;
    let days: Vec<i64> = (0..DAYS).map(|day| since + day * DAY).collect();
    let mut week = Week {
        days,
        ..Week::default()
    };

    counted(db, &mut week, since)?;
    week.deferred_all = deferred_all(db, today - DAY)?;

    let mut filed: HashMap<String, (u64, u64)> = HashMap::new();
    for (kind, spam) in [("message-ingest.ham", false), ("message-ingest.spam", true)] {
        for fields in events(db, kind, since, limits, &mut week)? {
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
    week.filed = ranked(
        filed,
        |(ham, spam)| ham + spam,
        "filed",
        &mut week.listed,
        limits,
    )
    .into_iter()
    .map(|(domain, (ham, spam))| (domain, ham, spam))
    .collect();

    let mut failing: HashMap<String, (u64, u64)> = HashMap::new();
    for fields in events(db, "smtp.spf-from-fail", since, limits, &mut week)? {
        if let Some(domain) = fields["from"]
            .as_str()
            .and_then(domain)
            .filter(|_| failed(&fields))
        {
            failing.entry(domain).or_default().0 += 1;
        }
    }
    for fields in events(db, "smtp.dmarc-fail", since, limits, &mut week)? {
        if let Some(domain) = fields["domain"].as_str().filter(|_| failed(&fields)) {
            failing.entry(domain.to_lowercase()).or_default().1 += 1;
        }
    }
    week.failing = ranked(
        failing,
        |(spf, dmarc)| spf + dmarc,
        "failing",
        &mut week.listed,
        limits,
    )
    .into_iter()
    .map(|(domain, (spf, dmarc))| (domain, spf, dmarc))
    .collect();

    transit(db, &mut week, since, limits)?;
    Ok(week)
}
