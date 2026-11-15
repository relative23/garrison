//! Read-only queries over the event history, used by the web service.
//!
//! Every query has a row limit and a response-size budget; the caller opens the
//! connection with `core::sqlite::reading`, which adds a time budget. Search
//! terms are matched literally with `instr()`, so wildcard or quote characters
//! cannot change the query.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use rusqlite::types::Value as Sql;
use rusqlite::{Connection, OptionalExtension, Row, params_from_iter};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::answers::{DeliverySummary, Detail, EventItem, Page, SessionSummary};
use crate::deliveries::{Event, MAX_SUMMARY_EVENTS, summarize_queue, summarize_session};
use crate::policy::identifier;

mod select;

use select::{chosen, clause, conditions, foldable, searched};

const MAX_RESPONSE_BYTES: usize = 768 * 1024;

/// Stalwart's own label and explanation of an event type (generated data).
#[derive(Debug, Deserialize)]
pub struct Labels {
    pub label: String,
    pub explanation: String,
}

static LABELS: LazyLock<BTreeMap<String, Labels>> =
    LazyLock::new(|| serde_json::from_str(include_str!("../event_types.json")).unwrap_or_default());

pub fn labels(event_type: &str) -> Option<&'static Labels> {
    LABELS.get(event_type)
}

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// A cursor or stored value that cannot be read; the request is refused.
    #[error("Invalid query")]
    Invalid,
    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),
}

impl QueryError {
    /// The reader's progress handler interrupted a query over its time budget.
    pub fn is_interrupted(&self) -> bool {
        matches!(self, QueryError::Sqlite(error) if garrison_core::sqlite::out_of_time(error))
    }
}

pub(crate) type Result<T> = std::result::Result<T, QueryError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    pub search: String,
    pub category: String,
    pub event_type: String,
    pub since: Option<i64>,
    pub until: Option<i64>,
    /// `seq` for events, `last_seen:id` for deliveries and sessions.
    pub before: Option<String>,
    pub limit: usize,
}

impl Default for Filter {
    fn default() -> Self {
        Filter {
            search: String::new(),
            category: String::new(),
            event_type: String::new(),
            since: None,
            until: None,
            before: None,
            limit: 50,
        }
    }
}

const EVENT_COLUMNS: &str = "seq,event_id,created_at,type,category,span_id,queue_id,fields";

fn fields(text: &str) -> Result<Map<String, Value>> {
    serde_json::from_str(text).map_err(|_| QueryError::Invalid)
}

fn event_item(row: &Row<'_>) -> Result<EventItem> {
    let event_type: String = row.get(3)?;
    let label =
        labels(&event_type).map_or_else(|| event_type.clone(), |labels| labels.label.clone());
    Ok(EventItem {
        seq: row.get(0)?,
        id: row.get(1)?,
        created_at: row.get(2)?,
        event_type,
        label,
        category: row.get(4)?,
        span_id: row.get(5)?,
        queue_id: row.get(6)?,
        fields: fields(&row.get::<_, String>(7)?)?,
    })
}

/// What an answer may still hold. Each item counts as the JSON it goes out
/// as.
struct Budget(usize);

impl Budget {
    fn new() -> Self {
        Budget(MAX_RESPONSE_BYTES)
    }

    /// Whether `item` still fits; it is counted if it does.
    fn takes<T: Serialize>(&mut self, item: &T) -> bool {
        let size = serde_json::to_string(item).map_or(usize::MAX, |text| text.len());
        match self.0.checked_sub(size) {
            Some(left) => {
                self.0 = left;
                true
            }
            None => false,
        }
    }
}

/// At most `limit` items within the response budget, and whether more exist.
fn bounded(items: Vec<EventItem>, limit: usize) -> (Vec<EventItem>, bool) {
    let more = items.len() > limit;
    let mut budget = Budget::new();
    let mut kept = Vec::new();
    for item in items.into_iter().take(limit) {
        if !budget.takes(&item) {
            return (kept, true);
        }
        kept.push(item);
    }
    (kept, more)
}

pub fn list_events(db: &Connection, filter: &Filter) -> Result<Page<EventItem>> {
    if !filter.search.is_empty() {
        foldable(db)?;
    }
    let (mut terms, mut values) = conditions(filter);
    if let Some(before) = &filter.before {
        terms.push("seq<?".to_owned());
        values.push(Sql::Integer(
            before.parse().map_err(|_| QueryError::Invalid)?,
        ));
    }
    let Some((choice, values)) = chosen(filter, &terms, values) else {
        // A category that has no type: nothing is recorded under it.
        return Ok(Page {
            items: Vec::new(),
            next: None,
        });
    };
    // The page's events are chosen by their numbers alone and read afterwards.
    // For a type, with or without a time range, the choice then needs only
    // the index that holds a type's events newest first with their time, and
    // ends with the page; only the page's events are read.
    let sql =
        format!("SELECT {EVENT_COLUMNS} FROM events WHERE seq IN ({choice}) ORDER BY seq DESC");
    let mut statement = db.prepare(&sql)?;
    let mut rows = statement.query(params_from_iter(values))?;
    let mut items = Vec::new();
    while let Some(row) = rows.next()? {
        items.push(event_item(row)?);
    }
    let (items, more) = bounded(items, filter.limit);
    let next = items
        .last()
        .filter(|_| more)
        .map(|last| last.seq.to_string());
    Ok(Page { items, next })
}

fn limit_plus_one(limit: usize) -> i64 {
    i64::try_from(limit).map_or(i64::MAX, |limit| limit.saturating_add(1))
}

/// The events of one queue or span, oldest first, one more than are summarized.
fn events_for(db: &Connection, column: Group, value: &str) -> Result<Vec<(Event, EventItem)>> {
    let sql = format!(
        "SELECT {EVENT_COLUMNS} FROM events WHERE {}=? ORDER BY created_at, seq LIMIT ?",
        column.column()
    );
    let mut statement = db.prepare(&sql)?;
    let mut rows = statement.query(rusqlite::params![value, limit_plus_one(MAX_SUMMARY_EVENTS)])?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        let pair = (row.get::<_, String>(3)?, fields(&row.get::<_, String>(7)?)?);
        events.push((pair, event_item(row)?));
    }
    Ok(events)
}

fn count(db: &Connection, column: Group, value: &str) -> Result<usize> {
    let sql = format!("SELECT count(*) FROM events WHERE {}=?", column.column());
    let total: i64 = db.query_row(&sql, [value], |row| row.get(0))?;
    Ok(usize::try_from(total).unwrap_or(0))
}

/// Deliveries group events by queue ID, sessions by span ID. The column names
/// in the SQL come only from here.
#[derive(Clone, Copy, Debug)]
enum Group {
    Queue,
    Span,
}

impl Group {
    fn column(self) -> &'static str {
        match self {
            Group::Queue => "queue_id",
            Group::Span => "span_id",
        }
    }

    fn table(self) -> &'static str {
        match self {
            Group::Queue => "queues",
            Group::Span => "spans",
        }
    }

    /// The index that holds the groups by when they were last seen. A page
    /// of a list is read along it, newest first, and ends after as many rows
    /// as the page has. SQLite is told to: left to choose, it reads every
    /// session and sorts them for each page as soon as the list has a
    /// condition the index does not hold (`work_tests.rs` counts the steps).
    fn newest_first(self) -> &'static str {
        match self {
            Group::Queue => "queues_last",
            Group::Span => "spans_last",
        }
    }

    /// What a page shows of its groups, in its list and by ID. Sessions are
    /// SMTP sessions. A delivery is a message that reached the queue: Stalwart
    /// gives a message its queue ID before a milter or a hook has seen it,
    /// and one they refuse is part of its session, not a delivery.
    fn only(self) -> &'static str {
        match self {
            Group::Queue => {
                "EXISTS (SELECT 1 FROM events WHERE events.queue_id=queues.queue_id \
                 AND events.category IN ('queue','delivery'))"
            }
            Group::Span => "protocol='smtp'",
        }
    }
}

fn keyset(before: Option<&str>) -> Result<Option<(i64, String)>> {
    let Some(before) = before.filter(|before| !before.is_empty()) else {
        return Ok(None);
    };
    let (stamp, key) = before.split_once(':').unwrap_or((before, ""));
    let stamp = Some(stamp)
        .filter(|stamp| !stamp.is_empty() && stamp.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|stamp| stamp.parse().ok());
    match (stamp, identifier(&Value::String(key.to_owned()))) {
        (Some(stamp), Some(key)) => Ok(Some((stamp, key))),
        _ => Err(QueryError::Invalid),
    }
}

/// One group row: its ID and first and last event time.
struct GroupRow {
    id: String,
    first_seen: i64,
    last_seen: i64,
}

impl GroupRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<GroupRow> {
        Ok(GroupRow {
            id: row.get(0)?,
            first_seen: row.get(1)?,
            last_seen: row.get(2)?,
        })
    }
}

fn grouped(db: &Connection, group: Group, filter: &Filter) -> Result<Vec<GroupRow>> {
    let key = group.column();
    let mut terms = vec![group.only().to_owned()];
    let mut values = Vec::new();
    if let Some((stamp, id)) = keyset(filter.before.as_deref())? {
        terms.push(format!("(last_seen<? OR (last_seen=? AND {key}<?))"));
        values.extend([Sql::Integer(stamp), Sql::Integer(stamp), Sql::Text(id)]);
    }
    if let Some(since) = filter.since {
        terms.push("last_seen>=?".to_owned());
        values.push(Sql::Integer(since));
    }
    if let Some(until) = filter.until {
        terms.push("first_seen<=?".to_owned());
        values.push(Sql::Integer(until));
    }
    if !filter.search.is_empty() {
        // Match groups that contain at least one event with the literal text.
        foldable(db)?;
        let (term, found) = searched(&filter.search);
        terms.push(format!(
            "{key} IN (SELECT {key} FROM events WHERE {key} IS NOT NULL AND {term})"
        ));
        values.extend(found);
    }
    values.push(Sql::Integer(limit_plus_one(filter.limit)));
    let sql = format!(
        "SELECT {key},first_seen,last_seen FROM {} INDEXED BY {}{} \
         ORDER BY last_seen DESC, {key} DESC LIMIT ?",
        group.table(),
        group.newest_first(),
        clause(&terms)
    );
    let mut statement = db.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(values), GroupRow::from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Makes the summary of one group from its row, its events and their count.
type Summarize<S> = fn(&GroupRow, &[Event], usize) -> S;

fn delivery(row: &GroupRow, events: &[Event], total: usize) -> DeliverySummary {
    DeliverySummary {
        queue_id: row.id.clone(),
        first_seen: row.first_seen,
        last_seen: row.last_seen,
        event_count: total,
        lifecycle: summarize_queue(events, total),
    }
}

fn session(row: &GroupRow, events: &[Event], total: usize) -> SessionSummary {
    SessionSummary {
        span_id: row.id.clone(),
        first_seen: row.first_seen,
        last_seen: row.last_seen,
        event_count: total,
        milestones: summarize_session(events, total),
    }
}

/// The summary of one group with the events it shows.
fn summary<S>(
    db: &Connection,
    group: Group,
    row: &GroupRow,
    summarize: Summarize<S>,
) -> Result<Detail<S>> {
    let events = events_for(db, group, &row.id)?;
    let total = count(db, group, &row.id)?;
    let pairs: Vec<Event> = events.iter().map(|(pair, _)| pair.clone()).collect();
    // The summary reads every event up to its bound; the events that are
    // shown end where the answer is full, and that is said.
    let items = events.into_iter().map(|(_, item)| item).collect();
    let (items, truncated) = bounded(items, MAX_SUMMARY_EVENTS);
    Ok(Detail {
        summary: summarize(row, &pairs, total),
        events: items,
        truncated,
    })
}

fn page<S: Serialize>(
    db: &Connection,
    group: Group,
    filter: &Filter,
    summarize: Summarize<S>,
) -> Result<Page<S>> {
    let rows = grouped(db, group, filter)?;
    let mut more = rows.len() > filter.limit;
    let mut budget = Budget::new();
    let mut items = Vec::new();
    for row in rows.iter().take(filter.limit) {
        let item = summary(db, group, row, summarize)?.summary;
        // The page ends where the answer is full; the next begins there.
        if !budget.takes(&item) {
            more = true;
            break;
        }
        items.push(item);
    }
    let next = items
        .len()
        .checked_sub(1)
        .and_then(|last| rows.get(last))
        .filter(|_| more)
        .map(|last| format!("{}:{}", last.last_seen, last.id));
    Ok(Page { items, next })
}

fn detail<S>(
    db: &Connection,
    group: Group,
    id: &str,
    summarize: Summarize<S>,
) -> Result<Option<Detail<S>>> {
    let key = group.column();
    let mut terms = vec![format!("{key}=?")];
    terms.push(group.only().to_owned());
    let sql = format!(
        "SELECT {key},first_seen,last_seen FROM {}{}",
        group.table(),
        clause(&terms)
    );
    let row = db.query_row(&sql, [id], GroupRow::from_row).optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    summary(db, group, &row, summarize).map(Some)
}

pub fn list_deliveries(db: &Connection, filter: &Filter) -> Result<Page<DeliverySummary>> {
    page(db, Group::Queue, filter, delivery)
}

pub fn delivery_detail(db: &Connection, queue_id: &str) -> Result<Option<Detail<DeliverySummary>>> {
    detail(db, Group::Queue, queue_id, delivery)
}

pub fn list_sessions(db: &Connection, filter: &Filter) -> Result<Page<SessionSummary>> {
    page(db, Group::Span, filter, session)
}

pub fn session_detail(db: &Connection, span_id: &str) -> Result<Option<Detail<SessionSummary>>> {
    detail(db, Group::Span, span_id, session)
}

#[cfg(test)]
mod budget_tests;
#[cfg(test)]
mod refused_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod work_tests;
