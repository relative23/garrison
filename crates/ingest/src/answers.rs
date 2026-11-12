//! What the queries answer: recorded events, the summaries of deliveries and
//! SMTP sessions, and how much the history covers.
//!
//! The web service turns these into the API's types. Their JSON form, with the
//! names the API uses, is what a list's size budget counts and what the golden
//! test records.

use serde::Serialize;
use serde_json::{Map, Value};

use crate::deliveries::{Lifecycle, Milestones};

/// One recorded event with Stalwart's own label of its type.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventItem {
    pub seq: i64,
    pub id: String,
    pub created_at: i64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub label: String,
    pub category: String,
    pub span_id: Option<String>,
    pub queue_id: Option<String>,
    /// The stored fields of the event, in the order Stalwart sent them.
    pub fields: Map<String, Value>,
}

/// One page of a list, newest first. `next` is the cursor of the following
/// page, or `None` after the last one.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<String>,
}

/// One delivery or session with its events, oldest first. `truncated` when
/// more events were recorded than are shown and summarized.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Detail<S> {
    pub summary: S,
    pub events: Vec<EventItem>,
    pub truncated: bool,
}

/// One queued message, by its queue ID.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverySummary {
    pub queue_id: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub event_count: usize,
    #[serde(flatten)]
    pub lifecycle: Lifecycle,
}

/// One SMTP session, by its span ID.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub span_id: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub event_count: usize,
    #[serde(flatten)]
    pub milestones: Milestones,
}

/// Whether the receiver wrote its heartbeat lately.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Receiver {
    Running,
    /// The last heartbeat is older than 90 seconds.
    Stale,
    /// There is no event database yet.
    Unavailable,
}

impl Receiver {
    pub const fn as_str(self) -> &'static str {
        match self {
            Receiver::Running => "running",
            Receiver::Stale => "stale",
            Receiver::Unavailable => "unavailable",
        }
    }
}

/// A time span inside the history in which events may be missing, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Gap {
    pub start: i64,
    pub end: i64,
    pub reason: String,
}

/// A size limit of the history.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Limit {
    /// `ingest.max_events`.
    Events,
    /// `ingest.max_database_mib`.
    Bytes,
}

impl Limit {
    pub const fn as_str(self) -> &'static str {
        match self {
            Limit::Events => "events",
            Limit::Bytes => "bytes",
        }
    }
}

/// The history begins later than its retention allows: events up to `until`
/// were removed to keep `limit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Trimmed {
    pub until: i64,
    pub limit: Limit,
}

/// What the history covers. Without a database nothing but the limitations
/// is known.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub available: bool,
    pub receiver: Receiver,
    pub heartbeat_at: Option<i64>,
    pub recording_since: Option<i64>,
    pub last_batch_at: Option<i64>,
    pub retention_days: Option<i64>,
    pub event_count: i64,
    /// Set while a size limit, not the retention, decides where the history begins.
    pub trimmed: Option<Trimmed>,
    pub gap_count: i64,
    /// The 20 newest gaps.
    pub gaps: Vec<Gap>,
    pub limitations: Vec<&'static str>,
}
