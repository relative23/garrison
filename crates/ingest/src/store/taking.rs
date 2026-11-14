//! One event of a batch: whether it is recorded, whether it reads, and
//! what it adds to the history.

use rusqlite::{Connection, params};
use serde_json::Value;

use super::{MAX_EVENT_ID, SqliteError, parse_time};
use crate::policy::{EventType, identifier, select_fields};

/// Stalwart's clock and this host's may differ by this many seconds before
/// an event counts as dated after its own arrival.
const AHEAD: i64 = 300;

/// When a batch arrived, and where what the history keeps begins then.
#[derive(Clone, Copy, Debug)]
pub(super) struct Arrival {
    pub(super) at: i64,
    pub(super) kept_from: i64,
}

impl Arrival {
    /// Whether an event that arrives now can have happened at `created`.
    ///
    /// The time is the sender's word, and the history is kept by it:
    /// retention and the size limits remove the oldest events first. An
    /// event dated years ahead would outlive both and, once a limit is
    /// reached, take the place of every real one; one dated before what is
    /// kept would be gone with the next clean-up. Neither time is one of an
    /// event that arrives now, so neither is recorded as if it were.
    fn can_be(self, created: i64) -> bool {
        (self.kept_from..=self.at.saturating_add(AHEAD)).contains(&created)
    }
}

/// What became of one event of a batch.
pub(super) enum Taken {
    Stored,
    /// Stored already: Stalwart brought the batch again.
    Duplicate,
    /// No event, or of a type that is not recorded.
    NotRecorded,
    /// Of a type that is recorded, with an id that does not read or a time
    /// that does not read or cannot be the time of an event arriving now.
    Unreadable,
}

/// Insert one event, and say what became of it.
pub(super) fn insert(
    db: &Connection,
    event: &Value,
    arrival: Arrival,
) -> Result<Taken, SqliteError> {
    let Value::Object(event) = event else {
        return Ok(Taken::NotRecorded);
    };
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        .and_then(EventType::parse);
    let created = event
        .get("createdAt")
        .and_then(parse_time)
        .filter(|created| arrival.can_be(*created));
    let event_id = match event.get("id") {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Number(number)) if !number.is_f64() => Some(number.to_string()),
        _ => None,
    }
    .filter(|id| id.chars().count() <= MAX_EVENT_ID);
    // A type that is not recorded is left out on purpose. One that is, with
    // a time or an id that does not read, or a time that cannot be its own,
    // is an event that goes missing.
    let Some(event_type) = event_type else {
        return Ok(Taken::NotRecorded);
    };
    let (Some(created), Some(event_id)) = (created, event_id) else {
        return Ok(Taken::Unreadable);
    };
    let data = event.get("data").unwrap_or(&Value::Null);
    let fields = select_fields(event_type, data);
    let span = data.get("spanId").and_then(identifier);
    let queue = data.get("queueId").and_then(identifier);
    let kind = event_type.category();
    let inserted = db.execute(
        "INSERT OR IGNORE INTO events(event_id,created_at,received_at,type,category,\
         span_id,queue_id,fields) VALUES(?,?,?,?,?,?,?,?)",
        params![
            event_id,
            created,
            arrival.at,
            event_type.as_str(),
            kind,
            span,
            queue,
            Value::Object(fields).to_string(),
        ],
    )?;
    if inserted != 1 {
        return Ok(Taken::Duplicate); // A retried batch: the event is already recorded.
    }
    if let Some(queue) = &queue {
        db.execute(
            "INSERT INTO queues VALUES(?,?,?,1) ON CONFLICT(queue_id) DO UPDATE SET \
             first_seen=min(first_seen,excluded.first_seen),\
             last_seen=max(last_seen,excluded.last_seen),event_count=event_count+1",
            params![queue, created, created],
        )?;
    }
    if let Some(span) = &span {
        // A span that contains any SMTP event is an SMTP session, even if a
        // queue event of the same span happened to arrive first.
        db.execute(
            "INSERT INTO spans VALUES(?,?,?,1,?) ON CONFLICT(span_id) DO UPDATE SET \
             first_seen=min(first_seen,excluded.first_seen),\
             last_seen=max(last_seen,excluded.last_seen),event_count=event_count+1,\
             protocol=CASE WHEN excluded.protocol='smtp' THEN 'smtp' ELSE protocol END",
            params![span, created, created, kind],
        )?;
    }
    Ok(Taken::Stored)
}
