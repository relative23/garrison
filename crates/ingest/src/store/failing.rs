//! The time in which the receiver ran and stored nothing.
//!
//! A receiver that is down leaves a stale heartbeat, and its next start
//! records the gap. One that runs and takes nothing looks alive: the
//! signature key no longer matches (401), the database is full or cannot be
//! written (503), or Stalwart writes the events of a recorded type in a way
//! that no longer reads, which is answered as stored and never comes again.
//! So the receiver keeps since when it stores nothing, in memory and, where
//! the database takes it, beside the heartbeat; whoever reads the history
//! sees it there, and the first batch that is stored whole turns it into a
//! gap.

use garrison_core::recording::{FAILING_KIND, FAILING_SINCE, REFUSED, UNREADABLE, number, set};
use rusqlite::{Connection, params};

/// Why nothing was stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// Batches were refused; Stalwart keeps them for a while and brings
    /// them again.
    Refused,
    /// Events were answered as stored and could not be read, or carried a
    /// time that cannot be their own: lost at once.
    Unreadable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Failing {
    pub(super) since: i64,
    pub(super) kind: Kind,
}

/// What the receiver counted since it started, for its health answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Health {
    /// Since when no batch was stored whole, while that lasts.
    pub failing_since: Option<i64>,
    /// Batches refused for their signature or because storing failed.
    pub refused: u64,
    /// Events of a recorded type that could not be read.
    pub unreadable: u64,
    /// Events that were stored already: a batch that came again.
    pub duplicate: u64,
}

/// What an earlier run of the receiver left, if it ended while it failed.
pub(super) fn kept(db: &Connection) -> Option<Failing> {
    let since = number(db, FAILING_SINCE).ok().flatten()?;
    let kind = match number(db, FAILING_KIND).ok().flatten() {
        Some(2) => Kind::Unreadable,
        _ => Kind::Refused,
    };
    Some(Failing { since, kind })
}

/// Keep `failing` beside the heartbeat, for the readers of the history and
/// for the next start.
pub(super) fn keep(db: &Connection, failing: Failing) -> rusqlite::Result<()> {
    set(db, FAILING_SINCE, failing.since)?;
    set(
        db,
        FAILING_KIND,
        match failing.kind {
            Kind::Refused => 1,
            Kind::Unreadable => 2,
        },
    )
}

/// A batch was stored whole at `now`: record what was lost since `failing`
/// began and forget it. Of refused batches Stalwart kept the last
/// `discard_after` seconds and brings them again; unreadable events are
/// gone up to now.
pub(super) fn ended(
    db: &Connection,
    failing: Failing,
    now: i64,
    discard_after: i64,
) -> rusqlite::Result<()> {
    let (lost_until, reason) = match failing.kind {
        Kind::Refused => (now - discard_after, REFUSED),
        Kind::Unreadable => (now, UNREADABLE),
    };
    if lost_until > failing.since {
        db.execute(
            "INSERT INTO gaps(start_at,end_at,reason) VALUES(?,?,?)",
            params![failing.since, lost_until, reason],
        )?;
    }
    db.execute(
        "DELETE FROM metadata WHERE key IN (?,?)",
        [FAILING_SINCE, FAILING_KIND],
    )?;
    Ok(())
}
