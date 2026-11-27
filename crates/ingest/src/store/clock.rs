//! The time the receiver removes old events by: its run time, which a jump
//! of the host's clock cannot take along (`garrison_core::run_time`). The
//! receiver looks at its clock with every heartbeat and every batch. A step
//! of at most ten minutes moves the run time on; a clock further ahead, as
//! on a host that starts with its clock ahead before its time server
//! answers, leaves the history as the run time has it, until the receiver
//! has run at the clock's new time for a day or the clock comes back.
//! Counted from the clock alone, one clean-up at a time a month ahead
//! emptied the history, and nothing said that it had ever held more.

use garrison_core::recording;
use garrison_core::run_time::{self, Kept, Pace, Turn};
use garrison_core::time;
use log::Level;
use rusqlite::Connection;

use super::{SqliteError, meta};

/// The steps of the receiver: ten minutes move its run time on, a day at a
/// time ahead makes that time believed, and a longer step counts as one
/// heartbeat.
const PACE: Pace = Pace {
    limit: 600,
    hold: 86_400,
    run: 30,
};
/// The receiver's run time, and for how long it has run at a time ahead of
/// it, among what it keeps about itself.
const BELIEVED: &str = "runTime";
const AHEAD_FOR: &str = "runTimeAheadFor";

/// What the receiver kept at its last look; a value that is no number is
/// as good as none.
fn kept(db: &Connection) -> Result<Kept, SqliteError> {
    let number = |key| Ok::<_, SqliteError>(meta(db, key)?.and_then(|value| value.as_i64()));
    Ok(Kept {
        believed: number(BELIEVED)?,
        ahead_for: number(AHEAD_FOR)?,
    })
}

fn keep(db: &Connection, key: &str, value: Option<i64>) -> rusqlite::Result<()> {
    match value {
        Some(value) => recording::set(db, key, value),
        None => db
            .execute("DELETE FROM metadata WHERE key=?", [key])
            .map(|_| ()),
    }
}

fn at(second: i64) -> String {
    time::Timestamp::from_second(second).map_or_else(|_| second.to_string(), time::isoformat)
}

/// The receiver looks at its clock at `now`; `previous` is when it looked
/// before, its last heartbeat. Where a stretch at a time ahead begins or
/// ends, it gives the line for the journal, to [`say`] once the look is
/// kept.
pub(super) fn looked(
    db: &Connection,
    now: i64,
    previous: Option<i64>,
) -> Result<Option<(Level, String)>, SqliteError> {
    let before = kept(db)?;
    let looked = run_time::look(before, now, previous, PACE);
    keep(db, BELIEVED, looked.kept.believed)?;
    if looked.kept.ahead_for != before.ahead_for {
        keep(db, AHEAD_FOR, looked.kept.ahead_for)?;
    }
    Ok(looked.turn.map(|turn| match turn {
        Turn::Ahead { believed } => (
            Level::Warn,
            format!(
                "The receiver's clock reads {}, more than ten minutes after its own run time, \
                 {}: the clock went ahead, or the receiver paused. Old events are removed by \
                 the run time until the receiver has run at this time for a day, or the clock \
                 comes back.",
                at(now),
                at(believed)
            ),
        ),
        Turn::Back => (
            Level::Info,
            "The clock is back within ten minutes of the receiver's run time; old events are \
             removed by it again"
                .to_owned(),
        ),
        Turn::Held => (
            Level::Info,
            "The receiver has run for a day at its clock's new time; old events are removed \
             by the clock again"
                .to_owned(),
        ),
    }))
}

/// Writes what a look found to the journal.
pub(super) fn say(said: Option<(Level, String)>) {
    if let Some((level, line)) = said {
        log::log!(level, "{line}");
    }
}

/// The time to remove old events by at `now`: the run time while the clock
/// is ahead of it, also where it went ahead since the last look, else
/// `now`.
pub(super) fn cleaned_by(db: &Connection, now: i64) -> Result<i64, SqliteError> {
    let kept = kept(db)?;
    Ok(match (kept.believed, kept.ahead_for) {
        (Some(believed), Some(_)) => believed.min(now),
        (Some(believed), None) if now > believed.saturating_add(PACE.limit) => believed,
        _ => now,
    })
}

/// For tests that ask about something else: the time passed to `now` in the
/// receiver's looks, so that its clock is believed there.
#[cfg(test)]
pub(super) fn passed(db: &Connection, now: i64) -> rusqlite::Result<()> {
    keep(db, BELIEVED, Some(now))?;
    keep(db, AHEAD_FOR, None)
}
