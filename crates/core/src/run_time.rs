//! A time of a service's own, by which it removes what is old.
//!
//! A history is kept for a number of days. Counted from the host's clock, a
//! clock that jumps ahead takes with it what is still to be kept; a year
//! ahead, all of it. So a service that cleans up keeps a time of its own,
//! its run time: each step from one look at the clock to the next of at most
//! the limit moves it on by that step; a longer one, a pause or a jump,
//! moves it not at all. It cannot jump, so clean-up never stops: it lags at
//! most by the pauses not counted yet.
//!
//! The clock's time is believed, and taken as the run time, when it is at
//! most the limit after it, or before it: a clean-up by an earlier time
//! removes nothing more, and a clock put right after hours ahead is back
//! within the limit of the run time. A look further ahead cleans up by the
//! run time. A pause looks the same as a jump, so the clock's time is
//! believed once the service has run at it for the hold: each step of the
//! limit or less adds its length, a longer one adds one run, so that a
//! service that looks rarely finds its way back too, and a step back by
//! more than the limit, to another time still ahead, begins the hold again.

use crate::time;

/// What a service keeps between two looks: its run time, and for how long
/// it has run at a time ahead of it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kept {
    pub believed: Option<i64>,
    pub ahead_for: Option<i64>,
}

/// How a service's steps count, in seconds: the longest step that moves the
/// run time on, how long it runs at a time ahead before that time is
/// believed, and what a longer step counts towards that.
#[derive(Clone, Copy, Debug)]
pub struct Pace {
    pub limit: i64,
    pub hold: i64,
    pub run: i64,
}

/// What a look found changed, for the service's journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Turn {
    /// The clock is back within the limit of the run time.
    Back,
    /// The clock is more than the limit after the run time, `believed`: it
    /// went ahead, or the service paused.
    Ahead { believed: i64 },
    /// The service has run at the clock's new time for the hold.
    Held,
}

/// The time to clean up by at a look, what to keep for the next one, and
/// what changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Looked {
    pub by: i64,
    pub kept: Kept,
    pub turn: Option<Turn>,
}

/// `second` where it is a time at all; what a service kept is read as data.
fn when(second: i64) -> Option<i64> {
    time::Timestamp::from_second(second).ok().map(|_| second)
}

/// What the step from the look before, `previous`, to `now` adds to the run
/// time, and towards the hold; `None` begins the hold again.
fn step(previous: Option<i64>, now: i64, pace: Pace) -> (i64, Option<i64>) {
    match previous.map(|previous| now.saturating_sub(previous)) {
        Some(step) if (0..=pace.limit).contains(&step) => (step, Some(step)),
        // A step back within what a step forward may take is no time.
        Some(step) if (-pace.limit..0).contains(&step) => (0, Some(0)),
        Some(step) if step < 0 => (0, None),
        // A pause, a jump ahead, or no look before to hold it against.
        _ => (0, Some(pace.run)),
    }
}

/// The look at the clock at `now`, `previous` being when the service looked
/// before, with what it `kept` since.
#[must_use]
pub fn look(kept: Kept, now: i64, previous: Option<i64>, pace: Pace) -> Looked {
    let previous = previous.and_then(when);
    // A service that kept nothing yet has its look before to go by; the
    // very first look has nothing to hold the clock against.
    let Some(believed) = kept.believed.and_then(when).or(previous) else {
        let kept = Kept {
            believed: Some(now),
            ..kept
        };
        return Looked {
            by: now,
            kept,
            turn: None,
        };
    };
    let ahead = kept
        .ahead_for
        .filter(|ahead| (0..pace.hold).contains(ahead));
    if now <= believed.saturating_add(pace.limit) {
        return Looked {
            by: now,
            kept: Kept {
                believed: Some(now),
                ahead_for: if ahead.is_some() {
                    None
                } else {
                    kept.ahead_for
                },
            },
            turn: ahead.map(|_| Turn::Back),
        };
    }
    let (counted, towards) = step(previous, now, pace);
    let run_time = believed.saturating_add(counted);
    let Some(ahead) = ahead
        .zip(towards)
        .map(|(ahead, step)| ahead.saturating_add(step))
    else {
        return Looked {
            by: run_time,
            kept: Kept {
                believed: Some(run_time),
                ahead_for: Some(0),
            },
            turn: Some(Turn::Ahead { believed }),
        };
    };
    if ahead < pace.hold {
        return Looked {
            by: run_time,
            kept: Kept {
                believed: Some(run_time),
                ahead_for: Some(ahead),
            },
            turn: None,
        };
    }
    Looked {
        by: now,
        kept: Kept {
            believed: Some(now),
            ahead_for: None,
        },
        turn: Some(Turn::Held),
    }
}
