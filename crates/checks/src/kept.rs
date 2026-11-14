//! Answers a check asks for only now and then.
//!
//! Some answers cost too much to ask for in every run: a package manager
//! takes seconds, a blocklist learns every address it is asked about, a test
//! message lands in a mailbox. A check keeps such an answer in the status
//! database with the time it was asked, uses it until a new one is due, and
//! says so. The observation made from it is dated by the answer, not by the
//! run that repeats it, and goes stale once a newer answer is overdue. So
//! "checked" on a card is when the source was asked, and a card whose answer
//! stays old shows as stale even while the collector runs.
//!
//! What is kept is JSON under a key of the collector's memory: the answer's
//! own fields with `at`, the second it was asked at, beside them. Nothing
//! may depend on it being there; what is lost is asked for again.

use garrison_core::observations::Observation;
use garrison_core::time::{self, Timestamp};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::context::Context;

/// How long after a new answer was due an observation made from the old one
/// is stale: three collection runs, as for what is read in every run.
pub const LATE: i64 = 180;

/// An answer as the memory holds it.
#[derive(Deserialize, Serialize)]
struct Stored<T> {
    at: i64,
    #[serde(flatten)]
    answer: T,
}

/// An answer, when it was asked and for how long it is used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept<T> {
    /// The second the answer was asked at.
    pub at: i64,
    /// The seconds from then until it is asked again; 0 for the next run.
    pub wait: i64,
    pub answer: T,
}

impl<T> Kept<T> {
    /// When the answer was asked, as an observation states a time.
    pub fn asked(&self) -> Option<String> {
        Timestamp::from_second(self.at).ok().map(time::isoformat)
    }

    /// `observation`, dated by this answer: checked when it was asked, and
    /// stale once the next answer is [`LATE`].
    #[must_use]
    pub fn dated(&self, mut observation: Observation) -> Observation {
        if let Some(asked) = self.asked() {
            observation.checked_at = asked;
        }
        let age = self.wait.max(0).saturating_add(LATE);
        observation.with_max_age(u32::try_from(age).unwrap_or(u32::MAX))
    }
}

/// What the memory holds under `key` and when it was asked, if it reads as
/// a `T`.
pub fn recalled<T: DeserializeOwned>(context: &Context<'_>, key: &str) -> Option<(i64, T)> {
    let text = context.memory.recall(key)?;
    let stored: Stored<T> = serde_json::from_str(&text).ok()?;
    Some((stored.at, stored.answer))
}

/// Keep `answer`, asked in this run, under `key`.
pub fn keep<T: Serialize>(context: &Context<'_>, key: &str, answer: &T) {
    let stored = Stored {
        at: context.now.as_second(),
        answer,
    };
    if let Ok(text) = serde_json::to_string(&stored) {
        context.memory.keep(key, &text);
    }
}

/// The answer kept under `key` while it is used, or a new one from `ask`,
/// which is kept in its place.
///
/// `wait` says for how many seconds an answer is used, given when it was
/// asked: its usual time, a shorter one for a failure that is worth another
/// try soon, 0 for an answer that no longer fits what is asked. An answer
/// from ahead of the clock is not used. `ask` gets what was kept before and
/// when it was asked, however old it is, for a check that carries something
/// over a failed try.
pub fn cached<T: Serialize + DeserializeOwned>(
    context: &Context<'_>,
    key: &str,
    wait: impl Fn(i64, &T) -> i64,
    ask: impl FnOnce(Option<(i64, T)>) -> T,
) -> Kept<T> {
    let now = context.now.as_second();
    let before = match recalled::<T>(context, key) {
        Some((at, answer)) => {
            let wait = wait(at, &answer);
            if (0..wait).contains(&now.saturating_sub(at)) {
                return Kept { at, wait, answer };
            }
            Some((at, answer))
        }
        None => None,
    };
    let answer = ask(before);
    keep(context, key, &answer);
    Kept {
        at: now,
        wait: wait(now, &answer),
        answer,
    }
}

#[cfg(test)]
mod tests;
