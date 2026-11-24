//! The states the services and the watch write to the journal: why a
//! service ended, why a collection run collected nothing, and what one look
//! at the collector found.

use std::fmt::Display;
use std::path::Path;

use crate::state::State;

/// `name`: the service as its command is called (web, ingest, collector,
/// broker, milter); `error`: why it ended.
pub(crate) fn stopped(name: &str, error: impl Display) -> State {
    State::new(
        "service-stopped",
        format!("The {name} service stopped: {error}"),
    )
}

/// A collection run that found another under way, which stores what this
/// one would: it ends as a success.
pub(crate) fn collect_busy() -> State {
    State::new(
        "collect-busy",
        "Another collection run is under way; this one ends without collecting",
    )
}

/// The watch looks without a configuration that loads, with the paths the
/// units use and the channels the last run left.
pub(crate) fn watch_unloaded(path: &Path, error: impl Display) -> State {
    State::new(
        "watch-unloaded",
        format!(
            "{} does not load ({error}); watching with what the last collection run left",
            path.display()
        ),
    )
}

pub(crate) fn watch_not_known(database: &Path) -> State {
    State::new(
        "watch-not-known",
        format!(
            "Whether the collector runs is not known: the newest snapshot in {} is dated at a \
             time that is none",
            database.display()
        ),
    )
}

pub(crate) fn watch_never_ran() -> State {
    State::new("watch-never-ran", "No collection run has finished yet")
}

pub(crate) fn watch_running() -> State {
    State::new("watch-running", "The collector runs")
}

pub(crate) fn watch_stopped() -> State {
    State::new("watch-stopped", "The collector has stopped")
}

pub(crate) fn watch_told_stopped() -> State {
    State::new(
        "watch-told-stopped",
        "The collector has stopped; the channels were told",
    )
}

pub(crate) fn watch_told_running() -> State {
    State::new(
        "watch-told-running",
        "The collector runs again; the channels were told",
    )
}

pub(crate) fn watch_unfinished(error: impl Display) -> State {
    State::new(
        "watch-unfinished",
        format!("The watch over the collector did not finish: {error}"),
    )
}
