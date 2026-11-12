//! The watch over the collector itself.
//!
//! Every notification comes out of a collection run, so a collector that no
//! longer runs reports nothing, its own end included. A timer of its own
//! starts this watch every few minutes. It reads when the last run finished
//! and tells the topic once when that is too long ago, and once when a run
//! has finished again.
//!
//! A collector usually stops because it no longer loads the configuration.
//! The watch must not depend on that file then: every run leaves the topic's
//! address in the status database, and the watch falls back on it.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use garrison_core::{sqlite, time};
use rusqlite::OptionalExtension;
use rustls::RootCertStore;

use crate::context::Memory;
use crate::notify::{Channels, Level, Note, Secrets, taken};

/// Where a run leaves the channel, in the collector's memory.
const CHANNEL: &str = "notify.channel";
/// The collector runs every minute. After this many seconds without a
/// finished run it counts as stopped.
pub const LIMIT: i64 = 600;
const BUDGET: Duration = Duration::from_secs(5);

/// Leave the channels for the watch, without their secrets; nothing where
/// none is configured.
pub fn remember(memory: &dyn Memory, channels: &Channels) {
    let text = if channels.is_empty() {
        String::new()
    } else {
        serde_json::to_string(channels).unwrap_or_default()
    };
    // Written only when it changes: the collector runs every minute.
    if memory.recall(CHANNEL).unwrap_or_default() != text {
        memory.keep(CHANNEL, &text);
    }
}

/// What one look at the collector found and did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// No run has ever finished: nothing to compare with.
    NeverRan,
    Running,
    /// Stopped; the channels know, or there is none to tell.
    Stopped,
    /// Stopped, and the channels were told just now.
    ToldStopped,
    /// A run finished again, and the channels were told just now.
    ToldRunning,
}

/// What a look needs.
#[derive(Debug)]
pub struct Watch<'a> {
    /// The status database, which the collector writes.
    pub database: &'a Path,
    /// The file that says the topic knows of the stop.
    pub marker: &'a Path,
    /// The channels of the configuration where that loads, empty for one
    /// without any; `Err` where it does not load.
    pub configured: Result<Channels, ()>,
    /// The secrets for the channels the last run left.
    pub secrets: Secrets,
    pub now: time::Timestamp,
    /// The authorities a channel's certificate is checked against.
    pub roots: Arc<RootCertStore>,
}

/// What the status database says of the collector.
#[derive(Debug, Default, PartialEq, Eq)]
struct Recorded {
    /// When the last run finished.
    last: Option<i64>,
    /// The channels that run left.
    channels: Channels,
}

/// The collector's record; the default where there is no database yet.
fn recorded(database: &Path) -> Result<Recorded, String> {
    let Some(reader) = sqlite::reading(database, BUDGET).map_err(|error| error.to_string())? else {
        return Ok(Recorded::default());
    };
    let last: Option<i64> = reader
        .query_row("SELECT MAX(collected_at) FROM snapshots", [], |row| {
            row.get(0)
        })
        .map_err(|error| error.to_string())?;
    let channel: Option<String> = reader
        .query_row("SELECT value FROM memory WHERE key=?", [CHANNEL], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|error| error.to_string())?;
    Ok(Recorded {
        last,
        channels: channel
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default(),
    })
}

fn at(second: i64) -> String {
    time::Timestamp::from_second(second).map_or_else(|_| second.to_string(), time::isoformat)
}

impl Watch<'_> {
    /// Look once. An error is a look that could not be finished, or a message
    /// that did not go out: the next look tries again.
    pub fn look(&self) -> Result<Outcome, String> {
        let recorded = recorded(self.database)?;
        let Some(last) = recorded.last else {
            return Ok(Outcome::NeverRan);
        };
        let channels = match &self.configured {
            Ok(channels) => channels.clone(),
            Err(()) => recorded.channels.with(self.secrets.clone()),
        };
        let stopped = self.now.as_second() - last > LIMIT;
        let told = fs::symlink_metadata(self.marker).is_ok();
        // A message counts once any channel took it.
        let send = |note: Note| match taken(&channels.send_with(&note, self.now, &self.roots)) {
            (true, _) => Ok(()),
            (false, problems) => Err(problems.unwrap_or_default()),
        };
        match (stopped, told, channels.is_empty()) {
            (true, false, false) => {
                send(Note::plain(
                    format!("Garrison on {}: the collector has stopped", channels.host),
                    format!(
                        "No collection run has finished since {}. Until one does, Garrison \
                         checks nothing and reports nothing else. On the host, `systemctl \
                         status garrison-collect.service` and `garrison check-config` say why.",
                        at(last)
                    ),
                    Level::Failed,
                ))?;
                fs::write(self.marker, self.now.as_second().to_string())
                    .map_err(|error| format!("{}: {error}", self.marker.display()))?;
                Ok(Outcome::ToldStopped)
            }
            (true, _, _) => Ok(Outcome::Stopped),
            (false, true, silent) => {
                if !silent {
                    send(Note::plain(
                        format!("Garrison on {}: the collector runs again", channels.host),
                        format!("A collection run finished at {}.", at(last)),
                        Level::Good,
                    ))?;
                }
                fs::remove_file(self.marker)
                    .map_err(|error| format!("{}: {error}", self.marker.display()))?;
                Ok(if silent {
                    Outcome::Running
                } else {
                    Outcome::ToldRunning
                })
            }
            (false, false, _) => Ok(Outcome::Running),
        }
    }
}

#[cfg(test)]
mod tests;
