//! The watch over the collector itself.
//!
//! Every notification comes out of a collection run, so a collector that no
//! longer runs reports nothing, its own end included. A timer of its own
//! starts this watch every few minutes. It reads when the last run finished
//! and tells the topic once when that is too long ago, and once when a run
//! has finished again.
//!
//! A collector usually stops because it no longer loads the configuration.
//! The watch must not depend on that file then: every run leaves the
//! channels in the status database, and the watch falls back on them. An
//! address that is kept in a file is left as the name of that file, which
//! the watch reads again.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use garrison_core::credentials::Credentials;
use garrison_core::{sqlite, time};
use rusqlite::{Connection, OptionalExtension};
use rustls::RootCertStore;

use crate::context::{Deadline, Memory};
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
    /// The newest snapshot is dated at a time that is none, or no snapshot
    /// is dated with a number, as in a damaged or hand-edited status
    /// database: whether the collector runs is not known, and nobody is told
    /// either way.
    NotKnown,
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
    /// Where those channels' files are, for an address kept in one.
    pub credentials: Credentials,
    pub now: time::Timestamp,
    /// The authorities a channel's certificate is checked against.
    pub roots: Arc<RootCertStore>,
}

/// What the status database says of the collector.
#[derive(Debug, Default, PartialEq, Eq)]
struct Recorded {
    /// When the last run finished, where a run did.
    last: Option<Finished>,
    /// The channels that run left.
    channels: Channels,
}

/// When the last run finished, as the snapshots say it.
#[derive(Debug, PartialEq, Eq)]
enum Finished {
    /// The newest of the snapshots dated with a number, a Unix second.
    At(i64),
    /// There are snapshots, but none is dated with a number, as in a
    /// damaged or hand-edited status database: when is not known.
    NoTime,
}

/// When the newest snapshot was written: when the last run finished. What
/// the database holds is data: a snapshot dated with text, bytes or a
/// fraction, which the collector never writes, gives no time.
fn finished(db: &Connection) -> rusqlite::Result<Option<Finished>> {
    let (newest, all): (Option<i64>, i64) = db.query_row(
        "SELECT MAX(collected_at) FILTER (WHERE typeof(collected_at) = 'integer'), count(*) \
         FROM snapshots",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(match (newest, all) {
        (Some(at), _) => Some(Finished::At(at)),
        (None, 0) => None,
        (None, _) => Some(Finished::NoTime),
    })
}

/// When the last collection run finished, as a Unix second; `None` before
/// the first one, also where there is no database yet. `garrison doctor`
/// asks this, so that both judge the collector the same way.
pub fn last_run(database: &Path) -> Result<Option<i64>, String> {
    let Some(reader) = sqlite::reading(database, BUDGET).map_err(|error| error.to_string())? else {
        return Ok(None);
    };
    match finished(&reader).map_err(|error| error.to_string())? {
        None => Ok(None),
        Some(Finished::At(at)) => Ok(Some(at)),
        Some(Finished::NoTime) => Err("no snapshot in it is dated with a number".to_owned()),
    }
}

/// Whether a collector whose last run finished at `last` has stopped by
/// `now`; `None` where `last` is no time, which a status database that was
/// damaged or edited by hand may hold.
#[must_use]
pub fn stopped(last: i64, now: time::Timestamp) -> Option<bool> {
    let last = time::Timestamp::from_second(last).ok()?;
    Some(now.as_second() - last.as_second() > LIMIT)
}

/// The collector's record; the default where there is no database yet.
fn recorded(database: &Path) -> Result<Recorded, String> {
    let Some(reader) = sqlite::reading(database, BUDGET).map_err(|error| error.to_string())? else {
        return Ok(Recorded::default());
    };
    let last = finished(&reader).map_err(|error| error.to_string())?;
    // Channels left in a form that is no text are none.
    let channel: Option<String> = reader
        .query_row("SELECT value FROM memory WHERE key=?", [CHANNEL], |row| {
            Ok(crate::store::as_written(row.get_ref(0)?))
        })
        .optional()
        .map_err(|error| error.to_string())?
        .flatten();
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
        let last = match recorded.last {
            None => return Ok(Outcome::NeverRan),
            Some(Finished::NoTime) => return Ok(Outcome::NotKnown),
            Some(Finished::At(last)) => last,
        };
        let channels = match &self.configured {
            Ok(channels) => channels.clone(),
            Err(()) => recorded
                .channels
                .with(self.secrets.clone())
                .located(&self.credentials),
        };
        let Some(stopped) = stopped(last, self.now) else {
            return Ok(Outcome::NotKnown);
        };
        let told = fs::symlink_metadata(self.marker).is_ok();
        // A message counts once any channel took it.
        let send = |note: Note| match taken(&channels.send_with(
            &note,
            self.now,
            &self.roots,
            Deadline::NONE,
        )) {
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
