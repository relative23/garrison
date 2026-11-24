//! The version Stalwart reported at its last recorded start, and whether a
//! later start may have gone unrecorded.

use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Kind, Observation, State};
use garrison_core::recording::{self, QUIET_AFTER};
use garrison_core::sqlite::reading;
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{Map, json};

use super::Stalwart;
use crate::context::{Context, ProviderError};

/// The fields of a recorded `server.startup` event that are read.
#[derive(Deserialize)]
struct Startup {
    version: String,
}

/// The version the running server reported at its last recorded start, and
/// when that was.
pub(in crate::providers) fn running_version(context: &Context<'_>) -> Option<(String, i64)> {
    let (started, fields): (i64, String) =
        reading(&context.events_database, Duration::from_secs(2))
            .ok()
            .flatten()
            .and_then(|db| {
                db.query_row(
                    "SELECT created_at, fields FROM events WHERE type='server.startup' \
                     ORDER BY created_at DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .ok()
                .flatten()
            })?;
    let Startup { version } = serde_json::from_str(&fields).ok()?;
    let valid = (1..=40).contains(&version.len())
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte));
    valid.then_some((version, started))
}

/// Why a start of Stalwart after `started` may be missing in the event
/// history, where it may: the receiver does not report, or it lost events
/// since. `None` says the recorded start is the last one.
fn later_start_unrecorded(context: &Context<'_>, started: i64) -> Option<String> {
    let db = reading(&context.events_database, Duration::from_secs(2))
        .ok()
        .flatten()?;
    match recording::uncovered(&db, started, context.now.as_second(), QUIET_AFTER) {
        Ok(reason) => reason.map(|reason| reason.to_string()),
        Err(error) => Some(format!(
            "what the event receiver recorded about itself cannot be read ({error})"
        )),
    }
}

impl Stalwart {
    /// The version from the last recorded `server.startup` event.
    pub(super) fn version(context: &Context<'_>) -> Result<Observation, ProviderError> {
        let found = running_version(context);
        let scope = if found.is_some() {
            "Version reported by the running server at its last recorded start."
        } else {
            "No server start has been recorded since the event webhook was enabled."
        };
        let mut value = Map::new();
        value.insert("component".into(), json!("Stalwart"));
        value.insert(
            "version".into(),
            json!(found.as_ref().map(|(version, _)| version)),
        );
        value.insert(
            "startedAt".into(),
            json!(found.as_ref().map(|(_, started)| started)),
        );
        // The recorded start is the running server only while every later
        // start would have been recorded too.
        let unrecorded = found
            .as_ref()
            .and_then(|(_, started)| later_start_unrecorded(context, *started));
        Ok(Self::observation(
            context,
            "version.stalwart",
            "Stalwart",
            &[ModuleId::Dashboard, ModuleId::Services],
            Evidence::Process,
            if found.is_some() && unrecorded.is_none() {
                State::Ok
            } else {
                State::Unknown
            },
            "server.startup event",
        )?
        .with_kind(Kind::Version)
        .with_scope(scope)
        .with_value(value)
        .with_findings(
            unrecorded
                .map(|reason| format!("A later start of Stalwart may not be recorded: {reason}."))
                .into_iter()
                .collect(),
        )
        .with_max_age(3600))
    }
}
