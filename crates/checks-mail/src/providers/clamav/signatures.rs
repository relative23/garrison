//! The card of the signature databases: when each file changed, and when
//! Fangfrisch last checked it.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Column, Evidence, Format, Observation, Required, State, Table};
use garrison_core::sqlite::reading;
use garrison_core::time;
use serde_json::json;

use super::Clamav;
use crate::context::{Context, Provider, ProviderError};

/// The daily signature database is older than this only where updates no
/// longer arrive: a new one is published every day.
const STALE_AFTER_HOURS: f64 = 48.0;
/// Two clocks may differ by this many hours before a file's time counts as
/// one from the future, of which no age is known.
const AHEAD_HOURS: f64 = 5.0 / 60.0;

impl Clamav {
    /// The card of the signature files, and the age in hours of the newest
    /// daily database that it judges, which the dashboard's gauge shows.
    pub(super) fn signatures(
        &self,
        context: &Context<'_>,
    ) -> Result<(Observation, Option<f64>), ProviderError> {
        let log = self
            .fangfrisch
            .as_deref()
            .map(|path| refresh_log(path, &self.signatures));
        let checked = log.as_ref().and_then(|read| read.as_ref().ok());
        let mut rows = Vec::new();
        // The newest daily database and its age in hours: the one file that
        // changes every day, and so the one that shows whether updates arrive.
        let mut daily: Option<(&str, f64)> = None;
        for name in &self.signatures {
            let Ok(info) = std::fs::metadata(self.database.join(name)) else {
                continue;
            };
            // The modification time with its fraction, in seconds.
            #[allow(clippy::cast_precision_loss)]
            let seconds = info.mtime() as f64 + info.mtime_nsec() as f64 * 1e-9;
            let modified = time::from_unix(seconds);
            if let Some(modified) = modified.filter(|_| name.starts_with("daily.")) {
                let hours = context.seconds_since(modified) / 3600.0;
                if daily.is_none_or(|(_, newest)| hours < newest) {
                    daily = Some((name.as_str(), hours));
                }
            }
            let modified = modified.map(time::isoformat);
            rows.push(vec![
                json!(name),
                json!(info.len()),
                json!(modified),
                json!(checked.and_then(|checks| checks.get(name))),
            ]);
        }
        let column = |label: &str, format| Column {
            label: label.to_owned(),
            format,
        };
        let (state, finding) = if rows.is_empty() {
            (State::Unknown, None)
        } else {
            current(daily)
        };
        let mut findings: Vec<String> = finding.into_iter().collect();
        // A refresh log that is named and cannot be read leaves its column
        // empty: the card says why, and is not in order for it.
        let state = match (&log, self.fangfrisch.as_deref()) {
            (Some(Err(why)), Some(path)) => {
                findings.push(format!(
                    "The Fangfrisch database {} could not be read: {why}; when it last checked \
                     each file is not known.",
                    path.display()
                ));
                if state == State::Ok {
                    State::Partial
                } else {
                    state
                }
            }
            _ => state,
        };
        let observation = Observation::new(Required {
            id: "clamav.signatures",
            provider: self.name(),
            title: "Signature databases",
            modules: [ModuleId::Antivirus],
            evidence: Evidence::Inventory,
            state,
            checked_at: &context.checked_at(),
            source: &self.database.display().to_string(),
        })?
        .with_scope("File times do not prove a successful update check or a loaded database.")
        .with_findings(findings)
        .with_table(Table {
            columns: vec![
                column("File", Format::Text),
                column("Size", Format::Bytes),
                column("Modified", Format::Datetime),
                column("Last refresh check", Format::Datetime),
            ],
            rows,
        })
        .with_max_age(900);
        let age = daily
            .map(|(_, hours)| hours)
            .filter(|hours| *hours >= -AHEAD_HOURS)
            .map(|hours| hours.max(0.0));
        Ok((observation, age))
    }
}

/// What the newest daily database, by its name and age in hours, says of
/// how current the signatures are: files that exist are not yet signatures
/// that are current.
fn current(daily: Option<(&str, f64)>) -> (State, Option<String>) {
    match daily {
        None => (
            State::Unknown,
            Some(
                "No daily signature database (daily.cld or daily.cvd) is among the files; how \
                 current the signatures are is not known."
                    .to_owned(),
            ),
        ),
        Some((name, hours)) if hours < -AHEAD_HOURS => (
            State::Warning,
            Some(format!(
                "{name} is dated {:.0} minutes ahead of this host's clock; one of the two clocks \
                 is wrong, so its age is not known.",
                -hours * 60.0
            )),
        ),
        Some((name, hours)) if hours > STALE_AFTER_HOURS => (
            State::Warning,
            Some(format!(
                "{name} was last updated {hours:.0} hours ago; ClamAV's signatures change every \
                 day, so the updates do not arrive."
            )),
        ),
        Some(_) => (State::Ok, None),
    }
}

/// When Fangfrisch last checked each of the files `listed`, by the file's
/// name, from the refresh log of its database at `path`; or why it could not
/// be read. The reader's time bounds the scan, and the names kept are the
/// listed ones, whatever the log's writer put there.
pub(in crate::providers) fn refresh_log(
    path: &Path,
    listed: &[String],
) -> Result<BTreeMap<String, String>, String> {
    let text = |error: rusqlite::Error| error.to_string();
    let db = reading(path, Duration::from_secs(2))
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "it is not there".to_owned())?;
    let mut statement = db
        .prepare("SELECT path, updated FROM refreshlog")
        .map_err(text)?;
    let mut rows = statement.query([]).map_err(text)?;
    let mut found = BTreeMap::new();
    while let Some(row) = rows.next().map_err(text)? {
        let path = sql_text(row.get::<_, rusqlite::types::Value>(0).map_err(text)?);
        let updated = sql_text(row.get::<_, rusqlite::types::Value>(1).map_err(text)?);
        // Fangfrisch writes UTC without saying so.
        let checked = time::parse_naive_utc(&updated).or_else(|| time::parse(&updated));
        let name = Path::new(&path)
            .file_name()
            .and_then(|file| file.to_str())
            .filter(|name| listed.iter().any(|file| file == name));
        if let (Some(name), Some(checked)) = (name, checked) {
            found
                .entry(name.to_owned())
                .or_insert_with(|| time::isoformat(checked));
        }
    }
    Ok(found)
}

fn sql_text(value: rusqlite::types::Value) -> String {
    match value {
        rusqlite::types::Value::Text(text) => text,
        rusqlite::types::Value::Integer(number) => number.to_string(),
        rusqlite::types::Value::Real(number) => number.to_string(),
        rusqlite::types::Value::Null => "null".to_owned(),
        rusqlite::types::Value::Blob(_) => String::new(),
    }
}
