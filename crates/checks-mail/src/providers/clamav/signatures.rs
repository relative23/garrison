//! The card of the signature databases: when each file changed, when
//! Fangfrisch last checked it, and for a daily database that is days old
//! whether `ClamAV` has published a newer one.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::SocketAddr;
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
use crate::dns::{self, Answer, Kind};

/// A daily signature database older than this is held against the newest
/// one `ClamAV` has published: most days bring one, but not every day.
const STALE_AFTER_HOURS: f64 = 48.0;
/// Where `ClamAV` names its newest databases, the record freshclam asks
/// before it downloads: `1.4.7:63:28194:...`, the engine, then the versions
/// of the main and the daily database.
const NEWEST: &str = "current.cvd.clamav.net";
/// Two clocks may differ by this many hours before a file's time counts as
/// one from the future, of which no age is known.
const AHEAD_HOURS: f64 = 5.0 / 60.0;

impl Clamav {
    /// Why no listed signature file was found, where a look at `name` was
    /// `refused` for another reason than that it is not there: another path
    /// mends only files that are not there.
    fn none_found(&self, refused: Option<(&String, std::io::Error)>) -> String {
        let directory = self.database.display();
        match refused {
            Some((name, error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                let path = self.database.join(name);
                let folder = path
                    .ancestors()
                    .skip(1)
                    .find(|folder| std::fs::symlink_metadata(folder).is_ok())
                    .unwrap_or(&self.database)
                    .display();
                format!(
                    "The signature files in {directory} cannot be looked for: the collector's \
                     user may not search the folder {folder}; let every user search it (chmod \
                     o+x {folder})."
                )
            }
            Some((_, error)) => {
                format!("The signature files in {directory} cannot be looked for: {error}.")
            }
            None => format!(
                "None of the listed signature files is in {directory}: set `database_directory` \
                 to clamd's, which `garrison detect --format toml` names, or `signatures` to the \
                 files it holds."
            ),
        }
    }

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
        // Why a look at a file failed where the file may be there.
        let mut refused = None;
        for name in &self.signatures {
            let info = match std::fs::metadata(self.database.join(name)) {
                Ok(info) => info,
                Err(error) => {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        refused.get_or_insert((name, error));
                    }
                    continue;
                }
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
            (State::Unknown, Some(self.none_found(refused)))
        } else {
            current(daily, |name| self.behind(name))
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

    /// By which versions the daily database `name` is behind: the one its
    /// own header names and the newer one `ClamAV` has published, or none
    /// where it is the newest there is. `Err` says why that is not known.
    fn behind(&self, name: &str) -> Result<Option<(u32, u32)>, String> {
        let held = held(&self.database.join(name)).ok_or("the file names no version of its own")?;
        let resolver = self
            .resolver
            .or_else(|| dns::system_resolver(None))
            .ok_or("this host names no resolver in /etc/resolv.conf")?;
        let published = published(resolver)?;
        Ok((held < published).then_some((held, published)))
    }
}

/// The version a `ClamAV` database names in its own header, the third field
/// of `ClamAV-VDB:25 Nov 2026 06-26 +0000:28194:...`.
fn held(path: &Path) -> Option<u32> {
    // A named pipe would hold the open until a writer came.
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut header = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(512)
        .read_to_end(&mut header)
        .ok()?;
    let mut fields = header.split(|byte| *byte == b':');
    if fields.next()? != b"ClamAV-VDB" {
        return None;
    }
    std::str::from_utf8(fields.nth(1)?).ok()?.parse().ok()
}

/// The version of the newest daily database `ClamAV` has published, as its
/// record at [`NEWEST`] names it to `resolver`, or why it is not known.
fn published(resolver: SocketAddr) -> Result<u32, String> {
    let records = match dns::ask(resolver, NEWEST, Kind::Txt).map_err(|error| error.to_string())? {
        Answer::Records(records) => records,
        Answer::NoSuchName => Vec::new(),
    };
    records
        .iter()
        .find_map(|record| record.split(':').nth(2)?.parse().ok())
        .ok_or_else(|| format!("{NEWEST} names no version"))
}

/// What the newest daily database, by its name and age in hours, says of
/// how current the signatures are: files that exist are not yet signatures
/// that are current. One that is days old is current where `behind` finds
/// that `ClamAV` has published none since; it is asked of no other.
fn current(
    daily: Option<(&str, f64)>,
    behind: impl FnOnce(&str) -> Result<Option<(u32, u32)>, String>,
) -> (State, Option<String>) {
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
        Some((name, hours)) if hours > STALE_AFTER_HOURS => match behind(name) {
            Ok(None) => (State::Ok, None),
            Ok(Some((held, published))) => (
                State::Warning,
                Some(format!(
                    "{name} was last updated {hours:.0} hours ago and is version {held}; ClamAV \
                     has published version {published} since, so the updates do not arrive."
                )),
            ),
            Err(why) => (
                State::Warning,
                Some(format!(
                    "{name} was last updated {hours:.0} hours ago; whether ClamAV has published \
                     a newer one since is not known: {why}."
                )),
            ),
        },
        Some(_) => (State::Ok, None),
    }
}

/// When Fangfrisch last checked each of the files `listed`, by the file's
/// name, from the refresh log of its database at `path`; or why it could not
/// be read. The reader's time bounds the scan, and the names kept are the
/// listed ones, whatever the log's writer put there.
fn refresh_log(path: &Path, listed: &[String]) -> Result<BTreeMap<String, String>, String> {
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

#[cfg(test)]
mod tests;
