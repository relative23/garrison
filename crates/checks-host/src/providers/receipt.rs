//! Dated result files written by other jobs (backups, restore tests, monitors).
//!
//! A receipt is historical evidence: it states that a job reported a result at
//! a time. The provider never re-runs the job. Field selection is explicit, so
//! only configured values leave the file.
//!
//! ```toml
//! [[providers]]
//! type = "receipt"
//! id = "backup-local"
//! title = "Local full backup"
//! path = "/var/lib/backup/last-run.json"
//! modules = ["backups"]
//! date = "date"
//! max_age_hours = 30
//! fields = [{ key = "pauseSeconds", label = "Mail service pause", format = "duration" }]
//! ok_when = { key = "result", equals = ["passed"] }   # optional
//! ```

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use garrison_core::files::{changed_only_by_trusted, read_json_with_metadata};
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Observation, Required, State};
use garrison_core::time::Written;
use serde_json::Value;

use crate::context::{Collected, Context, HostPath, Provider, Report, Use};
use crate::options::{Checked, Options, fail};

mod keys;
mod shown;

use keys::{Condition, Key, Selected, date, key, lookup, selected};

const MAX_DOCUMENT: usize = 1024 * 1024;
/// The table of a list receipt shows this many rows, the last ones, where a
/// job that appends a row for each run puts the newest. Every row is judged.
const MAX_ROWS: usize = 200;
const DEFAULT_SCOPE: &str = "Historical result reported by the job; not a current test.";

#[derive(Debug)]
pub struct Receipt {
    id: String,
    title: String,
    path: PathBuf,
    modules: BTreeSet<ModuleId>,
    date: Key,
    max_age_hours: i64,
    fields: Vec<Selected>,
    scope: String,
    ok_when: Option<Condition>,
    ok_rows: Option<Condition>,
    /// The list of row objects; empty means the document itself is the list.
    rows: Option<Key>,
    columns: Vec<Selected>,
    /// For list documents the receipt date is the newest row date.
    row_date: Option<Key>,
}

impl Receipt {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(
            raw,
            &[
                "id",
                "title",
                "path",
                "modules",
                "date",
                "max_age_hours",
                "fields",
                "ok_when",
                "rows",
                "columns",
                "scope",
                "row_date",
                "ok_rows",
            ],
        )?;
        let id = options.text("id", None)?;
        let lowercase = id
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && id.len() <= 64
            && id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !lowercase {
            return fail("providers[receipt].id must be a lowercase identifier");
        }
        let title = options.text("title", None)?;
        let path = options.path("path", None)?;
        let modules = options.modules(&[])?;
        let default_date = toml::Value::from("date");
        let date = key(
            Some(raw.get("date").unwrap_or(&default_date)),
            "receipt.date",
        )?;
        let max_age_hours = options.integer("max_age_hours", 0, 0, 24 * 400)?;
        let fields = selected(&options, "fields")?;
        let scope = match raw.get("scope") {
            None => DEFAULT_SCOPE.to_owned(),
            Some(toml::Value::String(text)) => text.clone(),
            Some(_) => return fail("providers[receipt].scope must be text"),
        };
        let ok_when = Condition::parse(raw.get("ok_when"), "ok_when")?;
        let ok_rows = Condition::parse(raw.get("ok_rows"), "ok_rows")?;
        let rows = match raw.get("rows") {
            None => None,
            Some(toml::Value::Array(items)) if items.is_empty() => Some(Vec::new()),
            Some(value) => Some(key(Some(value), "receipt.rows")?),
        };
        let columns = if rows.is_some() {
            selected(&options, "columns")?
        } else {
            Vec::new()
        };
        let row_date = match raw.get("row_date") {
            Some(value) => Some(key(Some(value), "receipt.row_date")?),
            None => None,
        };
        Ok(Receipt {
            id,
            title,
            path,
            modules,
            date,
            max_age_hours,
            fields,
            scope,
            ok_when,
            ok_rows,
            rows,
            columns,
            row_date,
        })
    }

    /// The place that `rows` names in the document, for a receipt with rows.
    fn place<'a>(&self, document: &'a Value) -> Option<&'a Value> {
        let mut items = document;
        for part in self.rows.as_ref()? {
            items = items.get(part).unwrap_or(&Value::Null);
        }
        Some(items)
    }

    /// The rows of a receipt that has them: every one, however many, as the
    /// file is at most 1 MiB.
    fn items(&self, document: &Value) -> Option<Vec<Value>> {
        let list = self.place(document)?.as_array()?;
        Some(
            list.iter()
                .filter(|item| item.is_object())
                .cloned()
                .collect(),
        )
    }

    /// What a receipt with rows says where they cannot all be read, and the
    /// state it may have at most: Unknown where `rows` names no list, as
    /// where a job that failed early wrote none, and Partial where rows are
    /// no objects, which are not read.
    fn unread_rows(&self, document: &Value) -> Option<(State, String)> {
        let Some(list) = self.place(document)?.as_array() else {
            let why = if self.rows.as_ref().is_some_and(Vec::is_empty) {
                "The receipt is no list of rows."
            } else {
                "The receipt holds no list of rows where `rows` names one."
            };
            return Some((State::Unknown, why.to_owned()));
        };
        let (others, total) = (
            list.iter().filter(|item| !item.is_object()).count(),
            list.len(),
        );
        let finding = match others {
            0 => return None,
            1 => format!("1 of the receipt's {total} rows is no object and was not read."),
            _ => {
                format!("{others} of the receipt's {total} rows are no objects and were not read.")
            }
        };
        Some((State::Partial, finding))
    }

    fn reported(&self, document: &Value, items: Option<&[Value]>) -> Option<Written> {
        if !document.is_array() {
            return date(&lookup(document, &self.date));
        }
        let row_date = self.row_date.as_ref()?;
        let mut newest: Option<Written> = None;
        for item in items.unwrap_or_default() {
            if let Some(found) = date(&lookup(item, row_date))
                && newest.is_none_or(|known| found.instant > known.instant)
            {
                newest = Some(found);
            }
        }
        newest
    }
}

/// Two clocks may differ by this many seconds before a date counts as one
/// from the future.
const AHEAD: f64 = 300.0;

impl Receipt {
    /// What the receipt's age says against it, where it says anything: no
    /// date that reads, one from the future, or one beyond the limit.
    fn by_age(&self, age: Option<f64>) -> Option<(State, String)> {
        match age {
            None => Some((State::Unknown, "The receipt has no valid date.".to_owned())),
            // A date from the future is no fresh one: a clock is wrong.
            Some(seconds) if seconds < -AHEAD => Some((
                State::Warning,
                format!(
                    "The receipt is dated {:.0} minutes ahead of this host's clock; one of the \
                     two clocks is wrong, so its age is not known.",
                    -seconds / 60.0
                ),
            )),
            #[allow(clippy::cast_precision_loss)]
            Some(seconds)
                if self.max_age_hours > 0 && seconds > (self.max_age_hours * 3600) as f64 =>
            {
                Some((
                    State::Warning,
                    format!(
                        "The last receipt is older than {} hours.",
                        self.max_age_hours
                    ),
                ))
            }
            Some(_) => None,
        }
    }

    /// Why there is no receipt to read, with what mends it: none at its
    /// path, which a job of the operator's writes; a folder on the way that
    /// the collector's user may not search; a file it may not open, as one
    /// a job writes under umask 027 or 077; a link or no plain file; or a
    /// file too large or no JSON object or list.
    fn unread(&self) -> String {
        let path = self.path.display();
        let denied = |error: &std::io::Error| error.kind() == std::io::ErrorKind::PermissionDenied;
        match std::fs::symlink_metadata(&self.path) {
            Err(error) if denied(&error) => {
                // The deepest folder that can be looked at is the one that
                // cannot be searched.
                let folder = self
                    .path
                    .ancestors()
                    .skip(1)
                    .find(|folder| std::fs::symlink_metadata(folder).is_ok())
                    .unwrap_or(&self.path)
                    .display();
                format!(
                    "The receipt at {path} cannot be looked for: the collector's user may not \
                     search the folder {folder}; let every user search it (chmod o+x {folder})."
                )
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                format!("The receipt at {path} cannot be looked for: {error}.")
            }
            Err(_) => {
                format!("No receipt at {path}: the job that writes it has written none there.")
            }
            Ok(metadata) if metadata.is_symlink() => format!(
                "The receipt at {path} is a link, which is not followed: let the job write the \
                 file there itself."
            ),
            Ok(metadata) if !metadata.is_file() => format!(
                "The receipt at {path} is no plain file: let the job write it there as one."
            ),
            Ok(_) if std::fs::File::open(&self.path).is_err_and(|error| denied(&error)) => format!(
                "The receipt at {path} is there, but the collector's user may not open it: let \
                 the job write it with mode 0644 (chmod 0644 {path})."
            ),
            Ok(_) => format!(
                "The receipt at {path} cannot be read: it must be at most {} KiB of JSON, an \
                 object or a list.",
                MAX_DOCUMENT / 1024
            ),
        }
    }
}

impl Provider for Receipt {
    fn name(&self) -> &'static str {
        "receipt"
    }

    fn ids(&self) -> Vec<String> {
        vec![format!("receipt.{}", self.id)]
    }

    fn paths(&self) -> Vec<HostPath<'_>> {
        vec![HostPath {
            option: "path",
            path: &self.path,
            used: Use::Reads,
        }]
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let read = read_json_with_metadata(&self.path, MAX_DOCUMENT)
            .filter(|(value, _)| value.is_object() || value.is_array());
        let base = |state| {
            Observation::new(Required {
                id: &format!("receipt.{}", self.id),
                provider: self.name(),
                title: &self.title,
                modules: self.modules.iter().copied(),
                evidence: Evidence::Receipt,
                state,
                checked_at: &context.checked_at(),
                source: &self.path.display().to_string(),
            })
            .map(|observation| observation.with_scope(self.scope.clone()))
        };
        let Some((document, metadata)) = read else {
            let unknown = base(State::Unknown)?.with_findings(vec![self.unread()]);
            return Ok(Report::of(unknown));
        };
        // A result that someone else could have written is not evidence.
        let trusted = changed_only_by_trusted(&metadata);
        let items = self.items(&document);
        let reported = self.reported(&document, items.as_deref());
        let mut findings = Vec::new();
        let mut state = State::Ok;
        let age = reported.map(|written| context.seconds_since(written.instant));
        if let Some((by_age, finding)) = self.by_age(age) {
            state = by_age;
            findings.push(finding);
        }
        if self
            .ok_when
            .as_ref()
            .is_some_and(|condition| !condition.holds(&document))
        {
            state = State::Failed;
            findings.push("The recorded result is not a success.".to_owned());
        }
        let rows_fail = self
            .ok_rows
            .as_ref()
            .is_some_and(|condition| items.iter().flatten().any(|item| !condition.holds(item)));
        if rows_fail {
            state = State::Failed;
            findings.push("At least one recorded result is not a success.".to_owned());
        }
        // Rows that cannot be read are no rows in order.
        if let Some((at_most, finding)) = self.unread_rows(&document) {
            if state == State::Ok {
                state = at_most;
            }
            findings.push(finding);
        }
        if let Some(items) = items.as_ref().filter(|items| items.len() > MAX_ROWS) {
            findings.push(format!(
                "The receipt lists {} rows; the table shows the last {MAX_ROWS}.",
                items.len()
            ));
        }
        let fields = self.fields(&document, reported, &mut findings);
        let table = items.as_ref().map(|items| {
            let shown = &items[items.len().saturating_sub(MAX_ROWS)..];
            self.table(shown, &mut findings)
        });
        // Without a limit the receipt of a job that stopped running months
        // ago is as much in order as yesterday's: the card says so.
        if self.max_age_hours == 0 {
            findings.push(
                "No age limit is set (max_age_hours): this receipt stays in order however old \
                 it is."
                    .to_owned(),
            );
        }
        if !trusted {
            state = State::Unknown;
            findings.insert(
                0,
                format!(
                    "Users other than root can change this receipt (owner {}, mode {:04o}); \
                     its result is not trusted.",
                    metadata.uid(),
                    metadata.mode() & 0o7777
                ),
            );
        }
        let mut observation = base(state)?
            .with_fields(fields)
            .with_findings(findings)
            .with_max_age(900);
        if let Some(table) = table {
            observation = observation.with_table(table);
        }
        let mut report = Report::of(observation);
        if let Some(seconds) = age.filter(|_| trusted) {
            report
                .gauges
                .insert(format!("receipt_age_hours.{}", self.id), seconds / 3600.0);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod unread_tests;
