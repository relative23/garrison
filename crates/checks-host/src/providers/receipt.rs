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
use std::time::Instant;

use garrison_core::files::changed_only_by_trusted;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Observation, Required, State};
use garrison_core::time::Written;
use serde_json::Value;

use super::ran::patience;
use crate::context::{Collected, Context, HostPath, Provider, Report, Use};
use crate::options::{Checked, Options, fail};

mod keys;
mod shown;
mod unread;

use keys::{Condition, Key, Selected, date, key, lookup, selected};

const MAX_DOCUMENT: usize = 1024 * 1024;
/// The table of a list receipt shows this many rows, the last ones, where a
/// job that appends a row for each run puts the newest. Every row is judged.
const MAX_ROWS: usize = 200;
const DEFAULT_SCOPE: &str = "Historical result reported by the job; not a current test.";

/// Refuses the options that a receipt of this shape would not read.
fn unused(options: &Options<'_>, rows: Option<&Key>) -> Checked<()> {
    let found = |names: [&'static str; 3]| names.into_iter().find(|name| options.has(name));
    match rows {
        None => match found(["columns", "ok_rows", "row_date"]) {
            Some(name) => fail(format!("providers[receipt].{name} needs rows")),
            None => Ok(()),
        },
        Some(key) if !key.is_empty() && options.has("row_date") => fail(
            "providers[receipt].row_date is only for rows = []; rows under a key take the \
             receipt's date from date",
        ),
        Some(key) if !key.is_empty() => Ok(()),
        Some(_) => match found(["fields", "ok_when", "date"]) {
            Some(name) => fail(format!(
                "providers[receipt].{name} reads an object, but rows = [] reads a list; use \
                 columns, ok_rows and row_date"
            )),
            None if !options.has("row_date") => {
                fail("providers[receipt] with rows = [] needs row_date, the key of each row's date")
            }
            None => Ok(()),
        },
    }
}

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
        unused(&options, rows.as_ref())?;
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

    /// What a receipt with rows says where they cannot all be read or
    /// judged, and the state it may have at most: Unknown where `rows` names
    /// no list, as where a job that failed early wrote none, or where
    /// `ok_rows` found no row to judge, as in an empty list, and Partial
    /// where rows are no objects, which are not read.
    fn unread_rows(&self, document: &Value) -> Option<(State, String)> {
        let Some(list) = self.place(document)?.as_array() else {
            let why = "The receipt holds no list of rows where `rows` names one.";
            return Some((State::Unknown, why.to_owned()));
        };
        let (others, total) = (
            list.iter().filter(|item| !item.is_object()).count(),
            list.len(),
        );
        let judged_none = self.ok_rows.is_some() && others == total;
        let finding = match others {
            0 if judged_none => "The receipt lists no rows, so `ok_rows` judged none.".to_owned(),
            0 => return None,
            1 => format!("1 of the receipt's {total} rows is no object and was not read."),
            _ => {
                format!("{others} of the receipt's {total} rows are no objects and were not read.")
            }
        };
        let at_most = if judged_none {
            State::Unknown
        } else {
            State::Partial
        };
        Some((at_most, finding))
    }

    /// What the card says of a receipt of the other shape than its entry
    /// reads, a list for an entry that reads an object or the other way
    /// round, which it does not judge.
    fn misshapen(&self, document: &Value) -> Option<String> {
        let path = self.path.display();
        match (
            document.is_array(),
            self.rows.as_ref().is_some_and(Vec::is_empty),
        ) {
            (true, false) => Some(format!(
                "The receipt at {path} is a list, but its entry reads an object: read a list \
                 with rows = [] and row_date, as checks.md shows."
            )),
            (false, true) => Some(format!(
                "The receipt at {path} is an object, but rows = [] reads a list: name the key \
                 of its list in rows, such as rows = [\"results\"], or leave rows out to read \
                 the object."
            )),
            _ => None,
        }
    }

    /// What the card says where its table cannot show every row it read
    /// (`items`): how many rows the receipt lists, those that are no
    /// objects among them, and which the table shows.
    fn cut(&self, document: &Value, items: &[Value]) -> Option<String> {
        if items.len() <= MAX_ROWS {
            return None;
        }
        let listed = self
            .place(document)
            .and_then(Value::as_array)
            .map_or(items.len(), Vec::len);
        let read = if listed == items.len() {
            String::new()
        } else {
            format!(" of the {} it read", items.len())
        };
        Some(format!(
            "The receipt lists {listed} rows; the table shows the last {MAX_ROWS}{read}."
        ))
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
        self.card(context, patience())
    }
}

impl Receipt {
    /// The card, with the receipt read by `until`.
    fn card(&self, context: &Context<'_>, until: Instant) -> Collected {
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
        let (document, metadata) = match self.read(until) {
            Ok(read) => read,
            Err(why) => return Ok(Report::of(base(State::Unknown)?.with_findings(vec![why]))),
        };
        if let Some(finding) = self.misshapen(&document) {
            return Ok(Report::of(
                base(State::Unknown)?.with_findings(vec![finding]),
            ));
        }
        // A result that someone else could have written is not evidence.
        let trusted = changed_only_by_trusted(&metadata);
        let items = self.items(&document);
        let reported = self.reported(&document, items.as_deref());
        let mut findings = Vec::new();
        let mut state = State::Ok;
        // What makes the card failed comes first, before an age that alone
        // would make it a warning: a notification carries the first finding.
        let mut failed = 0;
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
            findings.insert(failed, "The recorded result is not a success.".to_owned());
            failed += 1;
        }
        let rows_fail = self
            .ok_rows
            .as_ref()
            .is_some_and(|condition| items.iter().flatten().any(|item| !condition.holds(item)));
        if rows_fail {
            state = State::Failed;
            let rows = "At least one recorded result is not a success.";
            findings.insert(failed, rows.to_owned());
        }
        // Rows that cannot be read are no rows in order.
        if let Some((at_most, finding)) = self.unread_rows(&document) {
            if state == State::Ok {
                state = at_most;
            }
            findings.push(finding);
        }
        findings.extend(
            items
                .as_deref()
                .and_then(|items| self.cut(&document, items)),
        );
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
mod rows_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod unread_tests;
