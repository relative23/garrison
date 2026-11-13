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
use garrison_core::observations::{Column, Evidence, Field, Format, Observation, State, Table};
use garrison_core::time::{self, Written};
use serde_json::{Value, json};

use crate::context::{Collected, Context, Provider, Report};
use crate::options::{Checked, Options, fail};
use crate::values::{from_toml, loosely_equal};

const MAX_DOCUMENT: usize = 1024 * 1024;
const MAX_TEXT: usize = 300;
const MAX_ROWS: usize = 200;
const DEFAULT_SCOPE: &str = "Historical result reported by the job; not a current test.";

/// A path into nested objects: one key or up to six.
type Key = Vec<String>;

fn key(value: Option<&toml::Value>, name: &str) -> Checked<Key> {
    let valid = |part: &str| {
        (1..=120).contains(&part.chars().count())
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_@/.:-".contains(&byte))
    };
    let parts: Option<Key> = match value {
        Some(toml::Value::String(text)) => Some(vec![text.clone()]),
        Some(toml::Value::Array(items)) if (1..=6).contains(&items.len()) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => None,
    };
    match parts {
        Some(parts) if parts.iter().all(|part| valid(part)) => Ok(parts),
        _ => fail(format!("{name} must be a key or a list of keys")),
    }
}

/// The value at `key`: scalars as they are (text truncated), lists by their length.
fn lookup(document: &Value, key: &[String]) -> Value {
    let mut current = document;
    for part in key {
        let Value::Object(map) = current else {
            return Value::Null;
        };
        current = map.get(part).unwrap_or(&Value::Null);
    }
    match current {
        Value::String(text) => Value::String(text.chars().take(MAX_TEXT).collect()),
        Value::Array(items) => json!(items.len()),
        Value::Object(_) => Value::Null,
        scalar => scalar.clone(),
    }
}

/// A timestamp with a zone, or a plain date taken as 00:00 UTC. A timestamp
/// without a zone is ambiguous and therefore not accepted.
fn date(value: &Value) -> Option<Written> {
    let text = value.as_str()?;
    let plain = text.len() == 10
        && text.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        });
    if plain {
        return time::parse_written(&format!("{text}T00:00:00+00:00"));
    }
    time::parse_written(text)
}

fn format_of(name: &str) -> Option<Format> {
    Some(match name {
        "text" => Format::Text,
        "number" => Format::Number,
        "bytes" => Format::Bytes,
        "datetime" => Format::Datetime,
        "duration" => Format::Duration,
        "boolean" => Format::Boolean,
        "url" => Format::Url,
        _ => return None,
    })
}

#[derive(Debug)]
struct Selected {
    key: Key,
    label: String,
    format: Format,
}

fn selected(options: &Options<'_>, list: &str) -> Checked<Vec<Selected>> {
    let mut result = Vec::new();
    for item in options.tables(list)? {
        let label = item.get("label").and_then(toml::Value::as_str);
        let format = match item.get("format") {
            None => Some(Format::Text),
            Some(value) => value.as_str().and_then(format_of),
        };
        let extra = item
            .keys()
            .any(|name| !["key", "label", "format"].contains(&name.as_str()));
        let (Some(label), Some(format), false) = (label, format, extra) else {
            return fail(format!(
                "providers[{}].{list} entries need key, label, format",
                options.kind
            ));
        };
        let key = key(item.get("key"), &format!("{}.{list}.key", options.kind))?;
        result.push(Selected {
            key,
            label: label.to_owned(),
            format,
        });
    }
    Ok(result)
}

/// `{ key = …, equals = […] }`: the value at `key` must equal one of `equals`.
#[derive(Debug)]
struct Condition {
    key: Key,
    equals: Vec<Value>,
}

impl Condition {
    fn parse(value: Option<&toml::Value>, name: &str) -> Checked<Option<Self>> {
        let Some(value) = value else {
            return Ok(None);
        };
        let table = value.as_table().filter(|table| {
            table.len() == 2 && table.contains_key("key") && table.contains_key("equals")
        });
        let Some(toml::Value::Array(equals)) = table.and_then(|table| table.get("equals")) else {
            return fail(format!("providers[receipt].{name} needs key and equals"));
        };
        Ok(Some(Condition {
            key: key(
                table.and_then(|table| table.get("key")),
                &format!("{name}.key"),
            )?,
            equals: equals.iter().map(from_toml).collect(),
        }))
    }

    fn holds(&self, document: &Value) -> bool {
        let value = lookup(document, &self.key);
        self.equals
            .iter()
            .any(|allowed| loosely_equal(&value, allowed))
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

    fn items(&self, document: &Value) -> Option<Vec<Value>> {
        let mut items = document;
        for part in self.rows.as_ref()? {
            items = items.get(part).unwrap_or(&Value::Null);
        }
        let list = items.as_array()?;
        Some(
            list.iter()
                .take(MAX_ROWS)
                .filter(|item| item.is_object())
                .cloned()
                .collect(),
        )
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

    fn table(&self, items: &[Value]) -> Table {
        Table {
            columns: self
                .columns
                .iter()
                .map(|column| Column {
                    label: column.label.clone(),
                    format: column.format,
                })
                .collect(),
            rows: items
                .iter()
                .map(|item| {
                    self.columns
                        .iter()
                        .map(|column| lookup(item, &column.key))
                        .collect()
                })
                .collect(),
        }
    }
}

impl Provider for Receipt {
    fn name(&self) -> &'static str {
        "receipt"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let read = read_json_with_metadata(&self.path, MAX_DOCUMENT)
            .filter(|(value, _)| value.is_object() || value.is_array());
        let base = |state| {
            Observation::new(
                format!("receipt.{}", self.id),
                self.name(),
                self.title.clone(),
                self.modules.iter().copied(),
                Evidence::Receipt,
                state,
                context.checked_at(),
                self.path.display().to_string(),
            )
            .map(|observation| observation.with_scope(self.scope.clone()))
        };
        let Some((document, metadata)) = read else {
            let unknown = base(State::Unknown)?.with_findings(vec!["No readable receipt.".into()]);
            return Ok(Report::of(unknown));
        };
        // A result that someone else could have written is not evidence.
        let trusted = changed_only_by_trusted(&metadata);
        let items = self.items(&document);
        let reported = self.reported(&document, items.as_deref());
        let mut findings = Vec::new();
        let mut state = State::Ok;
        let age = reported.map(|written| context.seconds_since(written.instant));
        match age {
            None => {
                state = State::Unknown;
                findings.push("The receipt has no valid date.".to_owned());
            }
            #[allow(clippy::cast_precision_loss)]
            Some(seconds)
                if self.max_age_hours > 0 && seconds > (self.max_age_hours * 3600) as f64 =>
            {
                state = State::Warning;
                findings.push(format!(
                    "The last receipt is older than {} hours.",
                    self.max_age_hours
                ));
            }
            Some(_) => {}
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
        let mut fields = vec![Field::new(
            "Reported at",
            reported.map(time::isoformat_written),
            Format::Datetime,
        )];
        if document.is_object() {
            fields.extend(self.fields.iter().map(|field| {
                Field::new(
                    field.label.clone(),
                    lookup(&document, &field.key),
                    field.format,
                )
            }));
        }
        let mut observation = base(state)?
            .with_fields(fields)
            .with_findings(findings)
            .with_max_age(900);
        if let Some(items) = &items {
            observation = observation.with_table(self.table(items));
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
