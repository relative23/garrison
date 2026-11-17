//! The keys a receipt's options name, the values at them, and the
//! conditions a value must meet.

use garrison_core::observations::Format;
use garrison_core::time::{self, Written};
use serde_json::{Value, json};

use crate::options::{Checked, Options, fail};
use crate::values::{from_toml, loosely_equal};

const MAX_TEXT: usize = 300;

/// A path into nested objects: one key or up to six.
pub(super) type Key = Vec<String>;

pub(super) fn key(value: Option<&toml::Value>, name: &str) -> Checked<Key> {
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
pub(super) fn lookup(document: &Value, key: &[String]) -> Value {
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
pub(super) fn date(value: &Value) -> Option<Written> {
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

pub(super) fn format_of(name: &str) -> Option<Format> {
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
pub(super) struct Selected {
    pub(super) key: Key,
    pub(super) label: String,
    pub(super) format: Format,
}

pub(super) fn selected(options: &Options<'_>, list: &str) -> Checked<Vec<Selected>> {
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
pub(super) struct Condition {
    pub(super) key: Key,
    equals: Vec<Value>,
}

impl Condition {
    pub(super) fn parse(value: Option<&toml::Value>, name: &str) -> Checked<Option<Self>> {
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

    pub(super) fn holds(&self, document: &Value) -> bool {
        let value = lookup(document, &self.key);
        self.equals
            .iter()
            .any(|allowed| loosely_equal(&value, allowed))
    }
}
