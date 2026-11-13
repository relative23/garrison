//! Typed access to one `[[providers]]` table; unknown keys are rejected.
//!
//! Operators see these messages from `check-config`; keep them precise.

use std::collections::BTreeSet;
use std::path::PathBuf;

use garrison_core::config::ConfigError;
use garrison_core::modules::ModuleId;
use toml::{Table, Value};

pub type Checked<T> = Result<T, ConfigError>;

pub fn fail<T>(message: impl Into<String>) -> Checked<T> {
    Err(ConfigError(message.into()))
}

#[derive(Debug)]
pub struct Options<'a> {
    pub kind: String,
    pub raw: &'a Table,
}

impl<'a> Options<'a> {
    pub fn new(raw: &'a Table, allowed: &[&str]) -> Checked<Self> {
        let kind = raw
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let unknown: BTreeSet<&str> = raw
            .keys()
            .map(String::as_str)
            .filter(|key| *key != "type" && !allowed.contains(key))
            .collect();
        if !unknown.is_empty() {
            let names: Vec<&str> = unknown.into_iter().collect();
            return fail(format!(
                "providers[{kind}] has unknown settings: {}",
                names.join(", ")
            ));
        }
        Ok(Options { kind, raw })
    }

    pub fn has(&self, key: &str) -> bool {
        self.raw.contains_key(key)
    }

    pub fn text(&self, key: &str, default: Option<&str>) -> Checked<String> {
        let value = match self.raw.get(key) {
            Some(Value::String(text)) => Some(text.as_str()),
            Some(_) => None,
            None => default,
        };
        match value {
            Some(text) if !text.is_empty() && text.chars().count() <= 500 => Ok(text.to_owned()),
            _ => fail(format!(
                "providers[{}].{key} must be a short text",
                self.kind
            )),
        }
    }

    pub fn optional_text(&self, key: &str) -> Checked<Option<String>> {
        if self.has(key) {
            self.text(key, None).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn path(&self, key: &str, default: Option<&str>) -> Checked<PathBuf> {
        let value = self.text(key, default)?;
        if !value.starts_with('/') {
            return fail(format!(
                "providers[{}].{key} must be an absolute path",
                self.kind
            ));
        }
        Ok(PathBuf::from(value))
    }

    pub fn integer(&self, key: &str, default: i64, low: i64, high: i64) -> Checked<i64> {
        let value = match self.raw.get(key) {
            None => Some(default),
            Some(Value::Integer(number)) => Some(*number),
            Some(_) => None,
        };
        match value {
            Some(number) if (low..=high).contains(&number) => Ok(number),
            _ => fail(format!(
                "providers[{}].{key} must be {low}..{high}",
                self.kind
            )),
        }
    }

    pub fn flag(&self, key: &str, default: bool) -> Checked<bool> {
        match self.raw.get(key) {
            None => Ok(default),
            Some(Value::Boolean(flag)) => Ok(*flag),
            Some(_) => fail(format!(
                "providers[{}].{key} must be true or false",
                self.kind
            )),
        }
    }

    pub fn modules(&self, default: &[&str]) -> Checked<BTreeSet<ModuleId>> {
        let defaults: Vec<Value> = default.iter().map(|name| Value::from(*name)).collect();
        let value = self
            .raw
            .get("modules")
            .cloned()
            .unwrap_or(Value::Array(defaults));
        modules_of(Some(&value), &format!("providers[{}].modules", self.kind))
    }

    pub fn tables(&self, key: &str) -> Checked<Vec<&'a Table>> {
        let items = match self.raw.get(key) {
            None => return Ok(Vec::new()),
            Some(Value::Array(items)) if items.len() <= 200 => items,
            Some(_) => return self.not_tables(key),
        };
        let tables: Option<Vec<&Table>> = items.iter().map(Value::as_table).collect();
        tables.map_or_else(|| self.not_tables(key), Ok)
    }

    fn not_tables<T>(&self, key: &str) -> Checked<T> {
        fail(format!(
            "providers[{}].{key} must be a list of tables",
            self.kind
        ))
    }
}

/// A non-empty list of known module IDs.
pub fn modules_of(value: Option<&Value>, name: &str) -> Checked<BTreeSet<ModuleId>> {
    let ids: Option<BTreeSet<ModuleId>> = value
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .and_then(|items| {
            items
                .iter()
                .map(|item| item.as_str().and_then(|text| text.parse().ok()))
                .collect()
        });
    ids.map_or_else(|| fail(format!("{name} must list known module IDs")), Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> Table {
        text.parse().unwrap()
    }

    #[test]
    fn lists_of_tables_hold_at_most_200() {
        let list = |count: usize| {
            table(&format!(
                "type = \"receipt\"\nitems = [{}]",
                vec!["{}"; count].join(", ")
            ))
        };
        let (most, more) = (list(200), list(201));
        assert_eq!(
            Options::new(&most, &["items"])
                .unwrap()
                .tables("items")
                .unwrap()
                .len(),
            200
        );
        let error = Options::new(&more, &["items"])
            .unwrap()
            .tables("items")
            .unwrap_err()
            .0;
        assert!(error.contains("items must be a list of tables"), "{error}");
    }

    #[test]
    fn unknown_settings_and_bad_values_are_named() {
        let raw = table("type = \"host\"\ndisk = \"/\"\nother = 1");
        assert_eq!(
            Options::new(&raw, &["disk_path"]).unwrap_err().0,
            "providers[host] has unknown settings: disk, other"
        );
        let raw = table("type = \"x\"\nname = \"\"\npath = \"relative\"\ncount = 5\nlist = [1]");
        let options = Options::new(&raw, &["name", "path", "count", "list"]).unwrap();
        assert_eq!(
            options.text("name", None).unwrap_err().0,
            "providers[x].name must be a short text"
        );
        assert_eq!(options.text("missing", Some("d")).unwrap(), "d");
        assert_eq!(
            options.path("path", None).unwrap_err().0,
            "providers[x].path must be an absolute path"
        );
        assert_eq!(
            options.integer("count", 0, 1, 4).unwrap_err().0,
            "providers[x].count must be 1..4"
        );
        assert_eq!(options.integer("missing", 3, 1, 4).unwrap(), 3);
        assert_eq!(
            options.tables("list").unwrap_err().0,
            "providers[x].list must be a list of tables"
        );
        assert_eq!(
            options.modules(&["nowhere"]).unwrap_err().0,
            "providers[x].modules must list known module IDs"
        );
        assert_eq!(
            options.modules(&["dashboard"]).unwrap(),
            BTreeSet::from([ModuleId::Dashboard])
        );
    }
}
