//! `ClamAV` scanner, milter and signature observations.
//!
//! Configuration values describe the files on disk; whether the running daemons
//! loaded them is not verified. Signature file times are not proof of a
//! successful update check; the Fangfrisch database records actual refresh
//! times.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Column, Evidence, Field, Format, Observation, State, Table};
use garrison_core::sqlite::reading;
use garrison_core::time;
use serde_json::json;

use super::directives::directives;
use crate::context::{Collected, Context, Provider, ProviderError, Report};
use crate::options::{Checked, Options, fail};

const ACTIONS: [&str; 5] = ["Accept", "Reject", "Defer", "Blackhole", "Quarantine"];
const DEFAULT_SIGNATURES: [&str; 6] = [
    "main.cvd",
    "main.cld",
    "daily.cvd",
    "daily.cld",
    "bytecode.cvd",
    "bytecode.cld",
];

type Directives = BTreeMap<String, Option<String>>;

/// `25M` and friends in bytes.
fn size(value: Option<&str>) -> Option<u64> {
    let value = value?;
    let digits = value.trim_end_matches(|c: char| "kKmMgG".contains(c));
    let suffix = &value[digits.len()..];
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) || suffix.len() > 1 {
        return None;
    }
    let exponent = match suffix.to_ascii_uppercase().as_str() {
        "" => 0,
        "K" => 1,
        "M" => 2,
        _ => 3,
    };
    digits
        .parse::<u64>()
        .ok()?
        .checked_mul(1024_u64.pow(exponent))
}

fn yes(value: Option<&str>) -> Option<bool> {
    match value?.to_lowercase().as_str() {
        "yes" | "true" => Some(true),
        "no" | "false" => Some(false),
        _ => None,
    }
}

fn get<'a>(values: Option<&'a Directives>, key: &str) -> Option<&'a str> {
    values?.get(key)?.as_deref()
}

#[derive(Debug)]
pub struct Clamav {
    milter_config: PathBuf,
    clamd_config: PathBuf,
    database: PathBuf,
    signatures: Vec<String>,
    fangfrisch: Option<PathBuf>,
    expect_on_infected: String,
    expect_on_fail: String,
}

impl Clamav {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(
            raw,
            &[
                "milter_config",
                "clamd_config",
                "database_directory",
                "signatures",
                "fangfrisch_database",
                "expect_on_infected",
                "expect_on_fail",
            ],
        )?;
        let file_name = |name: &str| {
            (1..=80).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        };
        let signatures = match raw.get("signatures") {
            None => DEFAULT_SIGNATURES.iter().map(ToString::to_string).collect(),
            Some(toml::Value::Array(items)) => {
                let names: Option<Vec<String>> = items
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .filter(|name| file_name(name))
                            .map(str::to_owned)
                    })
                    .collect();
                match names {
                    Some(names) => names,
                    None => return fail("providers[clamav].signatures must list file names"),
                }
            }
            Some(_) => return fail("providers[clamav].signatures must list file names"),
        };
        Ok(Clamav {
            milter_config: options.path("milter_config", Some("/etc/mail/clamav-milter.conf"))?,
            clamd_config: options.path("clamd_config", Some("/etc/clamd.d/scan.conf"))?,
            database: options.path("database_directory", Some("/var/lib/clamav"))?,
            signatures,
            fangfrisch: if options.has("fangfrisch_database") {
                Some(options.path("fangfrisch_database", None)?)
            } else {
                None
            },
            expect_on_infected: options.text("expect_on_infected", Some("Reject"))?,
            expect_on_fail: options.text("expect_on_fail", Some("Defer"))?,
        })
    }

    fn configuration(&self, context: &Context<'_>) -> Result<Observation, ProviderError> {
        let milter = directives(&self.milter_config);
        let clamd = directives(&self.clamd_config);
        let (m, c) = (milter.as_ref(), clamd.as_ref());
        let action = |key: &str| get(m, key).filter(|value| ACTIONS.contains(value));
        let (infected, failure) = (action("OnInfected"), action("OnFail"));
        let mut findings = Vec::new();
        if let Some(infected) = infected.filter(|value| *value != self.expect_on_infected) {
            findings.push(format!(
                "Detected malware is handled with {infected}, not {}.",
                self.expect_on_infected
            ));
        }
        if let Some(failure) = failure.filter(|value| *value != self.expect_on_fail) {
            findings.push(format!(
                "Scanner failures are handled with {failure}, not {}.",
                self.expect_on_fail
            ));
        }
        let state = match (m.is_some() && c.is_some(), findings.is_empty()) {
            (false, _) => State::Unknown,
            (true, false) => State::Warning,
            (true, true) => State::Ok,
        };
        let bytes =
            |label: &str, values, key| Field::new(label, size(get(values, key)), Format::Bytes);
        let flag = |label: &str, key| Field::new(label, yes(get(c, key)), Format::Boolean);
        Ok(Observation::new(
            "clamav.configuration",
            self.name(),
            "Antivirus configuration",
            [ModuleId::Antivirus],
            Evidence::Configuration,
            state,
            context.checked_at(),
            format!(
                "{}; {}",
                self.milter_config.display(),
                self.clamd_config.display()
            ),
        )?
        .with_scope("On-disk configuration; whether the running daemons loaded it is not verified.")
        .with_fields(vec![
            Field::text("Detected malware", infected),
            Field::text("Scanner failure", failure),
            Field::text("Milter socket", get(m, "MilterSocket")),
            Field::text("Scanner socket", get(m, "ClamdSocket")),
            bytes("Milter file limit", m, "MaxFileSize"),
            bytes("Scanner stream limit", c, "StreamMaxLength"),
            bytes("Scanner file limit", c, "MaxFileSize"),
            bytes("Scanner total limit", c, "MaxScanSize"),
            flag("Archive scanning", "ScanArchive"),
            flag("Alert when limits are exceeded", "AlertExceedsMax"),
            flag("Alert for encrypted content", "AlertEncrypted"),
        ])
        .with_findings(findings))
    }

    fn signatures(&self, context: &Context<'_>) -> Result<Observation, ProviderError> {
        let mut rows = Vec::new();
        for name in &self.signatures {
            let Ok(info) = std::fs::metadata(self.database.join(name)) else {
                continue;
            };
            // The modification time with its fraction, in seconds.
            #[allow(clippy::cast_precision_loss)]
            let seconds = info.mtime() as f64 + info.mtime_nsec() as f64 * 1e-9;
            let modified = time::from_unix(seconds).map(time::isoformat);
            rows.push(vec![
                json!(name),
                json!(info.len()),
                json!(modified),
                json!(self.refreshed(name)),
            ]);
        }
        let column = |label: &str, format| Column {
            label: label.to_owned(),
            format,
        };
        Ok(Observation::new(
            "clamav.signatures",
            self.name(),
            "Signature databases",
            [ModuleId::Antivirus],
            Evidence::Inventory,
            if rows.is_empty() {
                State::Unknown
            } else {
                State::Ok
            },
            context.checked_at(),
            self.database.display().to_string(),
        )?
        .with_scope("File times do not prove a successful update check or a loaded database.")
        .with_table(Table {
            columns: vec![
                column("File", Format::Text),
                column("Size", Format::Bytes),
                column("Modified", Format::Datetime),
                column("Last refresh check", Format::Datetime),
            ],
            rows,
        })
        .with_max_age(900))
    }

    /// When Fangfrisch last checked this file, from its refresh log.
    fn refreshed(&self, name: &str) -> Option<String> {
        let db = reading(self.fangfrisch.as_deref()?, Duration::from_secs(2)).ok()??;
        let mut statement = db
            .prepare("SELECT path, updated FROM refreshlog LIMIT 512")
            .ok()?;
        let mut rows = statement.query([]).ok()?;
        while let Ok(Some(row)) = rows.next() {
            let path: String = row.get::<_, rusqlite::types::Value>(0).ok().map(sql_text)?;
            if Path::new(&path).file_name().and_then(|file| file.to_str()) == Some(name) {
                let updated = sql_text(row.get::<_, rusqlite::types::Value>(1).ok()?);
                // Fangfrisch writes UTC without saying so.
                return time::parse_naive_utc(&updated)
                    .or_else(|| time::parse(&updated))
                    .map(time::isoformat);
            }
        }
        None
    }
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

impl Provider for Clamav {
    fn name(&self) -> &'static str {
        "clamav"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let signatures = self.signatures(context)?;
        let daily = signatures
            .table
            .iter()
            .flat_map(|table| &table.rows)
            .find(|row| {
                row[0]
                    .as_str()
                    .is_some_and(|name| name.starts_with("daily."))
            });
        let age = daily
            .and_then(|row| row[2].as_str())
            .and_then(time::parse)
            .map(|modified| context.seconds_since(modified) / 3600.0);
        let mut report = Report {
            observations: vec![self.configuration(context)?, signatures],
            ..Report::default()
        };
        if let Some(hours) = age {
            report.gauges.insert("signature_age_hours".into(), hours);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Canned, config, context, table};

    #[test]
    fn sizes_take_one_binary_suffix() {
        for (text, bytes) in [
            ("1024", Some(1024)),
            ("4k", Some(4 << 10)),
            ("25M", Some(25 << 20)),
            ("2G", Some(2 << 30)),
            ("M", None),
            ("+5M", None),
            ("5MM", None),
            ("5T", None),
        ] {
            assert_eq!(size(Some(text)), bytes, "{text}");
        }
    }

    #[test]
    fn both_configurations_are_needed_for_a_verdict() {
        let directory = tempfile::tempdir().unwrap();
        let milter = directory.path().join("milter.conf");
        std::fs::write(&milter, "OnInfected Reject\nOnFail Defer\n").unwrap();
        let missing = directory.path().join("scan.conf");
        let raw = format!(
            "milter_config = \"{}\"\nclamd_config = \"{}\"",
            milter.display(),
            missing.display()
        );
        let clamav = Clamav::new(&table(&raw)).unwrap();
        let (config, runner) = (config(directory.path()), Canned(String::new()));
        let unknown = clamav.configuration(&context(&config, &runner)).unwrap();
        assert_eq!((unknown.state, unknown.findings.len()), (State::Unknown, 0));
        std::fs::write(&missing, "MaxFileSize 25M\n").unwrap();
        let known = clamav.configuration(&context(&config, &runner)).unwrap();
        assert_eq!(known.state, State::Ok);
    }
}
