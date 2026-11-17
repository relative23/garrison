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
use garrison_core::observations::{
    Column, Evidence, Field, Format, Observation, Required, State, Table,
};
use garrison_core::sqlite::reading;
use garrison_core::time;
use serde_json::json;

use super::directives;
use crate::context::{Collected, Context, HostPath, Provider, ProviderError, Report, Use};
use crate::options::{Checked, Options, fail};
use policy::{ON_FAIL, ON_INFECTED};

mod policy;

const DEFAULT_SIGNATURES: [&str; 6] = [
    "main.cvd",
    "main.cld",
    "daily.cvd",
    "daily.cld",
    "bytecode.cvd",
    "bytecode.cld",
];

type Directives = BTreeMap<String, Vec<String>>;

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

/// The value `ClamAV` takes of a directive: the first, where the file sets it
/// more than once.
fn get<'a>(values: Option<&'a Directives>, key: &str) -> Option<&'a str> {
    values?.get(key)?.first().map(String::as_str)
}

#[derive(Debug)]
pub struct Clamav {
    milter_config: PathBuf,
    clamd_config: PathBuf,
    database: PathBuf,
    signatures: Vec<String>,
    fangfrisch: Option<PathBuf>,
    expect_on_infected: &'static str,
    expect_on_fail: &'static str,
}

/// The daily signature database is older than this only where updates no
/// longer arrive: a new one is published every day.
const STALE_AFTER_HOURS: f64 = 48.0;

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
            expect_on_infected: ON_INFECTED.expected(&options, "Reject")?,
            expect_on_fail: ON_FAIL.expected(&options, "Defer")?,
        })
    }

    /// The card of the policy and limits the two files set. A policy that
    /// was read stays what it is where the scanner's file could not be read;
    /// only "in order" needs both.
    fn configuration(&self, context: &Context<'_>) -> Result<Observation, ProviderError> {
        let milter = directives::values(&self.milter_config);
        let clamd = directives::values(&self.clamd_config);
        let (m, c) = (milter.as_ref().ok(), clamd.as_ref().ok());
        // Each finding with whether it needs a look.
        let mut findings: Vec<(bool, String)> = Vec::new();
        let mut action = |policy: &policy::Policy, expected: &str| {
            let values = m?.get(policy.key).map_or(&[][..], Vec::as_slice);
            let judged = policy.judged(values, expected, &self.milter_config);
            findings.extend(judged.findings);
            judged.action
        };
        let infected = action(&ON_INFECTED, self.expect_on_infected);
        let failure = action(&ON_FAIL, self.expect_on_fail);
        for (path, read) in [(&self.milter_config, &milter), (&self.clamd_config, &clamd)] {
            if let Err(why) = read {
                findings.push((
                    false,
                    format!("{} could not be read: {why}.", path.display()),
                ));
            }
        }
        let state = if m.is_none() {
            State::Unknown
        } else if findings.iter().any(|(look, _)| *look) {
            State::Warning
        } else if c.is_none() {
            State::Unknown
        } else {
            State::Ok
        };
        // clamav-milter takes turns with every scanner it is given.
        let scanners = m
            .and_then(|values| values.get("ClamdSocket"))
            .map(|sockets| sockets.join(", "));
        let bytes =
            |label: &str, values, key| Field::new(label, size(get(values, key)), Format::Bytes);
        let flag = |label: &str, key| Field::new(label, yes(get(c, key)), Format::Boolean);
        Ok(Observation::new(Required {
            id: "clamav.configuration",
            provider: self.name(),
            title: "Antivirus configuration",
            modules: [ModuleId::Antivirus],
            evidence: Evidence::Configuration,
            state,
            checked_at: &context.checked_at(),
            source: &format!(
                "{}; {}",
                self.milter_config.display(),
                self.clamd_config.display()
            ),
        })?
        .with_scope("On-disk configuration; whether the running daemons loaded it is not verified.")
        .with_fields(vec![
            Field::text("Detected malware", infected),
            Field::text("Scanner failure", failure),
            Field::text("Milter socket", get(m, "MilterSocket")),
            Field::text("Scanner socket", scanners),
            bytes("Milter file limit", m, "MaxFileSize"),
            bytes("Scanner stream limit", c, "StreamMaxLength"),
            bytes("Scanner file limit", c, "MaxFileSize"),
            bytes("Scanner total limit", c, "MaxScanSize"),
            flag("Archive scanning", "ScanArchive"),
            flag("Alert when limits are exceeded", "AlertExceedsMax"),
            flag("Alert for encrypted content", "AlertEncrypted"),
        ])
        .with_findings(findings.into_iter().map(|(_, finding)| finding).collect()))
    }

    /// The card of the signature files, and the age in hours of the newest
    /// daily database that it judges, which the dashboard's gauge shows.
    fn signatures(
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
        // Files that exist are not yet signatures that are current.
        let (state, finding) = match daily {
            _ if rows.is_empty() => (State::Unknown, None),
            None => (
                State::Unknown,
                Some(
                    "No daily signature database (daily.cld or daily.cvd) is among the files; \
                     how current the signatures are is not known."
                        .to_owned(),
                ),
            ),
            Some((name, hours)) if hours > STALE_AFTER_HOURS => (
                State::Warning,
                Some(format!(
                    "{name} was last updated {hours:.0} hours ago; ClamAV's signatures change \
                     every day, so the updates do not arrive."
                )),
            ),
            Some(_) => (State::Ok, None),
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
        Ok((observation, daily.map(|(_, hours)| hours)))
    }
}

/// When Fangfrisch last checked each of the files `listed`, by the file's
/// name, from the refresh log of its database at `path`; or why it could not
/// be read. The reader's time bounds the scan, and the names kept are the
/// listed ones, whatever the log's writer put there.
pub(super) fn refresh_log(
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

impl Provider for Clamav {
    fn name(&self) -> &'static str {
        "clamav"
    }

    fn ids(&self) -> Vec<String> {
        vec![
            "clamav.configuration".to_owned(),
            "clamav.signatures".to_owned(),
        ]
    }

    fn paths(&self) -> Vec<HostPath<'_>> {
        [
            HostPath {
                option: "milter_config",
                path: &self.milter_config,
                used: Use::Reads,
            },
            HostPath {
                option: "clamd_config",
                path: &self.clamd_config,
                used: Use::Reads,
            },
            HostPath {
                option: "database_directory",
                path: &self.database,
                used: Use::Reads,
            },
        ]
        .into_iter()
        .chain(self.fangfrisch.as_deref().map(|path| HostPath {
            option: "fangfrisch_database",
            path,
            used: Use::Reads,
        }))
        .collect()
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let (signatures, age) = self.signatures(context)?;
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
        assert_eq!(
            (unknown.state, unknown.findings),
            (
                State::Unknown,
                vec![format!(
                    "{} could not be read: No such file or directory (os error 2).",
                    missing.display()
                )]
            )
        );
        // What was seen of the policy stays what it is.
        std::fs::write(&milter, "OnInfected Accept\n").unwrap();
        let drift = clamav.configuration(&context(&config, &runner)).unwrap();
        assert_eq!(drift.state, State::Warning, "{:?}", drift.findings);
        std::fs::write(&milter, "OnInfected Reject\nOnFail Defer\n").unwrap();
        std::fs::write(&missing, "MaxFileSize 25M\n").unwrap();
        let known = clamav.configuration(&context(&config, &runner)).unwrap();
        assert_eq!(known.state, State::Ok);
    }
}
