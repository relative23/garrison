//! Bulwark webmail plugin observations.

use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{fs, io};

use garrison_core::files::{answered_by, read_bounded};
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, Required, State};
use garrison_core::{hex, json};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::hidden::{self, Seen};
use super::ran::{SECONDS, patience, silent};
use crate::context::{Collected, Context, HostPath, Provider, Report, Use};
use crate::options::{Checked, Options, fail};

/// Bulwark's list of its plugins, below its administration folder.
const REGISTRY: &str = "plugins/registry.json";
const MAX_REGISTRY: usize = 1024 * 1024;
const MAX_BUNDLE: usize = 2 * 1024 * 1024;

/// `1.2.3`, optionally with a pre-release or build suffix.
fn is_version(text: &str) -> bool {
    let (core, suffix) = match text.find(['-', '+']) {
        Some(index) => (&text[..index], Some(&text[index + 1..])),
        None => (text, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && suffix.is_none_or(|suffix| {
            (1..=48).contains(&suffix.len())
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        })
}

/// Installed Bulwark webmail plugins and their recorded bundle integrity.
#[derive(Debug)]
pub struct Bulwark {
    base: PathBuf,
    plugins: Vec<String>,
}

impl Bulwark {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["admin_directory", "plugins"])?;
        let base = options.path("admin_directory", None)?;
        let identifier = |name: &str| {
            (1..=64).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        };
        let plugins: Option<Vec<String>> = match raw.get("plugins") {
            None => Some(Vec::new()),
            Some(toml::Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .filter(|name| identifier(name))
                        .map(str::to_owned)
                })
                .collect(),
            Some(_) => None,
        };
        let Some(plugins) = plugins else {
            return fail("providers[bulwark].plugins must list plugin IDs");
        };
        Ok(Bulwark { base, plugins })
    }

    /// The plugins the registry lists, or why it cannot be read by `until`.
    fn registry(&self, until: Instant) -> Result<Vec<Value>, String> {
        let path = self.base.join(REGISTRY);
        let missing = format!(
            "there is no {REGISTRY} in {}; set `admin_directory` to Bulwark's administration \
             folder, which holds it",
            self.base.display()
        );
        let data = read(&path, MAX_REGISTRY, until)
            .map_err(|error| unread(REGISTRY, &path, &error, MAX_REGISTRY, until, &missing))?;
        let registry =
            json::parse(&data, MAX_REGISTRY).map_err(|_| format!("{REGISTRY} is no valid JSON"))?;
        registry
            .get("plugins")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| format!("{REGISTRY} holds no list of plugins"))
    }

    /// The bundle of `name`, read by `until`, against the hash that its row
    /// records.
    fn integrity(&self, name: &str, row: &Value, until: Instant) -> Integrity {
        let Some(expected) = row
            .get("bundleHash")
            .and_then(Value::as_str)
            .filter(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        else {
            return Integrity::Unknown(format!("{REGISTRY} records no SHA-256 of it"));
        };
        let shown = format!("plugins/{name}.js");
        let path = self.base.join(&shown);
        let missing = format!(
            "{shown} is not there, though {REGISTRY} lists it; Bulwark writes it when it installs \
             the plugin"
        );
        match read(&path, MAX_BUNDLE, until) {
            Ok(code) if hex::encode(&Sha256::digest(&code)) == expected => Integrity::Verified,
            Ok(_) => Integrity::Mismatch,
            Err(error) => {
                Integrity::Unknown(unread(&shown, &path, &error, MAX_BUNDLE, until, &missing))
            }
        }
    }
}

/// The file at `path`, of at most `limit` bytes, as its file system answers
/// by `until`.
fn read(path: &Path, limit: usize, until: Instant) -> io::Result<Vec<u8>> {
    let path = path.to_path_buf();
    answered_by(until, move || read_bounded(&path, limit)).and_then(|read| read)
}

/// What the check of one plugin's bundle found.
#[derive(Debug, PartialEq, Eq)]
enum Integrity {
    Verified,
    Mismatch,
    /// Not known, and why.
    Unknown(String),
}

impl Integrity {
    /// The word the card shows for it.
    fn shown(&self) -> &'static str {
        match self {
            Integrity::Verified => "verified",
            Integrity::Mismatch => "mismatch",
            Integrity::Unknown(_) => "unknown",
        }
    }
}

/// Why a file below the administration folder could not be read: its file
/// system gave no answer by `until`, or it is not there, as `missing` says
/// with what mends it, a link, larger than it may be, kept from the
/// collector, or the error says.
fn unread(
    shown: &str,
    path: &Path,
    error: &io::Error,
    limit: usize,
    until: Instant,
    missing: &str,
) -> String {
    let silence = || format!("the file system of {shown} did not answer within {SECONDS} seconds");
    if silent(error) {
        return silence();
    }
    let looked = path.to_path_buf();
    match answered_by(until, move || fs::symlink_metadata(&looked)).and_then(|looked| looked) {
        Err(looked) if silent(&looked) => silence(),
        Err(_) if error.kind() == io::ErrorKind::NotFound => missing.to_owned(),
        Ok(metadata) if metadata.is_symlink() => {
            format!("{shown} is a link, which is not followed")
        }
        Ok(metadata) if metadata.is_file() && metadata.len() > limit as u64 => {
            format!("{shown} is larger than {} MiB", limit / (1024 * 1024))
        }
        _ if error.kind() == io::ErrorKind::PermissionDenied => {
            format!("the collector may not read {shown}")
        }
        _ => format!("{shown} cannot be read: {error}"),
    }
}

impl Provider for Bulwark {
    fn name(&self) -> &'static str {
        "bulwark"
    }

    fn ids(&self) -> Vec<String> {
        vec!["bulwark.plugins".to_owned()]
    }

    fn paths(&self) -> Vec<HostPath<'_>> {
        vec![HostPath {
            option: "admin_directory",
            path: &self.base,
            used: Use::Reads,
        }]
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        self.card(context, patience())
    }
}

impl Bulwark {
    /// The card, with what it reads below the folder read by `until`.
    pub(super) fn card(&self, context: &Context<'_>, until: Instant) -> Collected {
        let registry_path = self.base.join(REGISTRY);
        // What the collector's unit hides is not mended by another folder.
        let registry = match hidden::seen(&self.base) {
            Seen::Hidden(place) => Err(format!(
                "{} lies under {}, which the collector's unit hides from it: show the collector \
                 that folder at another place and set `admin_directory` to it \
                 (docs/operator/checks.md, \"Paths the collector cannot see\")",
                self.base.display(),
                place.display()
            )),
            Seen::Host | Seen::Bound { .. } => self.registry(until),
        };
        let mut fields = Vec::new();
        let (mut mismatched, mut unknown, mut verified) = (Vec::new(), Vec::new(), 0_usize);
        for name in &self.plugins {
            let (row, integrity) = match &registry {
                Ok(rows) => {
                    let matches: Vec<&Value> = rows
                        .iter()
                        .filter(|row| row.get("id").and_then(Value::as_str) == Some(name))
                        .collect();
                    match matches[..] {
                        [row] => (row, self.integrity(name, row, until)),
                        [] => (
                            &Value::Null,
                            Integrity::Unknown(format!("{REGISTRY} does not list it")),
                        ),
                        _ => (
                            &Value::Null,
                            Integrity::Unknown(format!(
                                "{REGISTRY} lists it {} times",
                                matches.len()
                            )),
                        ),
                    }
                }
                // The registry's own finding says why.
                Err(_) => (&Value::Null, Integrity::Unknown(String::new())),
            };
            match &integrity {
                Integrity::Verified => verified += 1,
                Integrity::Mismatch => mismatched.push(format!(
                    "The {name} bundle does not match its recorded hash."
                )),
                Integrity::Unknown(why) if registry.is_ok() => unknown.push(format!(
                    "The integrity of the {name} bundle is not known: {why}."
                )),
                Integrity::Unknown(_) => {}
            }
            let version = row
                .get("version")
                .and_then(Value::as_str)
                .filter(|text| is_version(text));
            fields.extend([
                Field::text(format!("{name}: version"), version),
                Field::new(
                    format!("{name}: enabled"),
                    row.get("enabled").and_then(Value::as_bool),
                    Format::Boolean,
                ),
                Field::text(format!("{name}: bundle integrity"), integrity.shown()),
            ]);
        }
        // An integrity that is not known is no integrity in order: the card
        // is Partial beside a bundle that was verified, Unknown without one,
        // as where no plugin is named.
        let state = match &registry {
            Err(_) => State::Unknown,
            Ok(_) if !mismatched.is_empty() => State::Failed,
            Ok(_) if verified == 0 => State::Unknown,
            Ok(_) if unknown.is_empty() => State::Ok,
            Ok(_) => State::Partial,
        };
        let mut findings: Vec<String> = registry
            .err()
            .map(|why| format!("No bundle's integrity is known: {why}."))
            .into_iter()
            .collect();
        if self.plugins.is_empty() {
            findings.push("No plugin is named in `plugins`, so no bundle is checked.".to_owned());
        }
        // A mismatch first, as the notifications carry the first finding.
        findings.extend(mismatched);
        findings.extend(unknown);
        let observation = Observation::new(Required {
            id: "bulwark.plugins",
            provider: self.name(),
            title: "Webmail plugins",
            modules: [ModuleId::Spam],
            evidence: Evidence::Configuration,
            state,
            checked_at: &context.checked_at(),
            source: &registry_path.display().to_string(),
        })?
        .with_scope("Administrator configuration; execution in browsers is not tested here.")
        .with_fields(fields)
        .with_findings(findings)
        .with_max_age(900);
        Ok(Report::of(observation))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing::{Canned, config, context, table};

    /// A plugin directory with `bundle` as `spam.js` and `hash` recorded for it.
    fn plugins(bundle: &[u8], hash: &str) -> (tempfile::TempDir, Observation) {
        let directory = tempfile::tempdir().unwrap();
        let plugins = directory.path().join("plugins");
        fs::create_dir_all(&plugins).unwrap();
        fs::write(plugins.join("spam.js"), bundle).unwrap();
        // Notes make the registry larger than a few KiB, as real ones are.
        let plugin = json!({"id": "spam", "version": "1.2.3", "enabled": true, "bundleHash": hash});
        let registry = json!({"plugins": [plugin], "notes": "x".repeat(64 * 1024)});
        fs::write(plugins.join("registry.json"), registry.to_string()).unwrap();
        let raw = format!(
            "admin_directory = \"{}\"\nplugins = [\"spam\"]",
            directory.path().display()
        );
        let provider = Bulwark::new(&table(&raw)).unwrap();
        let (config, runner) = (config(directory.path()), Canned(String::new()));
        let observation = provider
            .collect(&context(&config, &runner))
            .unwrap()
            .observations
            .remove(0);
        (directory, observation)
    }

    fn integrity(observation: &Observation) -> Value {
        let field = observation
            .fields
            .iter()
            .find(|field| field.label == "spam: bundle integrity");
        field.unwrap().value.clone()
    }

    #[test]
    fn bundles_up_to_two_mebibytes_are_verified_against_their_hash() {
        let bundle = vec![b'x'; 2 * 1024 * 1024];
        let hash = hex::encode(&Sha256::digest(&bundle));
        let (_directory, observation) = plugins(&bundle, &hash);
        assert_eq!(
            (observation.state, integrity(&observation)),
            (State::Ok, json!("verified"))
        );
        let (_directory, observation) = plugins(b"changed", &hash);
        assert_eq!(
            (observation.state, integrity(&observation)),
            (State::Failed, json!("mismatch"))
        );
        // Only a full SHA-256 in lowercase hex is a recorded hash.
        for recorded in ["abc", &hash.to_uppercase(), &format!("{}g", &hash[..63])] {
            let (_directory, observation) = plugins(b"x", recorded);
            assert_eq!(integrity(&observation), json!("unknown"), "{recorded}");
        }
    }

    /// A bundle whose file system gives no answer by the card's time is not
    /// known, and says so.
    #[test]
    fn a_bundle_whose_file_system_does_not_answer_is_not_known() {
        let directory = tempfile::tempdir().unwrap();
        let raw = format!("admin_directory = \"{}\"", directory.path().display());
        let provider = Bulwark::new(&table(&raw)).unwrap();
        let row = json!({"id": "spam", "bundleHash": hex::encode(&Sha256::digest(b"x"))});
        assert_eq!(
            provider.integrity("spam", &row, Instant::now()),
            Integrity::Unknown(
                "the file system of plugins/spam.js did not answer within 8 seconds".to_owned()
            )
        );
    }

    #[test]
    fn versions_have_three_numbers_and_an_optional_suffix() {
        for good in ["1.2.3", "10.0.0-beta.1", "1.2.3+build-7"] {
            assert!(is_version(good), "{good}");
        }
        for bad in [
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            "1.2.3-",
            "1..3",
            &format!("1.2.3-{}", "a".repeat(49)),
        ] {
            assert!(!is_version(bad), "{bad}");
        }
    }
}
