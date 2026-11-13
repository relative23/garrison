//! HTTP health probes and Bulwark webmail plugin observations.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use garrison_core::files::{read_bounded, read_json};
use garrison_core::hex;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, State};
use garrison_stalwart::http::status_of;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::context::{Collected, Context, Provider, Report};
use crate::options::{Checked, Options, fail};

const MAX_REGISTRY: usize = 1024 * 1024;
const MAX_BUNDLE: usize = 2 * 1024 * 1024;

/// A loopback endpoint answers with an expected status (process evidence).
#[derive(Debug)]
pub struct Http {
    id: String,
    title: String,
    url: String,
    expect: u16,
    modules: BTreeSet<ModuleId>,
}

impl Http {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["id", "title", "url", "expect_status", "modules"])?;
        let id = options.text("id", None)?;
        let title = options.text("title", None)?;
        let url = options.text("url", None)?;
        let loopback = url::Url::parse(&url).is_ok_and(|parsed| {
            parsed.scheme() == "http"
                && matches!(parsed.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))
        });
        if !loopback {
            return fail("providers[http].url must be a loopback http:// URL");
        }
        let expect = options.integer("expect_status", 200, 100, 599)?;
        Ok(Http {
            id,
            title,
            url,
            expect: u16::try_from(expect).unwrap_or(200),
            modules: options.modules(&["services"])?,
        })
    }
}

impl Provider for Http {
    fn name(&self) -> &'static str {
        "http"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let status = status_of(&self.url, Duration::from_secs(5)).ok();
        let findings = match status {
            None => vec!["The endpoint did not answer.".to_owned()],
            Some(status) if status != self.expect => {
                vec![format!("Answered HTTP {status}, expected {}.", self.expect)]
            }
            Some(_) => Vec::new(),
        };
        let observation = Observation::new(
            format!("http.{}", self.id),
            self.name(),
            self.title.clone(),
            self.modules.iter().copied(),
            Evidence::Process,
            if status == Some(self.expect) {
                State::Ok
            } else {
                State::Failed
            },
            context.checked_at(),
            self.url.clone(),
        )?
        .with_scope("The endpoint answered; this does not test user functionality.")
        .with_fields(vec![Field::new("HTTP status", status, Format::Number)])
        .with_findings(findings)
        .with_max_age(180);
        Ok(Report::of(observation))
    }
}

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

    fn integrity(&self, name: &str, expected: Option<&Value>) -> &'static str {
        let Some(expected) = expected.and_then(Value::as_str).filter(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) else {
            return "unknown";
        };
        let path = self.base.join("plugins").join(format!("{name}.js"));
        let Ok(code) = read_bounded(&path, MAX_BUNDLE) else {
            return "unknown";
        };
        if hex::encode(&Sha256::digest(&code)) == expected {
            "verified"
        } else {
            "mismatch"
        }
    }
}

impl Provider for Bulwark {
    fn name(&self) -> &'static str {
        "bulwark"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let registry_path = self.base.join("plugins/registry.json");
        let registry = read_json(&registry_path, MAX_REGISTRY);
        let rows = registry
            .as_ref()
            .and_then(|registry| registry.get("plugins"))
            .and_then(Value::as_array);
        let (mut fields, mut findings) = (Vec::new(), Vec::new());
        for name in &self.plugins {
            let matches: Vec<&Value> = rows
                .into_iter()
                .flatten()
                .filter(|row| row.get("id").and_then(Value::as_str) == Some(name))
                .collect();
            let row = if matches.len() == 1 {
                matches[0]
            } else {
                &Value::Null
            };
            let version = row
                .get("version")
                .and_then(Value::as_str)
                .filter(|text| is_version(text));
            let integrity = self.integrity(name, row.get("bundleHash"));
            if integrity == "mismatch" {
                findings.push(format!(
                    "The {name} bundle does not match its recorded hash."
                ));
            }
            fields.extend([
                Field::text(format!("{name}: version"), version),
                Field::new(
                    format!("{name}: enabled"),
                    row.get("enabled").and_then(Value::as_bool),
                    Format::Boolean,
                ),
                Field::text(format!("{name}: bundle integrity"), integrity),
            ]);
        }
        let state = match (rows.is_some(), findings.is_empty()) {
            (false, _) => State::Unknown,
            (true, false) => State::Failed,
            (true, true) => State::Ok,
        };
        let observation = Observation::new(
            "bulwark.plugins",
            self.name(),
            "Webmail plugins",
            [ModuleId::Spam],
            Evidence::Configuration,
            state,
            context.checked_at(),
            registry_path.display().to_string(),
        )?
        .with_scope("Administrator configuration; execution in browsers is not tested here.")
        .with_fields(fields)
        .with_findings(findings)
        .with_max_age(900);
        Ok(Report::of(observation))
    }
}

#[cfg(test)]
mod tests {
    use garrison_testing::http::{answer, serve};
    use serde_json::json;

    use super::*;
    use crate::testing::{Canned, config, context, table};

    fn probe(url: &str, expect: u16) -> Observation {
        let directory = tempfile::tempdir().unwrap();
        let (config, runner) = (config(directory.path()), Canned(String::new()));
        let raw =
            format!("id = \"api\"\ntitle = \"API\"\nurl = \"{url}\"\nexpect_status = {expect}");
        let provider = Http::new(&table(&raw)).unwrap();
        provider
            .collect(&context(&config, &runner))
            .unwrap()
            .observations
            .remove(0)
    }

    #[test]
    fn an_endpoint_is_ok_only_with_the_expected_status() {
        let ok = serve(vec![answer(204, "")]);
        let observation = probe(&ok.url, 204);
        assert_eq!(
            (observation.state, observation.findings.len()),
            (State::Ok, 0)
        );
        let other = serve(vec![answer(503, "")]);
        let observation = probe(&other.url, 204);
        assert_eq!(observation.state, State::Failed);
        assert_eq!(observation.findings, ["Answered HTTP 503, expected 204."]);
    }

    /// A plugin directory with `bundle` as `spam.js` and `hash` recorded for it.
    fn plugins(bundle: &[u8], hash: &str) -> (tempfile::TempDir, Observation) {
        let directory = tempfile::tempdir().unwrap();
        let plugins = directory.path().join("plugins");
        std::fs::create_dir_all(&plugins).unwrap();
        std::fs::write(plugins.join("spam.js"), bundle).unwrap();
        // Notes make the registry larger than a few KiB, as real ones are.
        let plugin = json!({"id": "spam", "version": "1.2.3", "enabled": true, "bundleHash": hash});
        let registry = json!({"plugins": [plugin], "notes": "x".repeat(64 * 1024)});
        std::fs::write(plugins.join("registry.json"), registry.to_string()).unwrap();
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
