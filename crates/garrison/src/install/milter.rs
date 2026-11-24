//! The macro milter's unit, which is the one service that does not always
//! run: only where the configuration has a `[milter]` section.
//!
//! `garrison stalwart setup` tells Stalwart of the filter and takes it out
//! again. The installer only starts it anew with a release, and must not
//! take it away while Stalwart still asks it: Stalwart would then defer
//! every message. It holds no administrator's credential, so it knows that
//! by setup's note of the filter's entry, which any run of setup that
//! changes entries writes first, and, where there is none and the filter
//! runs, by Stalwart's milters as the collector's API key reads them. Where
//! neither tells, the filter counts as asked: it is never stopped on a guess.

use std::path::Path;
use std::time::Duration;

use garrison_collector::providers::stalwart::answers::{Fixed, Written};
use garrison_core::config::{self, Config};
use garrison_core::credentials::Credentials;
use garrison_stalwart::jmap::JmapClient;
use serde::Deserialize;
use serde_json::Value;

use super::files::{Step, announce, run};
use super::system::unit_file;
use super::{CONFIG, SYSTEMCTL};
use crate::units;

/// One of Stalwart's milters, as far as the installer reads it.
#[derive(Debug, Deserialize)]
pub(super) struct Entry {
    id: String,
    #[serde(default)]
    host: Written,
    #[serde(default)]
    port: Written,
    #[serde(default)]
    enable: Fixed,
}

impl Entry {
    /// Whether Stalwart asks it on this host, where the filter listens:
    /// switched on, also under conditions.
    fn asked_here(&self) -> bool {
        self.enable.0 != Some(false)
            && matches!(
                self.host.0.as_ref().and_then(Value::as_str),
                Some("127.0.0.1" | "localhost")
            )
    }
}

/// Whether setup's note of the filter's entry in Stalwart is there, in any
/// form: a run of setup that stopped before Stalwart read its settings
/// leaves it marked, and one that names nothing may name an entry still.
fn noted(configuration: &Path) -> bool {
    configuration
        .join("credentials")
        .join(units::MILTER_ENTRY)
        .symlink_metadata()
        .is_ok()
}

/// Why Stalwart may still ask the filter that the configuration no longer
/// has, or `None` where nothing asks it. `running` says whether the filter
/// runs, `entries` asks Stalwart for its milters.
fn still_asked(
    configuration: &Path,
    loaded: Option<&Config>,
    running: bool,
    entries: impl FnOnce(&Config) -> Result<Vec<Entry>, String>,
) -> Option<String> {
    if noted(configuration) {
        return Some("setup's note of its entry in Stalwart is there".to_owned());
    }
    // A filter that does not run answers nobody, stopped or not.
    if !running {
        return None;
    }
    let Some(config) = loaded else {
        return Some(format!(
            "{} does not load, so Stalwart's milters cannot be asked",
            configuration.join("garrison.toml").display()
        ));
    };
    match entries(config) {
        Ok(entries) => entries
            .iter()
            .find(|entry| entry.asked_here())
            .map(|entry| {
                format!(
                    "Stalwart asks its milter entry {} at {}:{}, which may be the filter",
                    entry.id,
                    entry.host.text(),
                    entry.port.text()
                )
            }),
        Err(why) => Some(format!("Stalwart's milters could not be asked ({why})")),
    }
}

/// Stalwart's milters, as the collector's API key reads them.
fn stalwart_entries(config: &Config) -> Result<Vec<Entry>, String> {
    let key = Credentials::new(&config.credentials_directory)
        .read_secret(&config.collector.native_key)
        .map_err(|error| format!("the collector's API key: {error}"))?;
    JmapClient::new(&config.deployment.stalwart_url, &key)
        .with_timeout(Duration::from_secs(10))
        .get::<Entry>("MtaMilter", None, &["id", "host", "port", "enable"])
        .map_err(|error| error.to_string())
}

fn filter_runs() -> bool {
    run(SYSTEMCTL, &["is-active", "--quiet", units::MILTER])
        .is_ok_and(|output| output.status.success())
}

/// Whether the unit starts with the release. Where the configuration does
/// not have the filter and nothing asks it, it is stopped.
pub(super) fn runs() -> bool {
    let configuration = Path::new(CONFIG);
    let loaded = config::load(&configuration.join("garrison.toml")).ok();
    if loaded
        .as_ref()
        .is_some_and(|config| config.milter.is_some())
    {
        return unit_file(units::MILTER).exists();
    }
    match still_asked(
        configuration,
        loaded.as_ref(),
        filter_runs(),
        stalwart_entries,
    ) {
        Some(why) => announce(&format!(
            "The macro milter, which the configuration no longer has, keeps running: {why}. Run \
             `garrison stalwart setup`: it takes the filter out of Stalwart and stops it."
        )),
        None => {
            let _ = run(SYSTEMCTL, &["disable", "--now", units::MILTER]);
        }
    }
    false
}

/// Uninstalling stops the filter, so Stalwart must have forgotten it first.
pub(super) fn forgotten(configuration: &Path) -> Step {
    let loaded = config::load(&configuration.join("garrison.toml")).ok();
    let Some(why) = still_asked(
        configuration,
        loaded.as_ref(),
        filter_runs(),
        stalwart_entries,
    ) else {
        return Ok(());
    };
    Err(format!(
        "Stalwart may still ask Garrison's macro milter about every message, and would defer \
         mail without it: {why}; nothing was changed. Remove the [milter] section from {}, run \
         `garrison stalwart setup` and uninstall then.",
        configuration.join("garrison.toml").display()
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn entries(list: &Value) -> Vec<Entry> {
        serde_json::from_value(list.clone()).unwrap()
    }

    /// Every state a run that would stop the filter can meet: the note in
    /// any form, the filter running or not, Stalwart's milters as read, or
    /// no answer. Only where nothing can ask the filter is it stopped.
    #[test]
    fn the_filter_is_never_stopped_while_stalwart_may_ask_it() {
        let directory = tempfile::tempdir().unwrap();
        let configuration = directory.path();
        let credentials = configuration.join("credentials");
        std::fs::create_dir(&credentials).unwrap();
        let config = garrison_testing::config(configuration, "http://127.0.0.1:9");
        let unasked = |_: &Config| -> Result<Vec<Entry>, String> { panic!("asked Stalwart") };
        // Setup's note, named, marked or empty: asked, and Stalwart is not
        // even asked.
        for note in ["m1", "!m1", "!", ""] {
            std::fs::write(credentials.join(units::MILTER_ENTRY), note).unwrap();
            for running in [true, false] {
                let said = still_asked(configuration, Some(&config), running, unasked);
                assert!(said.is_some_and(|said| said.contains("note")), "{note:?}");
            }
        }
        std::fs::remove_file(credentials.join(units::MILTER_ENTRY)).unwrap();
        // No note and no filter running: nothing to keep.
        assert_eq!(
            still_asked(configuration, Some(&config), false, unasked),
            None
        );
        // No note, the filter running: as Stalwart's milters say.
        let stored = json!([
            {"id": "a", "host": "127.0.0.1", "port": 8096, "enable": {"match": {}, "else": "false"}},
            {"id": "b", "host": "10.0.0.5", "port": 8096},
        ]);
        let read = |_: &Config| Ok(entries(&stored));
        assert_eq!(still_asked(configuration, Some(&config), true, read), None);
        for (host, enable) in [("127.0.0.1", json!(true)), ("localhost", json!(null))] {
            let stored = json!([{"id": "m", "host": host, "port": 8096, "enable": enable}]);
            let said = still_asked(configuration, Some(&config), true, |_| Ok(entries(&stored)));
            assert!(
                said.is_some_and(|said| said.contains(&format!("entry m at {host}:8096"))),
                "{host}"
            );
        }
        // Where that cannot be told, the filter counts as asked.
        let refused = |_: &Config| Err("Stalwart did not answer".to_owned());
        let said = still_asked(configuration, Some(&config), true, refused).unwrap();
        assert!(
            said.contains("could not be asked (Stalwart did not answer)"),
            "{said}"
        );
        assert!(still_asked(configuration, None, true, unasked).is_some());
    }

    #[test]
    fn uninstalling_waits_until_stalwart_has_forgotten_the_filter() {
        let directory = tempfile::tempdir().unwrap();
        let credentials = directory.path().join("credentials");
        std::fs::create_dir(&credentials).unwrap();
        std::fs::write(credentials.join(units::MILTER_ENTRY), "b").unwrap();
        let refusal = forgotten(directory.path()).unwrap_err();
        assert!(refusal.contains("nothing was changed"), "{refusal}");
        assert!(refusal.contains("garrison stalwart setup"), "{refusal}");
    }
}
