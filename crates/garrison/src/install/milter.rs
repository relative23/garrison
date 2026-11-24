//! The macro milter's unit, which is the one service that does not always
//! run: only where the configuration has a `[milter]` section.
//!
//! `garrison stalwart setup` tells Stalwart of the filter and takes it out
//! again. The installer only starts it anew with a release, and must not
//! take it away while Stalwart still asks it: Stalwart would then defer
//! every message. It holds no administrator's credential, so it reads
//! Stalwart's milters with the collector's API key and keeps the filter
//! while an entry switched on is the filter's, by the rules setup acts by
//! (`doctor::milter::entries`). Where that cannot be told, the filter
//! counts as asked: it is never stopped on a guess.

use std::path::Path;
use std::time::Duration;

use garrison_core::config::{self, Config};
use garrison_core::credentials::Credentials;
use garrison_stalwart::jmap::JmapClient;

use super::files::{Step, announce, run};
use super::system::unit_file;
use super::{CONFIG, SYSTEMCTL};
use crate::doctor::milter::entries::{self, Entry};
use crate::units;

/// Why Stalwart may still ask the filter that the configuration no longer
/// has, or `None` where nothing asks it. `listening`: the ports the filter
/// listens on, where it runs; `entries` asks Stalwart for its milters.
fn still_asked(
    configuration: &Path,
    loaded: Option<&Config>,
    listening: Option<&[u16]>,
    entries: impl FnOnce(&Config) -> Result<Vec<Entry>, String>,
) -> Option<String> {
    // A filter that does not run answers nobody, stopped or not.
    let listening = listening?;
    if listening.is_empty() {
        return Some(format!("where {} listens cannot be seen", units::MILTER));
    }
    let Some(config) = loaded else {
        return Some(format!(
            "{} does not load, so Stalwart's milters cannot be asked",
            configuration.join("garrison.toml").display()
        ));
    };
    match entries(config) {
        Ok(stored) => entries::ours(&stored, None, listening)
            .into_iter()
            .find(|entry| entry.asked())
            .map(|entry| {
                format!(
                    "Stalwart asks its milter entry {} at {}, where the filter listens",
                    entry.id,
                    entry.address()
                )
            }),
        Err(why) => Some(format!("Stalwart's milters could not be asked ({why})")),
    }
}

/// Stalwart's milters, as the collector's API key reads them.
pub(super) fn stalwart_entries(config: &Config) -> Result<Vec<Entry>, String> {
    let key = Credentials::new(&config.credentials_directory)
        .read_secret(&config.collector.native_key)
        .map_err(|error| format!("the collector's API key: {error}"))?;
    JmapClient::new(&config.deployment.stalwart_url, &key)
        .with_timeout(Duration::from_secs(10))
        .get::<Entry>("MtaMilter", None, &["id", "host", "port", "enable"])
        .map_err(|error| error.to_string())
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
    let listening = entries::listening();
    match still_asked(
        configuration,
        loaded.as_ref(),
        listening.as_deref(),
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
    let listening = entries::listening();
    let Some(why) = still_asked(
        configuration,
        loaded.as_ref(),
        listening.as_deref(),
        stalwart_entries,
    ) else {
        return Ok(());
    };
    Err(format!(
        "Stalwart still asks Garrison's macro milter about every message, as far as this host \
         can tell, and would defer mail without it: {why}; nothing was changed. Remove the \
         [milter] section from {}, run `garrison stalwart setup` and uninstall then.",
        configuration.join("garrison.toml").display()
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn entries(list: &Value) -> Vec<Entry> {
        serde_json::from_value(list.clone()).unwrap()
    }

    /// Every state a run that would stop the filter can meet: the filter
    /// running or not, where it listens, Stalwart's milters as read, or no
    /// answer. Only where nothing can ask the filter is it stopped; another
    /// program's milter on this host keeps it no more than one elsewhere.
    #[test]
    fn the_filter_is_never_stopped_while_stalwart_may_ask_it() {
        let directory = tempfile::tempdir().unwrap();
        let configuration = directory.path();
        let config = garrison_testing::config(configuration, "http://127.0.0.1:9");
        let unasked = |_: &Config| -> Result<Vec<Entry>, String> { panic!("asked Stalwart") };
        // Not running: nothing to keep, and Stalwart is not even asked.
        assert_eq!(
            still_asked(configuration, Some(&config), None, unasked),
            None
        );
        let stored = json!([
            {"id": "a", "host": "127.0.0.1", "port": 8096, "enable": {"match": {}, "else": "false"}},
            {"id": "b", "host": "192.0.2.1", "port": 8096},
            {"id": "r", "host": "127.0.0.1", "port": 11332},
        ]);
        let read = |_: &Config| Ok(entries(&stored));
        let listening: &[u16] = &[8096];
        assert_eq!(
            still_asked(configuration, Some(&config), Some(listening), read),
            None
        );
        for (host, enable) in [
            ("127.0.0.1", json!(true)),
            ("localhost", json!(null)),
            ("0.0.0.0", json!(true)),
        ] {
            let stored = json!([{"id": "m", "host": host, "port": 8096, "enable": enable}]);
            let said = still_asked(configuration, Some(&config), Some(listening), |_| {
                Ok(entries(&stored))
            });
            assert!(
                said.is_some_and(|said| said.contains(&format!("entry m at {host}:8096"))),
                "{host}"
            );
        }
        // Where that cannot be told, the filter counts as asked.
        let refused = |_: &Config| Err("Stalwart did not answer".to_owned());
        let said = still_asked(configuration, Some(&config), Some(listening), refused).unwrap();
        assert!(
            said.contains("could not be asked (Stalwart did not answer)"),
            "{said}"
        );
        assert!(still_asked(configuration, None, Some(listening), unasked).is_some());
        let unseen = still_asked(configuration, Some(&config), Some(&[]), unasked).unwrap();
        assert!(unseen.contains("cannot be seen"), "{unseen}");
    }
}
