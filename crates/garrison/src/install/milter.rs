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
use super::{CONFIG, SYSTEMCTL, states};
use crate::doctor::milter::entries::{self, Entry};
use crate::state::State;
use crate::units;

/// Why Stalwart may still ask the filter that the configuration no longer
/// has, or `None` where nothing asks it. `listening`: the ports the filter
/// listens on, where it runs; `entries` asks Stalwart for its milters.
fn still_asked(
    configuration: &Path,
    loaded: Option<&Config>,
    listening: Option<&[u16]>,
    entries: impl FnOnce(&Config) -> Result<Vec<Entry>, State>,
) -> Option<State> {
    // A filter that does not run answers nobody, stopped or not.
    let listening = listening?;
    if listening.is_empty() {
        return Some(states::milter_unseen(units::MILTER));
    }
    let Some(config) = loaded else {
        return Some(states::milter_unloaded(
            &configuration.join("garrison.toml"),
        ));
    };
    match entries(config) {
        Ok(stored) => entries::ours(&stored, None, listening)
            .into_iter()
            .find(|entry| entry.asked())
            .map(|entry| states::milter_asked(&entry.id, &entry.address())),
        Err(why) => Some(states::milter_unasked(&why)),
    }
}

/// Stalwart's milters, as the collector's API key reads them.
pub(super) fn stalwart_entries(config: &Config) -> Result<Vec<Entry>, State> {
    let key = Credentials::new(&config.credentials_directory)
        .read_secret(&config.collector.native_key)
        .map_err(|error| states::io("the collector's API key", error))?;
    JmapClient::new(&config.deployment.stalwart_url, &key)
        .with_timeout(Duration::from_secs(10))
        .get::<Entry>("MtaMilter", None, &["id", "host", "port", "enable"])
        .map_err(|error| states::io("Stalwart", error))
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
        Some(why) => announce(&states::milter_kept(&why).to_string()),
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
    Err(states::milter_still_asked(
        &why,
        &configuration.join("garrison.toml"),
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
        let unasked = |_: &Config| -> Result<Vec<Entry>, State> { panic!("asked Stalwart") };
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
            let entry = states::milter_asked("m", &format!("{host}:8096"));
            assert_eq!(said, Some(entry), "{host}");
        }
        // Where that cannot be told, the filter counts as asked.
        let silent = || states::io("Stalwart", "did not answer");
        let refused = |_: &Config| Err(silent());
        let said = still_asked(configuration, Some(&config), Some(listening), refused);
        assert_eq!(said, Some(states::milter_unasked(&silent())));
        assert_eq!(
            still_asked(configuration, None, Some(listening), unasked),
            Some(states::milter_unloaded(
                &configuration.join("garrison.toml")
            ))
        );
        let unseen = still_asked(configuration, Some(&config), Some(&[]), unasked);
        assert_eq!(unseen, Some(states::milter_unseen(units::MILTER)));
    }
}
