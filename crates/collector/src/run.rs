//! One collection run: every provider, one snapshot, metric samples.
//!
//! A failing provider is reported in the snapshot and does not stop the
//! others. The collector is started by a systemd timer and exits after each
//! run.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use garrison_core::config::{Config, ConfigError, Database};
use garrison_core::credentials::Credentials;
use garrison_core::json;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Observation, State};
use garrison_core::sqlite::SqliteError;
use garrison_core::time::{self, Timestamp};
use serde::{Deserialize, Serialize};

use crate::command::Runner;
use crate::context::{Context, Provider};
use crate::notify::{Channels, Secrets};
use crate::snapshot::{ProviderError, SCHEMA, Snapshot};
use crate::store::StatusStore;

const MAX_CREDENTIAL: usize = 16384;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("Providers produced duplicate observation IDs: {0}")]
    Duplicates(String),
    #[error("status database: {0}")]
    Store(#[from] SqliteError),
}

fn native_key(config: &Config, credentials: &Credentials) -> Option<String> {
    let key = credentials.read_secret(&config.collector.native_key).ok();
    if key.is_none() {
        log::warn!("The collector API key is unavailable; Stalwart observations are Unknown");
    }
    key
}

/// The scrape credential file, as `garrison stalwart setup` writes it and
/// the collector reads it.
#[derive(Clone, Deserialize, Serialize)]
pub struct ScrapeCredential {
    pub username: String,
    pub secret: String,
}

impl fmt::Debug for ScrapeCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The secret stays out of logs and panic messages.
        formatter
            .debug_struct("ScrapeCredential")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

fn metrics_credential(config: &Config, credentials: &Credentials) -> Option<(String, String)> {
    let source = config.collector.metrics_credential.as_ref()?;
    let value = credentials
        .read_private(source, MAX_CREDENTIAL)
        .ok()
        .and_then(|data| json::parse(&data, MAX_CREDENTIAL).ok());
    let Some(value) = value else {
        log::warn!("The metrics credential is unavailable");
        return None;
    };
    let ScrapeCredential { username, secret } = json::object(value).ok()?;
    Some((username, secret))
}

/// The observation that stands in for a provider that failed.
fn failed(context: &Context<'_>, name: &str, kind: &str) -> Option<Observation> {
    Observation::new(
        format!("collector.{name}"),
        name,
        format!("Provider {name}"),
        [ModuleId::Services],
        Evidence::Process,
        State::Unknown,
        context.checked_at(),
        "collector",
    )
    .ok()
    .map(|observation| {
        observation.with_findings(vec![format!(
            "The provider {kind}; see the collector journal."
        )])
    })
}

/// Run `providers` once and store the snapshot; the snapshot is returned.
pub fn collect_from(
    providers: &[Box<dyn Provider>],
    config: &Config,
    credentials: &Credentials,
    runner: &dyn Runner,
    now: Timestamp,
) -> Result<Snapshot, Error> {
    let mut store = StatusStore::open(
        &config.database(Database::Status),
        config.collector.history_days,
    )?;
    let context = Context {
        deployment: &config.deployment,
        now,
        native_key: native_key(config, credentials),
        metrics_credential: metrics_credential(config, credentials),
        events_database: config.database(Database::Events),
        runner,
        memory: &store,
    };
    let mut observations = Vec::new();
    let mut gauges = BTreeMap::new();
    let mut counters = BTreeMap::new();
    let mut errors = Vec::new();
    for provider in providers {
        // A provider bug must not hide all other results.
        let outcome = catch_unwind(AssertUnwindSafe(|| provider.collect(&context)));
        let kind = match outcome {
            Ok(Ok(report)) => {
                observations.extend(report.observations);
                gauges.extend(report.gauges);
                counters.extend(report.counters);
                continue;
            }
            Ok(Err(error)) => {
                log::error!("Provider {} failed: {error}", provider.name());
                "failed"
            }
            Err(_) => {
                log::error!("Provider {} failed: it panicked", provider.name());
                "crashed"
            }
        };
        errors.push(ProviderError {
            provider: provider.name().to_owned(),
            error: kind.to_owned(),
        });
        observations.extend(failed(&context, provider.name(), kind));
    }
    let mut seen = BTreeSet::new();
    let duplicates: BTreeSet<&str> = observations
        .iter()
        .map(|observation| observation.id.as_str())
        .filter(|id| !seen.insert(*id))
        .collect();
    if !duplicates.is_empty() {
        let names: Vec<String> = duplicates.iter().map(|id| format!("'{id}'")).collect();
        return Err(Error::Duplicates(format!("[{}]", names.join(", "))));
    }
    let channels = Channels::of(config, Secrets::read(credentials, &config.notifications));
    observations.extend(crate::notify::after_run(
        &channels,
        &observations,
        &store,
        now,
    ));
    garrison_core::observations::with_aliases(
        &mut observations,
        garrison_core::observations::RENAMED,
    );
    // For the watch over the collector, should this configuration stop loading.
    crate::watch::remember(&store, &channels);
    let snapshot = Snapshot {
        schema_version: SCHEMA,
        collected_at: context.checked_at(),
        observations,
        provider_errors: errors,
    };
    store.write(now.as_second(), &snapshot, &gauges, &counters)?;
    log::info!(
        "Collected {} observations from {} providers",
        snapshot.observations.len(),
        providers.len()
    );
    Ok(snapshot)
}

/// Build the configured providers and run them once, now.
pub fn collect(
    config: &Config,
    credentials: &Credentials,
    runner: &dyn Runner,
) -> Result<Snapshot, Error> {
    let providers = crate::providers::build(&config.collector.providers)?;
    collect_from(&providers, config, credentials, runner, time::now())
}

#[cfg(test)]
mod tests;
