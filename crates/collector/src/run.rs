//! One collection run: every provider, one snapshot, metric samples.
//!
//! A failing provider is reported in the snapshot and does not stop the
//! others. The collector is started by a systemd timer and exits after each
//! run.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, TryLockError};
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use garrison_core::config::{Config, ConfigError, Database};
use garrison_core::credentials::Credentials;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Observation, Required, State};
use garrison_core::sqlite::SqliteError;
use garrison_core::time::{self, Timestamp};

use crate::command::Runner;
use crate::context::{Context, Deadline, Provider};
use crate::notify::{Channels, Secrets};
use crate::snapshot::{ProviderError, SCHEMA, Snapshot};
use crate::store::StatusStore;

mod credentials;

pub use credentials::ScrapeCredential;
use credentials::{dqs_key, metrics_credential, native_key};

/// A check that took this long is named in the journal.
const SLOW: Duration = Duration::from_secs(10);

/// The time one run has. systemd ends the unit after 120 seconds
/// (`TimeoutStartSec`), and a run that is ended stores nothing, not even
/// what the quick checks found. So the run keeps its own, shorter times.
#[derive(Clone, Copy, Debug)]
pub struct Time {
    /// No check begins after this, and a check that asks many times stops
    /// asking.
    pub checks: Duration,
    /// The notifications are sent or given up by then; the snapshot is
    /// written after.
    pub run: Duration,
    /// What an earlier release kept of a key of Spamhaus' Data Query Service
    /// is cleared from the status database by then, after the snapshot is
    /// stored, and systemd is asked for more time while that runs: on a disk
    /// that writes 1 MB a second, some 400 MB of history. The watch counts
    /// from the snapshot and sees no stop before ten minutes.
    pub rebuild: Duration,
}

impl Time {
    /// What the collector's unit leaves room for.
    pub const OF_A_RUN: Time = Time {
        checks: Duration::from_secs(70),
        run: Duration::from_secs(100),
        rebuild: Duration::from_secs(480),
    };
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("status database: {0}")]
    Store(#[from] SqliteError),
    /// Another run holds the state directory: this one collects nothing.
    #[error("another collection run is under way")]
    Busy,
    #[error("the collector's state directory {}: {}", .0.display(), .1)]
    Directory(PathBuf, io::Error),
}

/// Held for the whole of a run: a second run at the same time, such as a
/// `garrison collect` by hand beside the timer's, ends without collecting.
/// Two runs whose readings cross would count a counter's events twice: the
/// one that read first and writes last leaves its older reading behind.
/// The lock is the state directory's own, so that root and the collector's
/// user share it without a file that belongs to either; the kernel lets it
/// go when the run ends, however it ends.
fn alone(database: &Path) -> Result<File, Error> {
    let directory = database
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let failed = |error| Error::Directory(directory.to_owned(), error);
    fs::create_dir_all(directory).map_err(failed)?;
    let held = File::open(directory).map_err(failed)?;
    match held.try_lock() {
        Ok(()) => Ok(held),
        Err(TryLockError::WouldBlock) => Err(Error::Busy),
        Err(TryLockError::Error(error)) => Err(failed(error)),
    }
}

/// One of the configured providers, as the run speaks of it.
struct Named<'a> {
    /// The provider's type.
    name: &'a str,
    /// Which of the providers of its type it is, from one.
    place: usize,
    /// The type, and where more than one of it is configured also the
    /// provider's place in the configuration, as `garrison check-config`
    /// names it: a type alone would not say which of them failed.
    label: String,
}

impl<'a> Named<'a> {
    /// Every provider of `providers` with its name, in their order.
    fn all(providers: &'a [Box<dyn Provider>]) -> Vec<Named<'a>> {
        let mut places: BTreeMap<&str, usize> = BTreeMap::new();
        let mut named: Vec<Named<'a>> = Vec::new();
        for (index, provider) in providers.iter().enumerate() {
            let name = provider.name();
            let place = places.entry(name).or_insert(0);
            *place += 1;
            named.push(Named {
                name,
                place: *place,
                label: format!("{name} (providers[{index}])"),
            });
        }
        for provider in &mut named {
            if places.get(provider.name) == Some(&1) {
                provider.label = provider.name.to_owned();
            }
        }
        named
    }
}

/// The observation that stands in for a provider that failed or was not
/// run; `said` is its finding. The second and later providers of a type get
/// an id of their own, so that two of a type that both fail do not report
/// one id.
fn stand_in(context: &Context<'_>, provider: &Named<'_>, said: String) -> Option<Observation> {
    let Named { name, place, label } = provider;
    let id = if *place > 1 {
        format!("collector.{name}.{place}")
    } else {
        format!("collector.{name}")
    };
    Observation::new(Required {
        id: &id,
        provider: name,
        title: &format!("Provider {label}"),
        modules: [ModuleId::Services],
        evidence: Evidence::Process,
        state: State::Unknown,
        checked_at: &context.checked_at(),
        source: "collector",
    })
    .ok()
    .map(|observation| observation.with_findings(vec![said]))
}

/// Keep the first observation of each id and say which ids came more than
/// once. The configuration check refuses the providers it can tell will do
/// this; what it cannot tell must not cost the snapshot of every run.
fn without_repeats(
    context: &Context<'_>,
    observations: &mut Vec<Observation>,
) -> Option<Observation> {
    let (mut seen, mut repeated) = (BTreeSet::new(), BTreeSet::new());
    observations.retain(|observation| {
        let first = seen.insert(observation.id.clone());
        if !first {
            repeated.insert(observation.id.clone());
        }
        first
    });
    if repeated.is_empty() {
        return None;
    }
    let names: Vec<String> = repeated.into_iter().collect();
    let names = names.join(", ");
    log::error!("More than one provider reported: {names}; the first of each was kept");
    Observation::new(Required {
        id: "collector.duplicates",
        provider: "collector",
        title: "Checks that report the same observation",
        modules: [ModuleId::Services],
        evidence: Evidence::Process,
        state: State::Unknown,
        checked_at: &context.checked_at(),
        source: "collector",
    })
    .ok()
    .map(|observation| {
        observation.with_findings(vec![format!(
            "Reported by more than one check, and kept as it came first: {names}. \
             `garrison check-config` names providers that report the same observation."
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
    collect_within(providers, config, credentials, runner, now, Time::OF_A_RUN)
}

/// The same, within `time`.
pub fn collect_within(
    providers: &[Box<dyn Provider>],
    config: &Config,
    credentials: &Credentials,
    runner: &dyn Runner,
    now: Timestamp,
    time: Time,
) -> Result<Snapshot, Error> {
    let _alone = alone(&config.database(Database::Status))?;
    let run = Deadline::within(time.run);
    let rebuild = Instant::now() + time.rebuild;
    let mut store = StatusStore::open(
        &config.database(Database::Status),
        config.collector.history_days,
    )?;
    let context = Context {
        deployment: &config.deployment,
        now,
        deadline: Deadline::within(time.checks),
        native_key: native_key(config, credentials, &store),
        metrics_credential: metrics_credential(config, credentials, &store),
        dqs_key: dqs_key(config, credentials),
        events_database: config.database(Database::Events),
        runner,
        memory: &store,
    };
    let mut observations = Vec::new();
    let mut gauges = BTreeMap::new();
    let mut counters = BTreeMap::new();
    let mut errors = Vec::new();
    for (provider, named) in providers.iter().zip(Named::all(providers)) {
        let label = &named.label;
        // What is not begun in time is said, not waited for: the run ends
        // with a snapshot of what was found. Not run is no failure of it.
        if context.deadline.expired() {
            log::warn!("Provider {label} was not run: the run's time was used up");
            let said = "Not run: the checks before it used up the time of this collection run.";
            observations.extend(stand_in(&context, &named, said.to_owned()));
            continue;
        }
        let began = Instant::now();
        // A provider bug must not hide all other results.
        let outcome = catch_unwind(AssertUnwindSafe(|| provider.collect(&context)));
        let took = began.elapsed();
        if took >= SLOW {
            log::warn!("Provider {label} took {} s", took.as_secs());
        } else {
            log::debug!("Provider {label} took {} ms", took.as_millis());
        }
        let kind = match outcome {
            Ok(Ok(report)) => {
                observations.extend(report.observations);
                gauges.extend(report.gauges);
                counters.extend(report.counters);
                continue;
            }
            Ok(Err(error)) => {
                log::error!("Provider {label} failed: {error}");
                "failed"
            }
            Err(_) => {
                log::error!("Provider {label} failed: it panicked");
                "crashed"
            }
        };
        errors.push(ProviderError {
            provider: label.clone(),
            error: kind.to_owned(),
        });
        let said = format!("The provider {kind}; see the collector journal.");
        observations.extend(stand_in(&context, &named, said));
    }
    let repeats = without_repeats(&context, &mut observations);
    observations.extend(repeats);
    let channels = Channels::of(config, Secrets::read(credentials, &config.notifications))
        .located(credentials);
    // The channels get what is left of the run's time: a channel that does
    // not answer must not cost the snapshot.
    observations.extend(crate::notify::after_run(
        &channels,
        &observations,
        &store,
        now,
        run,
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
    // Last, once the snapshot is stored: a rebuild that takes long costs
    // nothing of the run.
    store.clear_residue(now.as_second(), rebuild);
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
mod credentials_tests;
#[cfg(test)]
mod journal_tests;
#[cfg(test)]
mod tests;
