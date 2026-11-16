//! What a provider receives and returns.
//!
//! A provider reads one kind of source and returns observations plus optional
//! metric samples. Providers never fail for an unavailable source: they return
//! an Unknown observation, so one missing service never hides the results of the
//! others. An error from a provider is a bug, reported as such in the snapshot.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use garrison_core::config::Deployment;
use garrison_core::observations::{NoModule, Observation};
use garrison_core::time::{self, Timestamp};

use crate::command::Runner;

/// What a provider keeps from one run to the next: one text under a key.
/// Nothing may depend on it being there; what is lost is asked for again.
pub trait Memory {
    fn recall(&self, key: &str) -> Option<String>;
    fn keep(&self, key: &str, value: &str);
}

/// A memory that keeps nothing.
#[derive(Debug)]
pub struct Forgetful;

impl Memory for Forgetful {
    fn recall(&self, _: &str) -> Option<String> {
        None
    }

    fn keep(&self, _: &str, _: &str) {}
}

/// When a collection run must be done with its checks, on the clock that
/// only runs forward. systemd ends a run that takes too long, and with it
/// everything the run had found: so a check that asks many times looks here
/// in between, and what is not asked in time is said, not waited for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline(Option<Instant>);

impl Deadline {
    /// No limit: for a check that is asked by hand, and for tests.
    pub const NONE: Deadline = Deadline(None);

    /// `time` from now.
    #[must_use]
    pub fn within(time: Duration) -> Self {
        Deadline(Instant::now().checked_add(time))
    }

    #[must_use]
    pub fn expired(self) -> bool {
        self.0.is_some_and(|until| Instant::now() >= until)
    }

    /// By when something that may take `most` must be done: then, or at the
    /// deadline if that comes first.
    #[must_use]
    pub fn by(self, most: Duration) -> Instant {
        let now = Instant::now();
        let then = now.checked_add(most).unwrap_or(now);
        self.0.map_or(then, |until| until.min(then))
    }
}

/// The key of Spamhaus' Data Query Service, as the collector read it from
/// its credential for this run: the lists written without it are asked
/// with it before their name.
#[derive(Clone, PartialEq, Eq)]
pub enum DqsKey {
    /// `collector.dqs_key` is not set.
    Unset,
    /// Its file gives no key: why, in words that hold no key.
    Missing(String),
    /// The key, one DNS label.
    Key(String),
}

impl fmt::Debug for DqsKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key stays out of logs and panic messages.
        match self {
            DqsKey::Unset => formatter.write_str("Unset"),
            DqsKey::Missing(why) => formatter.debug_tuple("Missing").field(why).finish(),
            DqsKey::Key(_) => formatter.write_str("Key(…)"),
        }
    }
}

/// Why a check that reads Stalwart with the collector's API key could not,
/// where the collector has none, as where its credential file is missing or
/// empty, and what makes one. Every card that needs the key says these
/// words, after a frame of its own, as it gives its other reasons.
pub const NO_KEY: &str =
    "the collector has no API key for Stalwart; run `garrison stalwart setup`, which makes one";

pub struct Context<'a> {
    pub deployment: &'a Deployment,
    pub now: Timestamp,
    /// When the run's checks must be done.
    pub deadline: Deadline,
    /// The collector's read-only management-API key, if it could be read;
    /// without it a check that needs it says [`NO_KEY`].
    pub native_key: Option<String>,
    /// User name and secret for the metrics exporter.
    pub metrics_credential: Option<(String, String)>,
    /// The key of Spamhaus' Data Query Service.
    pub dqs_key: DqsKey,
    pub events_database: PathBuf,
    pub runner: &'a dyn Runner,
    /// The status database, for what a provider asks only now and then.
    pub memory: &'a dyn Memory,
}

impl fmt::Debug for Context<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Secrets stay out of logs and panic messages.
        formatter
            .debug_struct("Context")
            .field("now", &self.now)
            .field("native_key", &self.native_key.as_ref().map(|_| "…"))
            .field("events_database", &self.events_database)
            .finish_non_exhaustive()
    }
}

impl Context<'_> {
    /// The collection time in the stored format.
    pub fn checked_at(&self) -> String {
        time::isoformat(self.now)
    }

    /// Seconds from `instant` to the collection time, from whole microseconds.
    #[allow(clippy::cast_precision_loss)]
    pub fn seconds_since(&self, instant: Timestamp) -> f64 {
        (self.now.as_microsecond() - instant.as_microsecond()) as f64 / 1_000_000.0
    }
}

/// One provider's results.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Report {
    pub observations: Vec<Observation>,
    pub gauges: BTreeMap<String, f64>,
    pub counters: BTreeMap<String, f64>,
}

impl Report {
    pub fn of(observation: Observation) -> Self {
        Report {
            observations: vec![observation],
            ..Report::default()
        }
    }

    #[must_use]
    pub fn gauge(mut self, name: impl Into<String>, value: f64) -> Self {
        self.gauges.insert(name.into(), value);
        self
    }
}

/// A provider could not build its report. This is a bug, not an unavailable source.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ProviderError(pub String);

impl From<NoModule> for ProviderError {
    fn from(error: NoModule) -> Self {
        ProviderError(error.to_string())
    }
}

pub type Collected = Result<Report, ProviderError>;

/// What a check does with a path of the host that one of its options names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    /// It reads the file or the folder there.
    Reads,
    /// It runs the program there.
    Runs,
    /// It measures the file system the path lies on, as `statvfs` does.
    Measures,
}

/// A path of the host that an option of a check names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPath<'a> {
    /// The option, as `garrison.toml` writes it.
    pub option: &'static str,
    pub path: &'a Path,
    pub used: Use,
}

/// One kind of source, configured by one `[[providers]]` table.
pub trait Provider {
    /// The provider's `type`, also the `provider` of its observations.
    fn name(&self) -> &'static str;

    /// The ids of the observations this provider reports, as far as its
    /// configuration alone decides them, also those it reports only where
    /// it finds something to say. An id two providers report can be stored
    /// for one of them only, so the configuration check refuses such a pair
    /// before anything runs. An id named after what it finds, a domain or a
    /// test, cannot be named beforehand and is left out.
    fn ids(&self) -> Vec<String> {
        Vec::new()
    }

    /// The paths of the host its options name. The collector's unit hides
    /// some places from the collector, while the configuration check runs as
    /// root, which sees them: it holds each of these against those places.
    fn paths(&self) -> Vec<HostPath<'_>> {
        Vec::new()
    }

    fn collect(&self, context: &Context<'_>) -> Collected;
}

#[cfg(test)]
mod tests {
    use crate::testing::{Canned, config, context};

    #[test]
    fn a_deadline_bounds_what_may_take_long() {
        use std::time::{Duration, Instant};

        use super::Deadline;
        let long = Duration::from_secs(3600);
        assert!(!Deadline::NONE.expired());
        assert!(Deadline::NONE.by(long) > Instant::now() + long / 2);
        let soon = Deadline::within(Duration::from_secs(60));
        assert!(!soon.expired());
        // What may take an hour must be done within the minute that is left,
        // and what takes a second within that second.
        assert!(soon.by(long) <= Instant::now() + Duration::from_secs(60));
        assert!(soon.by(Duration::from_secs(1)) <= Instant::now() + Duration::from_secs(1));
        let over = Deadline::within(Duration::ZERO);
        assert!(over.expired());
        assert!(over.by(long) <= Instant::now());
    }

    #[test]
    fn debug_output_hides_the_api_key() {
        let directory = tempfile::tempdir().unwrap();
        let (config, runner) = (config(directory.path()), Canned(String::new()));
        let mut context = context(&config, &runner);
        context.native_key = Some("collector-secret-key".into());
        context.dqs_key = super::DqsKey::Key("abcdefghijklmnopqrstuvwxyz".into());
        let text = format!("{context:?}");
        assert!(text.starts_with("Context { now: "), "{text}");
        assert!(text.contains("native_key: Some(\"…\")"), "{text}");
        assert!(!text.contains("collector-secret-key"), "{text}");
        assert_eq!(format!("{:?}", context.dqs_key), "Key(…)");
    }
}
