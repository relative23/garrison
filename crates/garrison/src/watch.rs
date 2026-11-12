//! `garrison watch`: one look at whether the collector still runs, started
//! by a timer of its own (`garrison-watch.timer`). The collector reports
//! every other failure, so only something beside it can report its own.
//!
//! The look works without a configuration that loads, since a configuration
//! the collector refuses is the usual reason it stopped: the paths then are
//! the ones the units use, and the topic is the one the last run left.

use std::path::{Path, PathBuf};

use garrison_collector::notify::{Channels, Secrets};
use garrison_collector::watch::{Outcome, Watch};
use garrison_core::config::{self, Database};
use garrison_core::credentials::{Credentials, SecretSource};
use garrison_core::time;

const DATABASE: &str = "/var/lib/garrison/collector/status.sqlite";
const CREDENTIALS: &str = "/etc/garrison/credentials";
/// systemd names the unit's own state directory; this is where it is.
const STATE: &str = "/var/lib/garrison/watch";
const MARKER: &str = "collector-stopped";

pub(crate) fn run(path: &Path) -> u8 {
    let loaded = config::load(path);
    if let Err(error) = &loaded {
        log::warn!(
            "{} does not load ({error}); watching with what the last collection run left",
            path.display()
        );
    }
    let (database, credentials) = match &loaded {
        Ok(config) => (
            config.database(Database::Status),
            Credentials::from_environment(&config.credentials_directory),
        ),
        Err(_) => (
            PathBuf::from(DATABASE),
            Credentials::from_environment(Path::new(CREDENTIALS)),
        ),
    };
    // Without a configuration the secrets are those the units load by name.
    let read = |name: &str| {
        let source = SecretSource::Credential(name.to_owned());
        credentials
            .read_secret(&source)
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let secrets = match &loaded {
        Ok(config) => Secrets::read(&credentials, &config.notifications),
        Err(_) => Secrets {
            ntfy: read("ntfy-token"),
            webhook: read("notify-webhook-token"),
            mail: read("notify-mail-password"),
        },
    };
    let state =
        std::env::var_os("STATE_DIRECTORY").map_or_else(|| PathBuf::from(STATE), PathBuf::from);
    let watch = Watch {
        database: &database,
        marker: &state.join(MARKER),
        configured: loaded
            .as_ref()
            .map_err(drop)
            .map(|config| Channels::of(config, secrets.clone())),
        secrets,
        now: time::now(),
        roots: garrison_collector::fetch::roots(),
    };
    match watch.look() {
        Ok(outcome) => {
            log::info!(
                "{}",
                match outcome {
                    Outcome::NeverRan => "No collection run has finished yet",
                    Outcome::Running => "The collector runs",
                    Outcome::Stopped => "The collector has stopped",
                    Outcome::ToldStopped => "The collector has stopped; the channels were told",
                    Outcome::ToldRunning => "The collector runs again; the channels were told",
                }
            );
            0
        }
        Err(error) => {
            log::error!("The watch over the collector did not finish: {error}");
            1
        }
    }
}
