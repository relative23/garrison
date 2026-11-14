//! `garrison watch`: one look at whether the collector still runs, started
//! by a timer of its own (`garrison-watch.timer`). The collector reports
//! every other failure, so only something beside it can report its own.
//!
//! The look works without a configuration that loads, since a configuration
//! the collector refuses is the usual reason it stopped: the paths then are
//! the ones the units use, and the channels are the ones the last run left.

use std::path::{Path, PathBuf};

use garrison_collector::notify::{Channels, Secrets};
use garrison_collector::watch::{Outcome, Watch};
use garrison_core::config::{self, Database};
use garrison_core::credentials::Credentials;
use garrison_core::time;

use crate::units;

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
            Path::new(units::STATE)
                .join(Database::Status.writer())
                .join(Database::Status.file_name()),
            Credentials::from_environment(Path::new(units::CREDENTIALS)),
        ),
    };
    // Without a configuration the secrets are those the units load by name.
    let secrets = match &loaded {
        Ok(config) => Secrets::read(&credentials, &config.notifications),
        Err(_) => Secrets::loaded(&credentials),
    };
    // systemd names the unit's own state directory; without it, where it is.
    let state = std::env::var_os("STATE_DIRECTORY")
        .map_or_else(|| Path::new(units::STATE).join("watch"), PathBuf::from);
    let watch = Watch {
        database: &database,
        marker: &state.join(MARKER),
        configured: loaded
            .as_ref()
            .map_err(drop)
            .map(|config| Channels::of(config, secrets.clone()).located(&credentials)),
        secrets,
        credentials: credentials.clone(),
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
