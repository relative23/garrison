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

use crate::states::services;
use crate::units;

const MARKER: &str = "collector-stopped";

pub(crate) fn run(path: &Path) -> u8 {
    let loaded = config::load(path);
    if let Err(error) = &loaded {
        log::warn!("{}", services::watch_unloaded(path, error));
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
        Ok(Outcome::NotKnown) => {
            log::warn!("{}", services::watch_not_known(&database));
            0
        }
        Ok(outcome) => {
            log::info!(
                "{}",
                match outcome {
                    Outcome::NeverRan => services::watch_never_ran(),
                    Outcome::Running | Outcome::NotKnown => services::watch_running(),
                    Outcome::Stopped => services::watch_stopped(),
                    Outcome::ToldStopped => services::watch_told_stopped(),
                    Outcome::ToldRunning => services::watch_told_running(),
                }
            );
            0
        }
        Err(error) => {
            log::error!("{}", services::watch_unfinished(error));
            1
        }
    }
}
