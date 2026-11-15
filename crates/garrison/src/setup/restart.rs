//! The services that hold secrets, started again so that they read new
//! ones.

use garrison_core::systemd::SYSTEMCTL;

use crate::{say, units};

/// The services read their credentials when they start; the collector starts
/// anew for every run. Services that are not running read the new secrets
/// when they start, as on a first setup before Garrison runs.
pub(super) fn restart() {
    let units = [units::INGEST, units::BROKER];
    let systemctl = |arguments: &[&str]| {
        std::process::Command::new(SYSTEMCTL)
            .args(arguments)
            .args(units)
            .stdout(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    if !rustix::process::geteuid().is_root() {
        say(
            "Settings reloaded. Restart garrison-ingest and garrison-broker so they read the new secrets.",
        );
    } else if !systemctl(&["is-active", "--quiet"]) {
        say("Settings reloaded; the services read the new secrets when they start.");
    } else if systemctl(&["try-restart"]) {
        say(
            "Settings reloaded; garrison-ingest and garrison-broker restarted with the new secrets.",
        );
    } else {
        say(
            "Settings reloaded. Restart garrison-ingest and garrison-broker so they read the new secrets.",
        );
    }
}
