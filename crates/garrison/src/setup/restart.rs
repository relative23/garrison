//! The services that hold secrets, started again so that they read new
//! ones.

use std::fs;
use std::path::Path;

use garrison_core::systemd::SYSTEMCTL;

use crate::{say, units};

/// Where systemd keeps the credentials it loaded for a unit while it runs.
const LOADED: &str = "/run/credentials";
/// The services that hold a secret, and its file: each read it when it
/// started.
pub(super) const HELD: [(&str, &str); 2] = [
    (units::INGEST, "webhook-signature-key"),
    (units::BROKER, "broker-native-key"),
];

/// Whether a file of the services' secrets holds none, so that setup makes
/// it anew: a running service holds the secrets it read when it started,
/// and one that started with an empty file has none.
pub(super) fn unheld(directory: &Path) -> bool {
    HELD.iter()
        .any(|(_, name)| !super::keys::holds_key(&directory.join(name)))
}

/// Whether a running service holds another secret than its file in
/// `directory` holds now. systemd copied the file for the unit when it
/// started, so a copy that differs means the file was replaced since: by a
/// rotation, also one that failed before its restart, by a new key for one
/// that Stalwart no longer had, or by hand. Only root reads those copies,
/// and a service that does not run has none.
pub(super) fn stale(directory: &Path) -> bool {
    stale_in(directory, Path::new(LOADED))
}

fn stale_in(directory: &Path, loaded: &Path) -> bool {
    HELD.iter().any(|(unit, name)| {
        fs::read(loaded.join(unit).join(name))
            .is_ok_and(|copy| fs::read(directory.join(name)).ok() != Some(copy))
    })
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// A file that holds no secret, as an empty one, is made anew as a
    /// missing one is, and its service must start again to read it.
    #[test]
    fn a_file_that_holds_no_secret_is_made_anew() {
        let directory = tempfile::tempdir().unwrap();
        for (_, name) in HELD {
            fs::write(directory.path().join(name), "0123456789abcdef-secret\n").unwrap();
        }
        assert!(!unheld(directory.path()));
        for written in ["", "\n", "short\n"] {
            fs::write(directory.path().join("broker-native-key"), written).unwrap();
            assert!(unheld(directory.path()), "{written:?}");
        }
        fs::remove_file(directory.path().join("broker-native-key")).unwrap();
        assert!(unheld(directory.path()));
    }

    #[test]
    fn a_service_holds_another_secret_where_its_copy_and_its_file_differ() {
        let directory = tempfile::tempdir().unwrap();
        let files = directory.path().join("credentials");
        let loaded = directory.path().join("run");
        fs::create_dir_all(&files).unwrap();
        for (unit, name) in HELD {
            fs::write(files.join(name), "old").unwrap();
            fs::create_dir_all(loaded.join(unit)).unwrap();
            fs::write(loaded.join(unit).join(name), "old").unwrap();
        }
        assert!(!stale_in(&files, &loaded));
        // A rotation that stopped before its restart left new files.
        fs::write(files.join("broker-native-key"), "new").unwrap();
        assert!(stale_in(&files, &loaded));
        // A service that does not run holds nothing.
        fs::remove_dir_all(loaded.join(units::BROKER)).unwrap();
        assert!(!stale_in(&files, &loaded));
        fs::remove_file(files.join("webhook-signature-key")).unwrap();
        assert!(stale_in(&files, &loaded));
    }
}
