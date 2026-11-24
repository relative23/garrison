//! The services that hold secrets, started again so that they read new
//! ones.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use garrison_core::files::{self, Form, Holds};
use garrison_core::systemd::SYSTEMCTL;

use crate::units;

/// Where systemd keeps the credentials it loaded for a unit while it runs.
const LOADED: &str = "/run/credentials";
/// The services that hold a secret, and its file: each read it when it
/// started.
const HELD: [(&str, &str); 2] = [
    (units::INGEST, "webhook-signature-key"),
    (units::BROKER, "broker-native-key"),
];

/// The files in `directory` whose running service holds another secret
/// than the file holds now. systemd copied the file for the unit when it
/// started, so a copy that differs means the file was replaced since: by a
/// rotation, also one that failed before its restart, by a new key for one
/// that Stalwart no longer had, or by hand. Only root reads those copies,
/// and a service that does not run has none.
pub(super) fn stale(directory: &Path) -> BTreeSet<&'static str> {
    stale_in(directory, Path::new(LOADED))
}

fn stale_in(directory: &Path, loaded: &Path) -> BTreeSet<&'static str> {
    HELD.iter()
        .filter(|(unit, name)| {
            fs::read(loaded.join(unit).join(name))
                .is_ok_and(|copy| fs::read(directory.join(name)).ok() != Some(copy))
        })
        .map(|(_, name)| *name)
        .collect()
}

/// The units whose secret's file is one of `files` and holds a secret
/// they can start with. Started again onto a file without one, a service
/// would not start, while the copy it runs with may still work.
fn units(directory: &Path, files: &BTreeSet<&str>) -> Vec<&'static str> {
    HELD.iter()
        .filter(|(_, name)| {
            files.contains(name)
                && files::holds(&directory.join(name), Form::Token)
                    .is_ok_and(|held| held == Holds::Secret)
        })
        .map(|(unit, _)| *unit)
        .collect()
}

/// Start the services whose secret's file is one of `files` again, so that
/// they read the new secrets, and say so; the collector starts anew for
/// every run. Services that are not running read the new secrets when they
/// start, as on a first setup before Garrison runs.
pub(super) fn restart(directory: &Path, files: &BTreeSet<&str>) -> Option<String> {
    let units = units(directory, files);
    if units.is_empty() {
        return None;
    }
    let one = units.len() == 1;
    let named = units
        .iter()
        .map(|unit| unit.trim_end_matches(".service"))
        .collect::<Vec<_>>()
        .join(" and ");
    let systemctl = |arguments: &[&str]| {
        std::process::Command::new(SYSTEMCTL)
            .args(arguments)
            .args(&units)
            .stdout(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    let asked = if one {
        format!("Restart {named} so it reads the new secret.")
    } else {
        format!("Restart {named} so they read the new secrets.")
    };
    Some(if !rustix::process::geteuid().is_root() {
        asked
    } else if !systemctl(&["is-active", "--quiet"]) {
        if one {
            format!("{named} reads the new secret when it starts.")
        } else {
            "The services read the new secrets when they start.".to_owned()
        }
    } else if systemctl(&["try-restart"]) {
        let secrets = if one { "secret" } else { "secrets" };
        format!("{named} restarted with the new {secrets}.")
    } else {
        asked
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(stale_in(&files, &loaded), BTreeSet::new());
        // A rotation that stopped before its restart left new files.
        fs::write(files.join("broker-native-key"), "new").unwrap();
        assert_eq!(
            stale_in(&files, &loaded),
            BTreeSet::from(["broker-native-key"])
        );
        // A service that does not run holds nothing.
        fs::remove_dir_all(loaded.join(units::BROKER)).unwrap();
        assert_eq!(stale_in(&files, &loaded), BTreeSet::new());
        fs::remove_file(files.join("webhook-signature-key")).unwrap();
        assert_eq!(
            stale_in(&files, &loaded),
            BTreeSet::from(["webhook-signature-key"])
        );
    }

    /// Only the services whose own secret's file was written anew start
    /// again, each only onto a file that holds a secret it can start with:
    /// a receiver started onto an empty file would not start, while the key
    /// it runs with still works.
    #[test]
    fn only_the_services_whose_file_was_written_anew_start_again_onto_a_key() {
        if rustix::process::geteuid().is_root() {
            return; // Root would ask systemd.
        }
        let directory = tempfile::tempdir().unwrap();
        let key = "a-key-of-sixteen-characters-or-more";
        fs::write(directory.path().join("broker-native-key"), key).unwrap();
        fs::write(directory.path().join("webhook-signature-key"), "").unwrap();
        let both = BTreeSet::from(["broker-native-key", "webhook-signature-key"]);
        let restarted = |files: &BTreeSet<&str>| restart(directory.path(), files);
        assert_eq!(
            restarted(&both).as_deref(),
            Some("Restart garrison-broker so it reads the new secret.")
        );
        assert_eq!(restarted(&BTreeSet::from(["webhook-signature-key"])), None);
        assert_eq!(restarted(&BTreeSet::new()), None);
        fs::write(directory.path().join("webhook-signature-key"), key).unwrap();
        assert_eq!(
            restarted(&both).as_deref(),
            Some("Restart garrison-ingest and garrison-broker so they read the new secrets.")
        );
        assert_eq!(
            restarted(&BTreeSet::from(["webhook-signature-key"])).as_deref(),
            Some("Restart garrison-ingest so it reads the new secret.")
        );
    }
}
