//! The macro milter's unit, which is the one service that does not always
//! run: only where the configuration has a `[milter]` section.
//!
//! `garrison stalwart setup` tells Stalwart of the filter and takes it out
//! again. The installer only starts it anew with a release, and must not
//! take it away while Stalwart still asks it: Stalwart would then defer
//! every message.

use std::path::Path;

use super::files::{Step, announce, run};
use super::system::unit_file;
use super::{CONFIG, SYSTEMCTL};
use crate::units;

/// Whether setup's note of the filter's entry in Stalwart is there.
fn asked(configuration: &Path) -> bool {
    configuration
        .join("credentials")
        .join(units::MILTER_ENTRY)
        .exists()
}

/// Whether the unit starts with the release. Where nothing asks the filter
/// and the configuration does not have it, it is stopped.
pub(super) fn runs() -> bool {
    let configuration = Path::new(CONFIG);
    let wanted = garrison_core::config::load(&configuration.join("garrison.toml"))
        .is_ok_and(|config| config.milter.is_some());
    if wanted {
        return unit_file(units::MILTER).exists();
    }
    if asked(configuration) {
        announce(
            "Stalwart still asks the macro milter, which the configuration no longer has. \
             Run `garrison stalwart setup`: it takes the filter out of Stalwart.",
        );
    } else {
        let _ = run(SYSTEMCTL, &["disable", "--now", units::MILTER]);
    }
    false
}

/// Uninstalling stops the filter, so Stalwart must have forgotten it first.
pub(super) fn forgotten(configuration: &Path) -> Step {
    if asked(configuration) {
        return Err(format!(
            "Stalwart still asks Garrison's macro milter about every message and would defer \
             mail without it; nothing was changed. Remove the [milter] section from {}, run \
             `garrison stalwart setup` and uninstall then.",
            configuration.join("garrison.toml").display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstalling_waits_until_stalwart_has_forgotten_the_filter() {
        let directory = tempfile::tempdir().unwrap();
        let credentials = directory.path().join("credentials");
        std::fs::create_dir(&credentials).unwrap();
        assert_eq!(forgotten(directory.path()), Ok(()));
        std::fs::write(credentials.join(units::MILTER_ENTRY), "b").unwrap();
        let refusal = forgotten(directory.path()).unwrap_err();
        assert!(refusal.contains("nothing was changed"), "{refusal}");
        assert!(refusal.contains("garrison stalwart setup"), "{refusal}");
    }
}
