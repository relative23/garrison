//! After a failed upgrade: back to the release that ran, with a state it
//! can read.
//!
//! By the time a new release fails to start or to stay up, its services may
//! have opened their databases and raised their schema, and a collection run
//! of the new timer may have done the same to the status database. The
//! release that ran refuses to open such a database. So before it starts
//! again, every writer stops and each database whose schema rose goes back
//! to its copy from before the upgrade; the others keep what they recorded.
//!
//! The release counts as running only when it reads every database and its
//! services stay up. Otherwise the links stay as the upgrade set them:
//! `previous` then still names the release to return to, and `install
//! --rollback --restore-state` is the second attempt.

use std::path::Path;

use garrison_core::config;

use super::files::{Step, announce, switch};
use super::system::install_system_files;
use super::{BASE, CONFIG, cli, command, start, state, stop_services};

/// How the switch back ended, for the installer's last line.
pub(super) fn fall_back(
    old: &Path,
    earlier: Option<&Path>,
    attempted: &Path,
    backup: Option<&Path>,
) -> String {
    announce("Start failed; switching back to the previous release.");
    match switched_back(old, earlier, backup) {
        Ok(()) => "the previous release is running".to_owned(),
        Err(error) => {
            // Nothing of a release that is not current keeps running, and
            // `previous` keeps naming the release to return to.
            stop_services();
            let kept = switch(&Path::new(BASE).join("current"), attempted)
                .and_then(|()| switch(&Path::new(BASE).join("previous"), old));
            let again = format!(
                "`{} install --rollback --restore-state` returns to it with the state from \
                 before the upgrade",
                command::name()
            );
            match kept {
                Ok(()) => format!("the previous release did not start either ({error}); {again}"),
                Err(links) => format!(
                    "the previous release did not start either ({error}), and the links \
                     could not be set back ({links})"
                ),
            }
        }
    }
}

/// Return what the new release migrated, then start `old` and see that it
/// reads the state and stays up.
fn switched_back(old: &Path, earlier: Option<&Path>, backup: Option<&Path>) -> Step {
    // A service of the new release that still runs, or a collection run its
    // timer started, would write into a database that is being replaced.
    stop_services();
    if let Some(backup) = backup {
        let settings = Path::new(CONFIG).join("garrison.toml");
        let config = config::load(&settings)
            .map_err(|error| format!("cannot load {}: {error}", settings.display()))?;
        let returned = state::restore_migrated(backup, &config)?;
        if !returned.is_empty() {
            announce(&format!(
                "The new release had changed the schema of: {}. Returned to the copy from \
                 before the upgrade in {}; the other databases keep their data.",
                returned.join(", "),
                backup.display()
            ));
        }
    }
    let base = Path::new(BASE);
    switch(&base.join("current"), old)?;
    install_system_files(old)?;
    // Only the release itself knows which schemas it reads. The collector
    // opens its database when its timer runs, after this installer is gone:
    // a database it cannot read must be found now.
    if !cli(old, &["self-check"])?.status.success() {
        return Err("it cannot read the current state".to_owned());
    }
    start(old)?;
    // `previous` as it was before the upgrade.
    let previous = base.join("previous");
    if let Some(earlier) = earlier {
        return switch(&previous, earlier);
    }
    let _ = std::fs::remove_file(&previous);
    Ok(())
}
