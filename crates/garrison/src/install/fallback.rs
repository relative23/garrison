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
use super::{BASE, CONFIG, cli, command, name, start, state, stop_services};

/// Back to `old`, the release that ran, from `attempted`: what the new
/// release migrated goes back to its copy in `backup`, `old` must read the
/// state and stay up, and `previous` names `earlier` again. Where that
/// fails, nothing of a release that is not current keeps running, and the
/// links are set so that `install --rollback --restore-state` is the second
/// attempt; the error says so. Where `current` did not name `attempted` yet,
/// it stays at `old`.
pub(super) fn switch_back(
    old: &Path,
    earlier: Option<&Path>,
    attempted: &Path,
    backup: Option<&Path>,
) -> Step {
    let base = Path::new(BASE);
    let switched = std::fs::canonicalize(base.join("current")).ok().as_deref() == Some(attempted);
    let mut returned = state::Returned::default();
    switched_back(old, earlier, backup, &mut returned).map_err(|failure| {
        stop_services();
        let kept = if switched {
            switch(&base.join("current"), attempted)
                .and_then(|()| switch(&base.join("previous"), old))
        } else {
            switch(&base.join("current"), old)
        };
        let what = match failure {
            Failure::Before(error) => format!("switching back to {} failed ({error})", name(old)),
            Failure::Start(error) => format!("the previous release did not start either ({error})"),
        };
        let went = backup.map_or_else(String::new, |backup| returned.said(backup));
        match kept {
            Ok(()) => format!(
                "{what}.{went} `{} install --rollback --restore-state` returns to it with the state \
                 from before the upgrade",
                command::name()
            ),
            Err(links) => format!("{what}, and the links could not be set back ({links}).{went}"),
        }
    })
}

/// Why a switch back failed: before the release that ran started again,
/// or as it started.
enum Failure {
    Before(String),
    Start(String),
}

/// Return what the new release migrated, then start `old` and see that it
/// reads the state and stays up.
fn switched_back(
    old: &Path,
    earlier: Option<&Path>,
    backup: Option<&Path>,
    returned: &mut state::Returned,
) -> Result<(), Failure> {
    // A service of the new release that still runs, or a collection run its
    // timer started, would write into a database that is being replaced.
    stop_services();
    if let Some(backup) = backup {
        let settings = Path::new(CONFIG).join("garrison.toml");
        let config = config::load(&settings).map_err(|error| {
            Failure::Before(format!("cannot load {}: {error}", settings.display()))
        })?;
        state::restore_migrated(backup, &config, returned).map_err(Failure::Before)?;
        let went = returned.said(backup);
        if !went.is_empty() {
            announce(&format!(
                "The new release had changed what the release that ran cannot read.{went} The \
                 other databases keep their data."
            ));
        }
    }
    let base = Path::new(BASE);
    switch(&base.join("current"), old).map_err(Failure::Before)?;
    install_system_files(old).map_err(Failure::Before)?;
    // Only the release itself knows which schemas it reads. The collector
    // opens its database when its timer runs, after this installer is gone:
    // a database it cannot read must be found now.
    let checked = cli(old, &["self-check"]).map_err(Failure::Before)?;
    if !checked.status.success() {
        return Err(Failure::Before(format!(
            "{} cannot read the current state, as its self-check says of {}",
            name(old),
            state::unreadable(&checked.stdout)
        )));
    }
    start(old).map_err(Failure::Start)?;
    // `previous` as it was before the upgrade.
    let previous = base.join("previous");
    if let Some(earlier) = earlier {
        return switch(&previous, earlier).map_err(Failure::Before);
    }
    let _ = std::fs::remove_file(&previous);
    Ok(())
}
