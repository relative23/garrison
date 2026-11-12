//! The macro milter's entry in Stalwart.
//!
//! Stalwart asks a milter only where one is entered, with its host and port.
//! Where the configuration has a `[milter]` section, setup enters Garrison's
//! own; where the section is gone, setup takes that entry out again, since
//! an entry for a filter that no longer runs would make Stalwart defer all
//! mail. A milter has no name or description to tell Garrison's from
//! another, so setup keeps the entry's ID in a file beside the credentials.
//!
//! The order keeps mail flowing: the filter runs and answers before
//! Stalwart is told of it, and it stops only after Stalwart has forgotten
//! it.

use std::fs;
use std::path::Path;
use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::systemd::SYSTEMCTL;
use serde::{Deserialize, Serialize};

use super::objects::{Created, NEW, Set};
use super::{Admin, write_secret};
use crate::units;

/// The entry as setup writes it; Stalwart fills in the rest: asked when a
/// message's data has arrived, protocol 6, its own timeouts.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Milter {
    host: &'static str,
    port: u16,
    /// Defer mail while the filter cannot be reached, or take it unscanned.
    temp_fail_on_error: bool,
}

#[derive(Debug, Deserialize)]
struct Stored {
    id: String,
}

fn systemctl(arguments: &[&str]) -> bool {
    std::process::Command::new(SYSTEMCTL)
        .args(arguments)
        .arg(units::MILTER)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Whether this is a host where setup may start and stop the filter's unit.
fn managed() -> bool {
    rustix::process::geteuid().is_root()
        && Path::new("/etc/systemd/system")
            .join(units::MILTER)
            .exists()
}

/// Before anything changes: where the configuration switches the filter on,
/// it must answer. Root starts it anew first, so that it runs with the
/// configuration as it is now.
pub(super) fn prepare(config: &Config) -> Result<(), String> {
    let Some(milter) = &config.milter else {
        return Ok(());
    };
    if managed() {
        systemctl(&["enable", "--quiet"]);
        systemctl(&["restart"]);
    }
    let mut problem = String::new();
    for _ in 0..10 {
        match garrison_milter::answers(milter.port, Duration::from_secs(2)) {
            Ok(()) => return Ok(()),
            Err(error) => problem = error,
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "The macro milter does not answer on 127.0.0.1:{} ({problem}). Nothing was changed: \
         Stalwart would defer mail while it asks a filter that is not there. \
         `journalctl -u {} -n 20` shows why it does not run.",
        milter.port,
        units::MILTER
    ))
}

/// After Stalwart has read its settings again: where the configuration no
/// longer has the filter, root stops it; what was done, if anything.
pub(super) fn retire(config: &Config) -> Option<String> {
    if config.milter.is_some() || !managed() {
        return None;
    }
    if !systemctl(&["is-active", "--quiet"]) && !systemctl(&["is-enabled", "--quiet"]) {
        return None;
    }
    Some(if systemctl(&["disable", "--now", "--quiet"]) {
        format!("stopped and disabled {}", units::MILTER)
    } else {
        format!(
            "{} could not be stopped; `systemctl disable --now {0}` does it",
            units::MILTER
        )
    })
}

/// Enter, update or take out the entry, as the configuration says; what was
/// done, if anything.
pub(super) fn ensure(
    admin: &Admin,
    config: &Config,
    directory: &Path,
) -> Result<Option<String>, String> {
    let kept = directory.join(units::MILTER_ENTRY);
    let known = fs::read_to_string(&kept)
        .ok()
        .map(|id| id.trim().to_owned());
    let entered = match &known {
        Some(id) => admin
            .list::<Stored>("MtaMilter")?
            .iter()
            .any(|stored| stored.id == *id),
        None => false,
    };
    match (&config.milter, known.as_deref().filter(|_| entered)) {
        (Some(milter), id) => {
            let entry = Milter {
                host: "127.0.0.1",
                port: milter.port,
                temp_fail_on_error: milter.defer_when_unreachable,
            };
            if let Some(id) = id {
                admin.set("x:MtaMilter/set", &Set::update(id, entry))?;
                return Ok(Some(format!(
                    "updated the macro milter's entry (127.0.0.1:{})",
                    milter.port
                )));
            }
            let created: Created<Stored> = admin.call("x:MtaMilter/set", &Set::create(entry))?;
            let new = created
                .created
                .get(NEW)
                .ok_or("Stalwart did not name the new milter entry")?;
            write_secret(&kept, &new.id)?;
            Ok(Some(format!(
                "entered the macro milter (127.0.0.1:{}); Stalwart asks it about every message it is sent",
                milter.port
            )))
        }
        (None, Some(id)) => {
            admin.set("x:MtaMilter/set", &Set::<()>::Destroy([id]))?;
            let _ = fs::remove_file(&kept);
            Ok(Some(
                "took the macro milter's entry out of Stalwart".to_owned(),
            ))
        }
        (None, None) => {
            // An ID of an entry that is gone says nothing any more.
            let _ = fs::remove_file(&kept);
            Ok(None)
        }
    }
}
