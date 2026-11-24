//! When the record of an unfinished run (`unfinished.rs`) no longer says
//! what the state is.
//!
//! The record holds when each service that writes Garrison's state last
//! started, which stopping it does not change. A service that starts after
//! the record was written, by the run's own start of a release, a reboot or
//! by hand, may record what no copy the record names holds, so from then on
//! the record is stale: nothing goes back on its word. Its links are set as
//! its run had set them by its last step, which changes no data, and it is
//! removed with a line that says so. Only an upgrade whose new release is
//! current and does not run is switched back all the same, once the state
//! as it is has been copied (`fallback.rs`).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::SYSTEMCTL;
use super::files::{Step, run, switch};
use super::unfinished::{Unfinished, name};
use crate::units;

/// The services that write Garrison's state.
const WRITERS: [&str; 5] = [
    units::WEB,
    units::INGEST,
    units::BROKER,
    units::COLLECT,
    units::WATCH,
];
const BOOT: &str = "/proc/sys/kernel/random/boot_id";

/// When each writer last started, as systemd counts it: within one boot
/// that count changes only when the unit starts, also where the clock jumps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Stamp {
    boot: String,
    /// `InactiveExitTimestampMonotonic` of each writer, 0 for one that has
    /// not started in this boot.
    starts: BTreeMap<String, u64>,
}

impl Stamp {
    /// The writers as they are now; `None` where systemd does not answer.
    pub(super) fn take() -> Option<Self> {
        let boot = fs::read_to_string(BOOT).ok()?.trim().to_owned();
        let mut starts = BTreeMap::new();
        for unit in WRITERS {
            let asked = [
                "show",
                "-p",
                "InactiveExitTimestampMonotonic",
                "--value",
                unit,
            ];
            let output = run(SYSTEMCTL, &asked).ok()?;
            if !output.status.success() {
                return None;
            }
            let text = String::from_utf8_lossy(&output.stdout);
            let start = match text.trim() {
                "" => 0,
                value => value.parse().ok()?,
            };
            starts.insert(unit.to_owned(), start);
        }
        Some(Self { boot, starts })
    }

    #[cfg(test)]
    pub(super) fn of(boot: &str, starts: &[(&str, u64)]) -> Self {
        Self {
            boot: boot.to_owned(),
            starts: starts
                .iter()
                .map(|(unit, start)| ((*unit).to_owned(), *start))
                .collect(),
        }
    }
}

/// Whether the release `current` names runs: its web service and its
/// receiver active. A unit that is starting or stopping is waited for, as
/// long as a start may take.
pub(super) fn runs() -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    loop {
        let states: Option<Vec<String>> = [units::WEB, units::INGEST]
            .into_iter()
            .map(|unit| {
                let output =
                    run(SYSTEMCTL, &["show", "-p", "ActiveState", "--value", unit]).ok()?;
                Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
            })
            .collect();
        let Some(states) = states else {
            return false;
        };
        if states.iter().all(|state| state == "active") {
            return true;
        }
        let moving = states
            .iter()
            .any(|state| matches!(state.as_str(), "activating" | "deactivating" | "reloading"));
        if !moving || std::time::Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Whether a writer started between `written`, the stamp of the record, and
/// `now`. A record without a stamp, and a systemd that does not answer,
/// count as started since: nothing then goes back on the record's word.
pub(super) fn started_since(written: Option<&Stamp>, now: Option<&Stamp>) -> bool {
    let Some(now) = now else {
        return true;
    };
    match written {
        Some(written) if written.boot == now.boot => now
            .starts
            .iter()
            .any(|(unit, start)| written.starts.get(unit) != Some(start)),
        // Another boot, or no stamp: every start of this boot came after it.
        _ => now.starts.values().any(|start| *start > 0),
    }
}

/// Set `previous` in `base` as the run of the stale `record` had left it by
/// its last step, and say so: `file` is removed after this.
pub(super) fn resolve(record: &Unfinished, base: &Path, file: &Path) -> Step<String> {
    let current = fs::canonicalize(base.join("current")).ok();
    let at = |release: &Path| current.as_deref() == Some(release);
    let previous = match record {
        Unfinished::Upgrade { from, to, .. } if at(to) => Some(from.clone()),
        Unfinished::Upgrade { previous, .. } => previous.clone(),
        Unfinished::Rollback { to, previous, .. } if at(to) => {
            previous.clone().filter(|after| after != to)
        }
        Unfinished::Rollback { to, .. } => Some(to.clone()),
        Unfinished::Restore { kept, .. } => {
            return Ok(format!(
                "{} named {}, and Garrison was started since on what it had put back: the \
                 record was removed. The state from before that restore is in {}.",
                file.display(),
                record.describe(),
                kept.display()
            ));
        }
    };
    let link = base.join("previous");
    match &previous {
        Some(release) => switch(&link, release)?,
        None => {
            let _ = fs::remove_file(&link);
        }
    }
    let named = |release: Option<&Path>| release.map_or_else(|| "none".to_owned(), name);
    let mut said = format!(
        "{} named {}, but Garrison was started since, so the databases may hold what no copy \
         holds: the record was removed, and nothing goes back on its word. current names {}, \
         previous {}.",
        file.display(),
        record.describe(),
        named(current.as_deref()),
        named(previous.as_deref())
    );
    // Its state goes back before its target becomes current.
    if let Unfinished::Rollback {
        to, state: Some(_), ..
    } = record
        && !at(to)
    {
        said.push_str(
            " The state from before the upgrade may have gone back in part; `install \
             --rollback --restore-state` puts all of it back.",
        );
    }
    Ok(said)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEB: &str = units::WEB;
    const INGEST: &str = units::INGEST;

    #[test]
    fn a_start_after_the_record_makes_it_stale() {
        let written = Stamp::of("boot-1", &[(WEB, 100), (INGEST, 90)]);
        // Nothing started since: the same starts.
        assert!(!started_since(Some(&written), Some(&written)));
        // The web service started again, by a run or by hand.
        let later = Stamp::of("boot-1", &[(WEB, 500), (INGEST, 90)]);
        assert!(started_since(Some(&written), Some(&later)));
        // A writer the record did not know, which has started.
        let more = Stamp::of("boot-1", &[(WEB, 100), (INGEST, 90), (units::WATCH, 7)]);
        assert!(started_since(Some(&written), Some(&more)));
        // After a reboot: stale once anything started in the new boot.
        let rebooted = Stamp::of("boot-2", &[(WEB, 0), (INGEST, 0)]);
        assert!(!started_since(Some(&written), Some(&rebooted)));
        let started = Stamp::of("boot-2", &[(WEB, 0), (INGEST, 3)]);
        assert!(started_since(Some(&written), Some(&started)));
        // Without a stamp, or without an answer from systemd: stale.
        assert!(started_since(None, Some(&written)));
        assert!(!started_since(None, Some(&rebooted)));
        assert!(started_since(Some(&written), None));
    }
}
