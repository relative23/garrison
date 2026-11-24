//! The macro milter's entry in Stalwart.
//!
//! Stalwart asks a milter only where one is entered, with its host and port.
//! Where the configuration has a `[milter]` section, setup enters Garrison's
//! own; where the section is gone, setup takes that entry out again, since
//! an entry for a filter that no longer runs would make Stalwart defer all
//! mail. Which entries are Garrison's, setup tells by the rules doctor
//! judges by (`doctor::milter::entries`), and it leaves one entry for the
//! filter, which asks it once about every message. An entry Stalwart asks
//! in vain that setup cannot tell for Garrison's, it leaves as it is and
//! names, and it changes no entry while there is one.
//!
//! The order keeps mail flowing: the filter runs and answers before
//! Stalwart is told of it, it moves to another port only once setup knows
//! which entries ask it where it runs, and it stops only after Stalwart has
//! forgotten it. The note says from before the first change until Stalwart
//! has read its settings again that a run changed Stalwart's entries.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::systemd::SYSTEMCTL;
use serde::Serialize;

use super::objects::{Created, NEW, Set};
use super::{Admin, write_secret};
use crate::doctor::milter::{WITHIN, entries};
use crate::units;
use entries::{Entry, Note};

/// The entry as setup writes it: switched on, and asked once a message's
/// data has arrived. Stalwart fills in the rest: protocol 6, its own
/// timeouts. It takes `enable` only as an expression and `stages` as a map
/// that an update replaces whole (measured on 1.1.0), so an entry switched
/// off or asked at other stages by hand is Garrison's filter's again.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Milter {
    host: &'static str,
    port: u16,
    enable: Always,
    stages: Stages,
    /// Defer mail while the filter cannot be reached, or take it unscanned.
    temp_fail_on_error: bool,
}

/// An expression without conditions that is true: `{"match": {}, "else":
/// "true"}`.
#[derive(Debug, Serialize)]
struct Always {
    #[serde(rename = "match")]
    conditions: BTreeMap<String, String>,
    #[serde(rename = "else")]
    otherwise: &'static str,
}

#[derive(Debug, Serialize)]
struct Stages {
    data: bool,
}

/// The entry for the filter on loopback `port`, deferring mail while it
/// does not answer where `defer` says so.
fn entry(port: u16, defer: bool) -> Milter {
    Milter {
        host: "127.0.0.1",
        port,
        enable: Always {
            conditions: BTreeMap::new(),
            otherwise: "true",
        },
        stages: Stages { data: true },
        temp_fail_on_error: defer,
    }
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

/// The ports the filter listens on where setup manages it and it runs; an
/// error where it runs and they cannot be seen, since setup would not know
/// which entries ask it.
fn listening() -> Result<Vec<u16>, String> {
    if !managed() || !systemctl(&["is-active", "--quiet"]) {
        return Ok(Vec::new());
    }
    let ports = entries::listening();
    if ports.is_empty() {
        return Err(format!(
            "{} runs, but setup cannot see where it listens, so it cannot tell which of \
             Stalwart's entries ask it. Nothing was changed",
            units::MILTER
        ));
    }
    Ok(ports)
}

/// Whether the running filter listens elsewhere than on `port`.
fn moving(listening: &[u16], port: u16) -> bool {
    !listening.is_empty() && !listening.contains(&port)
}

/// Root starts the filter anew, so that it runs with the configuration as it
/// is now; then it must answer on `port`.
fn started(port: u16) -> Result<(), String> {
    if managed() {
        systemctl(&["enable", "--quiet"]);
        systemctl(&["restart"]);
    }
    let mut problem = String::new();
    for _ in 0..10 {
        match garrison_milter::answers(port, Duration::from_secs(2)) {
            Ok(()) => return Ok(()),
            Err(error) => problem = error,
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "The macro milter does not answer on 127.0.0.1:{port} ({problem}). Nothing was changed: \
         Stalwart would defer mail while it asks a filter that is not there. \
         `journalctl -u {} -n 20` shows why it does not run.",
        units::MILTER
    ))
}

/// Before anything changes: where the configuration switches the filter on,
/// it must answer. A filter that runs on another port moves later, once
/// setup knows which entries ask it where it runs (`ensure`).
pub(super) fn prepare(config: &Config) -> Result<(), String> {
    let Some(milter) = &config.milter else {
        return Ok(());
    };
    if moving(&listening()?, milter.port) {
        return Ok(());
    }
    started(milter.port)
}

/// After Stalwart has read its settings again: the note names what it asks
/// now, and where the configuration no longer has the filter, the note goes
/// and root stops the filter; what was done, if anything.
pub(super) fn retire(config: &Config) -> Option<String> {
    let kept = config.credentials_directory.join(units::MILTER_ENTRY);
    if config.milter.is_some() {
        if let Note::Pending(Some(id)) = Note::read(&kept) {
            return write_secret(&kept, &id).err();
        }
        return None;
    }
    let _ = fs::remove_file(&kept);
    if !managed() {
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

/// Why setup leaves Stalwart's milters as they are: it asks `stranded` in
/// vain, and setup cannot tell them for the filter's.
fn refused(stranded: &[&Entry]) -> String {
    let asked: Vec<String> = stranded
        .iter()
        .map(|entry| {
            format!(
                "{} (entry {}), where nothing answers, so it {}",
                entry.address(),
                entry.id,
                entry.meanwhile("all incoming mail")
            )
        })
        .collect();
    format!(
        "Stalwart asks a milter at {}. {} Setup changed no milter entry",
        asked.join(", and at "),
        entries::REMOVE
    )
}

/// Enter, update or take out the entry, as the configuration says, and
/// leave one; what was done, if anything.
pub(super) fn ensure(
    admin: &Admin,
    config: &Config,
    directory: &Path,
) -> Result<Option<String>, String> {
    let kept = directory.join(units::MILTER_ENTRY);
    let note = Note::read(&kept);
    let stored = admin.list::<Entry>("MtaMilter")?;
    let port = config.milter.as_ref().map(|milter| milter.port);
    let listening = listening()?;
    let ours = entries::ours(&stored, note.id(), port, &listening);
    let answers = |port| garrison_milter::answers(port, WITHIN).is_ok();
    let theirs = stored
        .iter()
        .filter(|entry| !ours.iter().any(|our| our.id == entry.id));
    let stranded = entries::vain(theirs, &answers);
    if !stranded.is_empty() {
        return Err(refused(&stranded));
    }
    let first = ours.first().map(|entry| entry.id.as_str());
    let Some(milter) = &config.milter else {
        if ours.is_empty() {
            return Ok(None);
        }
        // Stalwart asks them until it has read that they are gone.
        write_secret(&kept, &entries::pending(first))?;
        for entry in &ours {
            admin.set("x:MtaMilter/set", &Set::<()>::Destroy([entry.id.as_str()]))?;
        }
        return Ok(Some(match ours.len() {
            1 => "took the macro milter's entry out of Stalwart".to_owned(),
            many => format!("took the macro milter's {many} entries out of Stalwart"),
        }));
    };
    write_secret(&kept, &entries::pending(first))?;
    if moving(&listening, milter.port) {
        started(milter.port)?;
    }
    let wanted = entry(milter.port, milter.defer_when_unreachable);
    let Some((first, others)) = ours.split_first() else {
        let created: Created<Entry> = admin.call("x:MtaMilter/set", &Set::create(wanted))?;
        let new = created
            .created
            .get(NEW)
            .ok_or("Stalwart did not name the new milter entry")?;
        write_secret(&kept, &entries::pending(Some(&new.id)))?;
        return Ok(Some(format!(
            "entered the macro milter (127.0.0.1:{}); Stalwart asks it about every message it is sent",
            milter.port
        )));
    };
    admin.set("x:MtaMilter/set", &Set::update(&first.id, wanted))?;
    let found = if note.id() == Some(first.id.as_str()) {
        ""
    } else {
        ", found by its address, as setup's note named none"
    };
    // More than one would have Stalwart ask the filter more than once.
    for other in others {
        admin.set("x:MtaMilter/set", &Set::<()>::Destroy([other.id.as_str()]))?;
    }
    let more = match others.len() {
        0 => String::new(),
        1 => "; took another entry for it out of Stalwart".to_owned(),
        many => format!("; took {many} other entries for it out of Stalwart"),
    };
    Ok(Some(format!(
        "updated the macro milter's entry (127.0.0.1:{}){found}{more}",
        milter.port
    )))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_entry_is_written_switched_on_and_asked_with_the_data() {
        assert_eq!(
            serde_json::to_value(entry(8096, true)).unwrap(),
            json!({"host": "127.0.0.1", "port": 8096,
                "enable": {"match": {}, "else": "true"},
                "stages": {"data": true}, "tempFailOnError": true})
        );
    }
}
