//! The macro milter's entry in Stalwart.
//!
//! Stalwart asks a milter only where one is entered, with its host and port.
//! Where the configuration has a `[milter]` section, setup enters Garrison's
//! own; where the section is gone, setup takes that entry out again, since
//! an entry for a filter that no longer runs would make Stalwart defer all
//! mail. A milter has no name or description to tell Garrison's from
//! another, so setup keeps the entry's ID in a file beside the credentials.
//! Where that note is gone or names nothing, an entry that asks the filter
//! where it listens, 127.0.0.1 at the configured port, is Garrison's: the
//! filter answers there before setup tells Stalwart anything. Setup leaves
//! one entry for the filter, which asks it once about every message.
//!
//! The order keeps mail flowing: the filter runs and answers before
//! Stalwart is told of it, and it stops only after Stalwart has forgotten
//! it.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::systemd::SYSTEMCTL;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::objects::{Created, NEW, Set};
use super::{Admin, write_secret};
use crate::units;

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

/// A milter as Stalwart holds it, as far as setup tells Garrison's from
/// another's.
#[derive(Debug, Deserialize)]
struct Stored {
    id: String,
    #[serde(default)]
    host: Option<Value>,
    #[serde(default)]
    port: Option<Value>,
}

impl Stored {
    /// The port it asks, where it names one.
    fn port(&self) -> Option<u16> {
        match &self.port {
            Some(Value::Number(number)) => {
                number.as_u64().and_then(|port| u16::try_from(port).ok())
            }
            Some(Value::String(text)) => text.parse().ok(),
            _ => None,
        }
    }

    /// Whether it asks the filter where setup enters it: 127.0.0.1 at
    /// `port`.
    fn asks(&self, port: u16) -> bool {
        self.host.as_ref().and_then(Value::as_str) == Some("127.0.0.1") && self.port() == Some(port)
    }
}

/// Garrison's entries among those Stalwart holds: the one setup's note
/// names first, then every other that asks the filter where it listens,
/// 127.0.0.1 at `port`, the configured one, or, where the configuration no
/// longer has the filter, at the noted entry's port.
fn ours<'a>(stored: &'a [Stored], noted: Option<&str>, port: Option<u16>) -> Vec<&'a Stored> {
    let first = noted.and_then(|id| stored.iter().find(|entry| entry.id == id));
    let port = port.or_else(|| first.and_then(Stored::port));
    let others = stored.iter().filter(|entry| {
        first.is_none_or(|first| first.id != entry.id) && port.is_some_and(|port| entry.asks(port))
    });
    first.into_iter().chain(others).collect()
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

/// Enter, update or take out the entry, as the configuration says, and
/// leave one; what was done, if anything.
pub(super) fn ensure(
    admin: &Admin,
    config: &Config,
    directory: &Path,
) -> Result<Option<String>, String> {
    let kept = directory.join(units::MILTER_ENTRY);
    // An empty note names no entry, as a missing one does.
    let noted = fs::read_to_string(&kept)
        .ok()
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty());
    let stored = admin.list::<Stored>("MtaMilter")?;
    let port = config.milter.as_ref().map(|milter| milter.port);
    let ours = ours(&stored, noted.as_deref(), port);
    let Some(milter) = &config.milter else {
        for entry in &ours {
            admin.set("x:MtaMilter/set", &Set::<()>::Destroy([entry.id.as_str()]))?;
        }
        // An ID of an entry that is gone says nothing any more.
        let _ = fs::remove_file(&kept);
        return Ok(match ours.len() {
            0 => None,
            1 => Some("took the macro milter's entry out of Stalwart".to_owned()),
            many => Some(format!(
                "took the macro milter's {many} entries out of Stalwart"
            )),
        });
    };
    let wanted = entry(milter.port, milter.defer_when_unreachable);
    let Some((first, others)) = ours.split_first() else {
        let created: Created<Stored> = admin.call("x:MtaMilter/set", &Set::create(wanted))?;
        let new = created
            .created
            .get(NEW)
            .ok_or("Stalwart did not name the new milter entry")?;
        write_secret(&kept, &new.id)?;
        return Ok(Some(format!(
            "entered the macro milter (127.0.0.1:{}); Stalwart asks it about every message it is sent",
            milter.port
        )));
    };
    admin.set("x:MtaMilter/set", &Set::update(&first.id, wanted))?;
    let found = if noted.as_deref() == Some(first.id.as_str()) {
        ""
    } else {
        write_secret(&kept, &first.id)?;
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

    /// Garrison's entry is the one setup's note names, or, where the note
    /// names none, one that asks the filter where it listens; every other
    /// that asks it there is one more, and another milter's is none of
    /// them.
    #[test]
    fn garrisons_entry_is_the_noted_one_or_one_that_asks_where_the_filter_listens() {
        let stored: Vec<Stored> = serde_json::from_value(json!([
            {"id": "a", "host": "127.0.0.1", "port": 8096},
            {"id": "b", "host": "127.0.0.1", "port": 8097},
            {"id": "c", "host": "127.0.0.1", "port": "8097"},
            {"id": "d", "host": "10.0.0.5", "port": 8097},
            {"id": "e", "host": "127.0.0.1", "port": 11332},
            {"id": "f", "host": null, "port": null},
        ]))
        .unwrap();
        let ids = |found: Vec<&Stored>| -> Vec<String> {
            found.iter().map(|entry| entry.id.clone()).collect()
        };
        assert_eq!(ids(ours(&stored, Some("a"), Some(8097))), ["a", "b", "c"]);
        assert_eq!(ids(ours(&stored, None, Some(8097))), ["b", "c"]);
        assert_eq!(ids(ours(&stored, Some("gone"), Some(8096))), ["a"]);
        // The section gone: the noted entry, and the others at its address.
        assert_eq!(ids(ours(&stored, Some("b"), None)), ["b", "c"]);
        assert_eq!(ids(ours(&stored, None, None)), Vec::<String>::new());
    }
}
