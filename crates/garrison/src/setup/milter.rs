//! The macro milter's entry in Stalwart: one for the filter where the
//! configuration has `[milter]`, none where it has not, as an entry for a
//! filter that no longer runs makes Stalwart defer all mail. Each run tells
//! the filter's entries from what is there (`doctor::milter::entries`). The
//! order keeps mail flowing and leaves what the next run finishes: the
//! filter answers before Stalwart is first told of it, moves to another
//! port only after Stalwart has read the entry there, and stops only after
//! Stalwart has forgotten it.

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use garrison_core::config::{Config, DEFAULT_PATH};
use garrison_core::systemd::SYSTEMCTL;
use serde::Serialize;

use super::api::Failed;
use super::objects::{Set, Stored};
use super::{Admin, states};
use crate::doctor::milter::{WITHIN, entries, stray};
use crate::state::State;
use crate::units;
use entries::Entry;

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
fn listening() -> Result<Vec<u16>, State> {
    match entries::listening().filter(|_| managed()) {
        Some(ports) if ports.is_empty() => Err(states::milter_unseen()),
        ports => Ok(ports.unwrap_or_default()),
    }
}

/// Whether the running filter listens elsewhere than on `port`.
fn moving(listening: &[u16], port: u16) -> bool {
    !listening.is_empty() && !listening.contains(&port)
}

/// Whether the filter could have `port` once it moves: another program may
/// hold it, and the filter would leave the port Stalwart asks for nothing.
fn free(port: u16) -> Result<(), State> {
    match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
        Ok(_) => Ok(()),
        Err(error) => Err(states::milter_port_taken(port, error)),
    }
}

/// Root starts the filter anew where it does not run, or runs with an older
/// configuration than there is now, or is to move (`force`); then it must
/// answer on `port`. Whether it was started anew.
fn started(port: u16, force: bool) -> Result<bool, State> {
    let mut restarted = false;
    if managed() {
        systemctl(&["enable", "--quiet"]);
        if force || !systemctl(&["is-active", "--quiet"]) || !current() {
            restarted = systemctl(&["restart"]);
        }
    }
    let mut problem = String::new();
    for _ in 0..10 {
        match garrison_milter::answers(port, Duration::from_secs(2)) {
            Ok(()) => return Ok(restarted),
            Err(error) => problem = error,
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(states::milter_silent(port, &problem))
}

/// Whether the running filter started after `garrison.toml`, which its unit
/// reads, last changed; where that cannot be seen, it did not.
fn current() -> bool {
    let started = std::process::Command::new(SYSTEMCTL)
        .args([
            "show",
            "--timestamp=unix",
            "--property",
            "ActiveEnterTimestamp",
        ])
        .args(["--value", units::MILTER])
        .output()
        .ok()
        .and_then(|output| {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            text.strip_prefix('@')?.parse::<u64>().ok()
        });
    let changed = fs::metadata(DEFAULT_PATH)
        .and_then(|file| file.modified())
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok());
    matches!((started, changed), (Some(started), Some(changed)) if started > changed.as_secs())
}

/// Why setup stops where Stalwart does not let the administrator read its
/// milter entries, as a user without its administrator role: it could not
/// tell whether Stalwart asks one in vain.
fn unread(failed: Failed) -> State {
    if failed.is("forbidden") {
        return states::milters_unreadable(&failed.state);
    }
    failed.state
}

/// Before setup changes anything: Stalwart asks no entry in vain that is
/// not the filter's, and where the configuration has the filter, it
/// answers, or can move to its port. What was done, where the filter was
/// started anew.
pub(super) fn prepare(admin: &Admin, config: &Config) -> Result<Option<String>, State> {
    let stored = admin.list::<Entry>("MtaMilter").map_err(unread)?;
    let port = config.milter.as_ref().map(|milter| milter.port);
    let listening = listening().map_err(states::unchanged)?;
    let ours = entries::ours(&stored, port, &listening);
    let theirs = stored
        .iter()
        .filter(|entry| !ours.iter().any(|our| our.id == entry.id));
    let stranded = entries::vain(theirs, &|entry| entry.answers(WITHIN));
    if !stranded.is_empty() {
        let lines: Vec<State> = stranded.into_iter().map(stray).collect();
        return Err(states::milter_stranded(&lines));
    }
    match port {
        None => Ok(None),
        Some(port) if moving(&listening, port) => free(port).map(|()| None),
        Some(port) => Ok(started(port, false)?.then(|| {
            format!("started the macro milter with garrison.toml as it is now (127.0.0.1:{port})")
        })),
    }
}

/// Enter, update or take out the filter's entries, as the configuration
/// says, and leave one, as Stalwart shows it where that is as asked; what was
/// done, if anything.
pub(super) fn ensure(admin: &Admin, config: &Config) -> Result<Option<String>, State> {
    let shown = admin.list::<Stored>("MtaMilter")?;
    let read = serde_json::to_value(&shown).and_then(serde_json::from_value::<Vec<Entry>>);
    let stored = read.map_err(|error| states::unreadable("x:MtaMilter/get", error))?;
    let port = config.milter.as_ref().map(|milter| milter.port);
    let ours = entries::ours(&stored, port, &listening()?);
    // One stays where the configuration has the filter: more would have
    // Stalwart ask it more than once. Stalwart asks those taken out until it
    // has read that they are gone.
    let (kept, gone) = match (&config.milter, ours.split_first()) {
        (Some(_), Some((first, others))) => (Some(first), others),
        _ => (None, &ours[..]),
    };
    for entry in gone {
        admin.set("x:MtaMilter/set", &Set::<()>::Destroy([entry.id.as_str()]))?;
    }
    let Some(milter) = &config.milter else {
        let took = match gone.len() {
            0 => return Ok(None),
            1 => "took the macro milter's entry out of Stalwart".to_owned(),
            many => format!("took the macro milter's {many} entries out of Stalwart"),
        };
        return Ok(Some(took));
    };
    let wanted = entry(milter.port, milter.defer_when_unreachable);
    let Some(kept) = kept else {
        admin.set("x:MtaMilter/set", &Set::create(wanted))?;
        return Ok(Some(format!(
            "entered the macro milter (127.0.0.1:{}); Stalwart asks it about every message it is sent",
            milter.port
        )));
    };
    let held = shown.iter().find(|item| item.id == kept.id);
    let unchanged = held.is_some_and(|item| item.holds(&wanted));
    if !unchanged {
        admin.set("x:MtaMilter/set", &Set::update(&kept.id, wanted))?;
    }
    let more = match gone.len() {
        0 => String::new(),
        1 => "; took another entry for it out of Stalwart".to_owned(),
        many => format!("; took {many} other entries for it out of Stalwart"),
    };
    let port = milter.port;
    Ok(match (unchanged, gone.is_empty()) {
        (true, true) => None,
        (true, false) => Some(format!(
            "kept the macro milter's entry (127.0.0.1:{port}){more}"
        )),
        (false, _) => Some(format!(
            "updated the macro milter's entry (127.0.0.1:{port}){more}"
        )),
    })
}

/// After Stalwart has read its settings again, the filter follows them: one
/// that runs elsewhere moves to the port Stalwart now asks, and one the
/// configuration no longer has stops, now that Stalwart has forgotten it.
/// The note an earlier release kept of the filter's entry goes, as nothing
/// reads it. What was done.
pub(super) fn retire(config: &Config) -> Result<Vec<String>, State> {
    let mut done = Vec::new();
    let note = config.credentials_directory.join(units::MILTER_ENTRY);
    if fs::remove_file(&note).is_ok() {
        let note = note.display();
        done.push(format!("removed {note}, a note this release does not keep"));
    }
    if let Some(milter) = &config.milter {
        let port = milter.port;
        if moving(&listening()?, port) {
            started(port, true)?;
            done.push(format!("moved the macro milter to 127.0.0.1:{port}"));
        }
        return Ok(done);
    }
    let (unit, is) = (units::MILTER, |state| systemctl(&[state, "--quiet"]));
    if managed() && (is("is-active") || is("is-enabled")) {
        done.push(if systemctl(&["disable", "--now", "--quiet"]) {
            format!("stopped and disabled {unit}")
        } else {
            format!("{unit} could not be stopped; `systemctl disable --now {unit}` does it")
        });
    }
    Ok(done)
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

    /// The filter moves only to a port it can have: one another program
    /// holds refuses the run before anything changes.
    #[test]
    fn the_filter_moves_only_to_a_port_it_can_have() {
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = held.local_addr().unwrap().port();
        assert!(free(port).is_err_and(|refusal| refusal.name == "setup-milter-port-taken"));
        drop(held);
        assert_eq!(free(port), Ok(()));
    }
}
