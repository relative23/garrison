//! Stalwart's milter entries, and which of them are the macro filter's: the
//! rules `garrison stalwart setup` acts by and `garrison doctor` judges by,
//! so that what doctor names setup mends.
//!
//! A milter has no name in Stalwart, so setup keeps the ID of the entry it
//! made in a note beside the credentials. An entry is the filter's where the
//! note names it, or where it asks this host at the filter's port: the one
//! the configuration gives it (setup made sure the filter answers there
//! before it told Stalwart), the noted entry's, or one the running filter
//! listens on. Stalwart asks its entries as it read them last, so setup marks
//! the note while a run has changed them and Stalwart has not read its
//! settings since; the installer and uninstall take any note as one that may
//! name an entry Stalwart asks.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use garrison_collector::providers::stalwart::answers::{Fixed, Stages, Tolerant, Written};
use garrison_core::systemd::SYSTEMCTL;
use serde::Deserialize;
use serde_json::Value;

use crate::units;

/// What a note starts with while Stalwart has not read what the run changed.
const PENDING: char = '!';

/// What mends an entry Stalwart asks in vain that setup cannot tell for the
/// filter's.
pub(crate) const REMOVE: &str = "If nothing is to answer there, remove that entry in the Stalwart \
                                 WebUI (Settings ▸ MTA ▸ Milters) and reload its settings.";

/// One of Stalwart's milters.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Entry {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) host: Written,
    #[serde(default)]
    pub(crate) port: Written,
    #[serde(default)]
    pub(crate) enable: Fixed,
    #[serde(default)]
    pub(crate) stages: Tolerant<Stages>,
    #[serde(default)]
    pub(crate) temp_fail_on_error: Fixed,
}

impl Entry {
    /// The port it asks, where it names one.
    pub(crate) fn port(&self) -> Option<u16> {
        match &self.port.0 {
            Some(Value::Number(number)) => {
                number.as_u64().and_then(|port| u16::try_from(port).ok())
            }
            Some(Value::String(text)) => text.parse().ok(),
            _ => None,
        }
    }

    /// Whether it asks this host, where the filter listens.
    pub(crate) fn here(&self) -> bool {
        matches!(
            self.host.0.as_ref().and_then(Value::as_str),
            Some("127.0.0.1" | "localhost")
        )
    }

    /// Whether it asks this host at `port`.
    pub(crate) fn asks(&self, port: u16) -> bool {
        self.here() && self.port() == Some(port)
    }

    /// Whether Stalwart asks it: switched on, also under conditions.
    pub(crate) fn asked(&self) -> bool {
        self.enable.0 != Some(false)
    }

    /// Where it asks, as Stalwart holds it.
    pub(crate) fn address(&self) -> String {
        format!("{}:{}", self.host.text(), self.port.text())
    }

    /// What Stalwart does with `mail` while the milter does not answer.
    pub(crate) fn meanwhile(&self, mail: &str) -> String {
        match self.temp_fail_on_error.0 {
            Some(true) => format!("defers {mail}"),
            Some(false) => format!("takes {mail} unscanned"),
            None => format!("decides by conditions of its own what to do with {mail}"),
        }
    }
}

/// What setup's note says.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Note {
    /// No note: setup has not told Stalwart of the filter, or has taken it
    /// out and Stalwart read its settings since.
    Missing,
    /// Stalwart was told of this entry and has read its settings since.
    Named(String),
    /// A note that names no entry.
    Empty,
    /// A run changed Stalwart's entries and stopped before Stalwart read its
    /// settings again; the entry it made or kept, where it knew it.
    Pending(Option<String>),
}

impl Note {
    /// The note at `path`.
    pub(crate) fn read(path: &Path) -> Note {
        let Ok(text) = fs::read_to_string(path) else {
            // One that is there but cannot be read names nothing it can tell.
            return if fs::symlink_metadata(path).is_ok() {
                Note::Empty
            } else {
                Note::Missing
            };
        };
        let text = text.trim();
        let id = |text: &str| (!text.is_empty()).then(|| text.to_owned());
        match text.strip_prefix(PENDING) {
            Some(rest) => Note::Pending(id(rest.trim())),
            None => id(text).map_or(Note::Empty, Note::Named),
        }
    }

    /// The entry it names, if any.
    pub(crate) fn id(&self) -> Option<&str> {
        match self {
            Note::Named(id) | Note::Pending(Some(id)) => Some(id),
            Note::Missing | Note::Empty | Note::Pending(None) => None,
        }
    }
}

/// A note of a run that changes Stalwart's entries, written before it
/// changes any: `id` the entry it makes or keeps, where it knows it.
pub(crate) fn pending(id: Option<&str>) -> String {
    format!("{PENDING}{}", id.unwrap_or_default())
}

/// The filter's entries among `entries`: the one the note names first, then
/// every other that asks this host at the filter's port: `port`, the
/// configuration's, the noted entry's, or one the running filter listens on.
pub(crate) fn ours<'a>(
    entries: &'a [Entry],
    noted: Option<&str>,
    port: Option<u16>,
    listening: &[u16],
) -> Vec<&'a Entry> {
    let first = noted.and_then(|id| entries.iter().find(|entry| entry.id == id));
    let ports: Vec<u16> = port
        .into_iter()
        .chain(first.and_then(Entry::port))
        .chain(listening.iter().copied())
        .collect();
    let others = entries.iter().filter(|entry| {
        first.is_none_or(|first| first.id != entry.id) && ports.iter().any(|port| entry.asks(*port))
    });
    first.into_iter().chain(others).collect()
}

/// The entries of `entries` that Stalwart asks in vain: switched on, asking
/// this host where no milter answers.
pub(crate) fn vain<'a>(
    entries: impl IntoIterator<Item = &'a Entry>,
    answers: &dyn Fn(u16) -> bool,
) -> Vec<&'a Entry> {
    entries
        .into_iter()
        .filter(|entry| entry.asked() && entry.here())
        .filter(|entry| entry.port().is_some_and(|port| !answers(port)))
        .collect()
}

/// The ports the macro filter listens on while it runs, as root sees its
/// sockets; none where it does not run or they cannot be seen.
pub(crate) fn listening() -> Vec<u16> {
    let pid = std::process::Command::new(SYSTEMCTL)
        .args(["show", "--property", "MainPID", "--value", units::MILTER])
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        })
        .filter(|pid| *pid != 0);
    pid.map_or_else(Vec::new, |pid| {
        listening_in(&Path::new("/proc").join(pid.to_string()))
    })
}

/// The ports the process whose `/proc` folder is `process` listens on.
pub(crate) fn listening_in(process: &Path) -> Vec<u16> {
    let sockets: BTreeSet<u64> = fs::read_dir(process.join("fd"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|descriptor| fs::read_link(descriptor.path()).ok())
        .filter_map(|target| {
            target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect();
    ["net/tcp", "net/tcp6"]
        .into_iter()
        .flat_map(|table| {
            let text = fs::read_to_string(process.join(table)).unwrap_or_default();
            text.lines()
                .skip(1)
                .filter_map(|line| listener(line, &sockets))
                .collect::<Vec<u16>>()
        })
        .collect()
}

/// The port of a line of `/proc/net/tcp` that listens on one of `sockets`.
fn listener(line: &str, sockets: &BTreeSet<u64>) -> Option<u16> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    // "0A" is TCP_LISTEN; the tenth field the socket's inode.
    let inode: u64 = fields.get(9)?.parse().ok()?;
    if fields.get(3) != Some(&"0A") || !sockets.contains(&inode) {
        return None;
    }
    u16::from_str_radix(fields.get(1)?.rsplit_once(':')?.1, 16).ok()
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};

    use serde_json::json;

    use super::*;

    fn read(list: &Value) -> Vec<Entry> {
        serde_json::from_value(list.clone()).unwrap()
    }

    fn ids(found: &[&Entry]) -> Vec<String> {
        found.iter().map(|entry| entry.id.clone()).collect()
    }

    /// The filter's entries are the one the note names and every other
    /// that asks this host at the filter's port: the configuration's, the
    /// noted entry's, or one the running filter listens on. Another
    /// milter's, or one asking another host, is none of them.
    #[test]
    fn the_filters_entries_are_the_noted_one_and_those_at_its_port() {
        let stored = read(&json!([
            {"id": "a", "host": "127.0.0.1", "port": 8096},
            {"id": "b", "host": "127.0.0.1", "port": 8097},
            {"id": "c", "host": "127.0.0.1", "port": "8097"},
            {"id": "d", "host": "10.0.0.5", "port": 8097},
            {"id": "e", "host": "127.0.0.1", "port": 11332},
            {"id": "f", "host": null, "port": null},
            {"id": "g", "host": "localhost", "port": 8098},
        ]));
        assert_eq!(
            ids(&ours(&stored, Some("a"), Some(8097), &[])),
            ["a", "b", "c"]
        );
        assert_eq!(ids(&ours(&stored, None, Some(8097), &[])), ["b", "c"]);
        assert_eq!(ids(&ours(&stored, Some("gone"), Some(8096), &[])), ["a"]);
        // The section gone: the noted entry, and the others at its address.
        assert_eq!(ids(&ours(&stored, Some("b"), None, &[])), ["b", "c"]);
        assert_eq!(ids(&ours(&stored, None, None, &[])), Vec::<String>::new());
        // Where the running filter listens, with or without the section.
        assert_eq!(ids(&ours(&stored, None, None, &[8096])), ["a"]);
        assert_eq!(
            ids(&ours(&stored, None, Some(8097), &[8098])),
            ["b", "c", "g"]
        );
    }

    /// Stalwart asks in vain an entry switched on that asks this host where
    /// nothing answers; one switched off, one of another host and one
    /// without a port it does not.
    #[test]
    fn an_entry_is_asked_in_vain_where_nothing_answers_on_this_host() {
        let stored = read(&json!([
            {"id": "a", "host": "127.0.0.1", "port": 8096, "enable": {"match": {}, "else": "true"}},
            {"id": "b", "host": "localhost", "port": 8096},
            {"id": "c", "host": "127.0.0.1", "port": 8096, "enable": {"match": {}, "else": "false"}},
            {"id": "d", "host": "10.0.0.5", "port": 8096},
            {"id": "e", "host": "127.0.0.1", "port": null},
            {"id": "f", "host": "127.0.0.1", "port": 8097},
        ]));
        let answers = |port| port == 8097;
        assert_eq!(ids(&vain(&stored, &answers)), ["a", "b"]);
    }

    /// The note: missing, a plain ID, empty, and the mark of a run that
    /// stopped before Stalwart read its settings again, with or without the
    /// ID; one that cannot be read names nothing it can tell.
    #[test]
    fn the_note_says_which_entry_and_whether_stalwart_read_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stalwart-milter-id");
        assert_eq!(Note::read(&path), Note::Missing);
        for (held, note) in [
            ("m\n", Note::Named("m".into())),
            ("", Note::Empty),
            (" \n", Note::Empty),
            ("!m\n", Note::Pending(Some("m".into()))),
            ("!", Note::Pending(None)),
        ] {
            fs::write(&path, held).unwrap();
            assert_eq!(Note::read(&path), note, "{held:?}");
        }
        assert_eq!(pending(Some("m")), "!m");
        assert_eq!(pending(None), "!");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(Note::read(&path), Note::Empty);
    }

    /// The ports a process listens on, as its sockets in /proc show them:
    /// this test's own listener, and not a connection it made.
    #[test]
    fn the_ports_a_process_listens_on_are_read_from_its_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let elsewhere = TcpListener::bind("127.0.0.1:0").unwrap();
        let connection = TcpStream::connect(elsewhere.local_addr().unwrap()).unwrap();
        let local = connection.local_addr().unwrap().port();
        let found = listening_in(Path::new("/proc/self"));
        assert!(found.contains(&port), "{found:?}");
        assert!(!found.contains(&local), "{found:?}");
        assert_eq!(
            listening_in(Path::new("/proc/garrison-no-such-process")),
            Vec::<u16>::new()
        );
    }
}
