//! Stalwart's milter entries, and which of them are the macro filter's: the
//! rules `garrison stalwart setup` acts by, the installer keeps the filter
//! by and `garrison doctor` judges by, so that what doctor names setup
//! mends. Each run reads the entries as Stalwart holds them then.
//!
//! A milter has no name in Stalwart (1.2.0's schema gives it no field), so
//! an entry is the filter's where it asks this host, under any name the
//! resolver gives a loopback or the unspecified address, at the filter's
//! port: the one the configuration gives it, or one the running filter
//! listens on. Stalwart asks an entry in vain where no milter answers at the
//! addresses its host and port resolve to, whatever the host, and then does
//! with all incoming mail what the entry says.

use std::collections::BTreeSet;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use garrison_collector::providers::stalwart::answers::{Fixed, Stages, Tolerant, Written};
use garrison_core::systemd::SYSTEMCTL;
use serde::Deserialize;
use serde_json::Value;

use crate::units;

/// What mends an entry Stalwart asks in vain that is not the filter's.
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

    /// The addresses Stalwart asks it at: its host and port as this host's
    /// resolver gives them, as Stalwart looks a milter's host up (it fails
    /// to read its settings with the resolver's words for a name that does
    /// not resolve, measured on 1.1.0 only).
    fn addresses(&self) -> Vec<SocketAddr> {
        let host = self.host.0.as_ref().and_then(Value::as_str);
        match (host, self.port()) {
            (Some(host), Some(port)) => format!("{host}:{port}")
                .to_socket_addrs()
                .map(Iterator::collect)
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// Whether it asks this host, at a loopback or the unspecified address.
    pub(crate) fn here(&self) -> bool {
        self.addresses().iter().any(|address| {
            let ip = address.ip().to_canonical();
            ip.is_loopback() || ip.is_unspecified()
        })
    }

    /// Whether it asks this host at `port`.
    pub(crate) fn asks(&self, port: u16) -> bool {
        self.port() == Some(port) && self.here()
    }

    /// Whether Stalwart asks it: switched on, also under conditions.
    pub(crate) fn asked(&self) -> bool {
        self.enable.0 != Some(false)
    }

    /// Whether a milter answers where Stalwart asks it, at any of its
    /// addresses, as Stalwart tries each.
    pub(crate) fn answers(&self, within: Duration) -> bool {
        self.addresses()
            .into_iter()
            .any(|address| garrison_milter::answers_at(address, within).is_ok())
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

/// The filter's entries among `entries`: those that ask this host at its
/// port, the configuration's `port` or one the running filter listens on.
pub(crate) fn ours<'a>(
    entries: &'a [Entry],
    port: Option<u16>,
    listening: &[u16],
) -> Vec<&'a Entry> {
    let ports: Vec<u16> = port.into_iter().chain(listening.iter().copied()).collect();
    entries
        .iter()
        .filter(|entry| ports.iter().any(|port| entry.asks(*port)))
        .collect()
}

/// The entries of `entries` that Stalwart asks in vain: switched on, where
/// no milter answers, as `answers` finds it.
pub(crate) fn vain<'a>(
    entries: impl IntoIterator<Item = &'a Entry>,
    answers: &dyn Fn(&Entry) -> bool,
) -> Vec<&'a Entry> {
    entries
        .into_iter()
        .filter(|entry| entry.asked() && entry.port().is_some() && !answers(entry))
        .collect()
}

/// The ports the macro filter listens on, as root sees its sockets, where
/// it runs: none where they cannot be seen.
pub(crate) fn listening() -> Option<Vec<u16>> {
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
    pid.map(|pid| listening_in(&Path::new("/proc").join(pid.to_string())))
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

    /// The filter's entries are those that ask this host at the filter's
    /// port: the configuration's, or one the running filter listens on.
    /// Another milter's, or one asking another host, is none of them.
    #[test]
    fn the_filters_entries_ask_this_host_at_its_port() {
        let stored = read(&json!([
            {"id": "a", "host": "127.0.0.1", "port": 8096},
            {"id": "b", "host": "127.0.0.1", "port": 8097},
            {"id": "c", "host": "127.0.0.1", "port": "8097"},
            {"id": "d", "host": "192.0.2.1", "port": 8097},
            {"id": "e", "host": "127.0.0.1", "port": 11332},
            {"id": "f", "host": null, "port": null},
            {"id": "g", "host": "localhost", "port": 8098},
        ]));
        assert_eq!(ids(&ours(&stored, Some(8097), &[])), ["b", "c"]);
        assert_eq!(ids(&ours(&stored, None, &[])), Vec::<String>::new());
        assert_eq!(ids(&ours(&stored, None, &[8096])), ["a"]);
        assert_eq!(ids(&ours(&stored, Some(8097), &[8098])), ["b", "c", "g"]);
    }

    /// Every name this host's resolver gives a loopback or the unspecified
    /// address counts as this host: an entry at the filter's port under it
    /// is the filter's, and one where nothing answers is asked in vain. An
    /// entry of another host is not the filter's, and asked in vain where
    /// nothing answers there.
    #[test]
    fn every_name_of_this_host_counts_and_every_host_is_judged() {
        for name in [
            "127.0.0.1",
            "localhost",
            "::1",
            "[::1]",
            "127.0.0.2",
            "127.1",
            "0.0.0.0",
            "LOCALHOST",
            "localhost.",
        ] {
            if format!("{name}:1").to_socket_addrs().is_err() {
                continue;
            }
            let stored = read(&json!([{"id": "g", "host": name, "port": 8096}]));
            assert_eq!(ids(&ours(&stored, Some(8096), &[])), ["g"], "{name}");
            assert_eq!(ids(&vain(&stored, &|_| false)), ["g"], "{name}");
        }
        let remote = read(&json!([{"id": "r", "host": "192.0.2.1", "port": 8096}]));
        assert_eq!(ids(&ours(&remote, Some(8096), &[])), Vec::<String>::new());
        assert_eq!(ids(&vain(&remote, &|_| false)), ["r"]);
    }

    /// Stalwart asks in vain an entry switched on where no milter answers
    /// at its addresses: a milter on `127.0.0.1` answers it under
    /// `127.0.0.1`, `0.0.0.0`, `127.1` and `localhost`, which resolves to
    /// both, and not under `::1` or `127.0.0.2`, nor at a port where nothing
    /// listens or a name that does not resolve. One switched off, and one
    /// without a port, is not.
    #[test]
    fn an_entry_is_asked_in_vain_where_no_milter_answers_it() {
        let milter = crate::doctor::answering_milter();
        let (_held, silent) = crate::doctor::silent_port();
        let stored = read(&json!([
            {"id": "a", "host": "127.0.0.1", "port": milter},
            {"id": "b", "host": "0.0.0.0", "port": milter},
            {"id": "c", "host": "127.1", "port": milter},
            {"id": "d", "host": "localhost", "port": milter},
            {"id": "e", "host": "::1", "port": milter},
            {"id": "f", "host": "127.0.0.2", "port": milter},
            {"id": "g", "host": "127.0.0.1", "port": silent},
            {"id": "h", "host": "garrison-test.invalid", "port": milter},
            {"id": "i", "host": "127.0.0.1", "port": silent,
                "enable": {"match": {}, "else": "false"}},
            {"id": "j", "host": "127.0.0.1", "port": null},
        ]));
        let found = vain(&stored, &|entry| entry.answers(Duration::from_secs(3)));
        assert_eq!(ids(&found), ["e", "f", "g", "h"]);
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
