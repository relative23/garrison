//! Stalwart's milters: every entry Stalwart asks where no milter answers,
//! which makes it defer all mail, or take it unscanned. A virus scanner's
//! milter that is down shows here. doctor asks Stalwart with the collector's
//! API key, as the collector reads Stalwart's milters.
//!
//! Stalwart asks an entry in vain where no milter answers at the addresses
//! its host and port resolve to, whatever the host, and then does with all
//! incoming mail what the entry says.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use garrison_collector::providers::stalwart::answers::{Fixed, Written};
use garrison_core::config::Config;
use garrison_core::credentials::Credentials;
use garrison_stalwart::jmap::JmapClient;
use serde::Deserialize;
use serde_json::Value;

use super::Finding;
use super::states::milter as states;

/// How long a milter has to answer the opening doctor sends.
const WITHIN: Duration = Duration::from_secs(3);
/// What doctor reads of each of Stalwart's milters.
const PROPERTIES: [&str; 5] = ["id", "host", "port", "enable", "tempFailOnError"];

/// One of Stalwart's milters.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Entry {
    pub(crate) id: String,
    #[serde(default)]
    host: Written,
    #[serde(default)]
    port: Written,
    #[serde(default)]
    enable: Fixed,
    #[serde(default)]
    temp_fail_on_error: Fixed,
}

impl Entry {
    /// The port it asks, where it names one.
    fn port(&self) -> Option<u16> {
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

    /// Whether a milter answers where Stalwart asks it, at any of its
    /// addresses, as Stalwart tries each.
    fn answers(&self, within: Duration) -> bool {
        self.addresses()
            .into_iter()
            .any(|address| answers_at(address, within))
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

/// Whether a milter answers at `address`: the opening a mail server sends,
/// and a milter's answer to it.
fn answers_at(address: SocketAddr, within: Duration) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, within) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(within));
    let _ = stream.set_write_timeout(Some(within));
    // Version 6, every action and every step on offer.
    let mut opening = vec![0, 0, 0, 13, b'O'];
    for value in [6_u32, 0x0000_01ff, 0x001f_ffff] {
        opening.extend_from_slice(&value.to_be_bytes());
    }
    let mut answer = [0; 5];
    let answered = stream.write_all(&opening).is_ok() && stream.read_exact(&mut answer).is_ok();
    let _ = stream.write_all(&[0, 0, 0, 1, b'Q']);
    answered && answer[4] == b'O'
}

/// The entries of `entries` that Stalwart asks in vain: switched on, also
/// under conditions, where no milter answers, as `answers` finds it.
fn vain<'a>(entries: &'a [Entry], answers: &dyn Fn(&Entry) -> bool) -> Vec<&'a Entry> {
    entries
        .iter()
        .filter(|entry| entry.enable.0 != Some(false) && entry.port().is_some() && !answers(entry))
        .collect()
}

/// What doctor says of an entry Stalwart asks in vain.
fn stranded(entry: &Entry) -> Finding {
    if entry.temp_fail_on_error.0 == Some(false) {
        Finding::warn(states::stranded_unscanned(entry))
    } else {
        Finding::fail(states::stranded(entry))
    }
}

/// Stalwart's milters, asked with the collector's API key, or why they
/// could not be asked.
fn asked(config: &Config, credentials: &Credentials) -> Result<Vec<Entry>, String> {
    let key = credentials
        .read_secret(&config.collector.native_key)
        .map_err(states::key_unread)?;
    let url = &config.deployment.stalwart_url;
    JmapClient::new(url, &key)
        .get::<Entry>("MtaMilter", None, &PROPERTIES)
        .map_err(|error| states::unasked(url, error))
}

pub(super) fn checks(config: &Config, credentials: &Credentials) -> Vec<Finding> {
    match asked(config, credentials) {
        Ok(entries) => vain(&entries, &|entry| entry.answers(WITHIN))
            .into_iter()
            .map(stranded)
            .collect(),
        Err(why) => vec![Finding::unknown(states::stranded_unknown(&why))],
    }
}

#[cfg(test)]
mod tests;
