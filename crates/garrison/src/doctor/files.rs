//! The credentials, which must stay root's alone. The units load every
//! credential (`LoadCredential=`), and systemd starts none of
//! them without its file, so each must be there; a file that may be empty,
//! which means none, is in order empty unless the configuration reads it,
//! and judged by its reader where it holds something. A key setup writes is
//! no key empty, as missing.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use garrison_collector::context::DqsKey;
use garrison_collector::run::{self as collector, ScrapeCredential};
use garrison_core::config::Config;
use garrison_core::credentials::Credentials;
use garrison_core::files::{self as protected, Form, Holds};

use super::states::files::{self as states, Lacks, Reader};
use super::{Finding, Level};
use crate::units;

/// The keys setup writes, which every installation reads.
const KEYS: [&str; 3] = [
    "webhook-signature-key",
    "collector-native-key",
    "broker-native-key",
];

/// The file `name` at `path`, made by `made_by`: owned by `owner`, root on a
/// real host, and readable by nobody else.
fn private(path: &Path, name: &str, made_by: &str, owner: u32) -> Finding {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Finding::fail(states::missing(name, path, made_by));
    };
    // Neither the installer nor the services follow a link here or change
    // a folder: only the file itself does.
    if !metadata.is_file() {
        return Finding::fail(states::not_a_file(name, path, made_by));
    }
    let mode = metadata.mode() & 0o777;
    if metadata.uid() == owner && mode & !0o600 == 0 {
        Finding::ok(states::private(name, mode))
    } else {
        Finding::fail(states::open(path, mode))
    }
}

/// A key setup writes, which its service reads with every start or check.
/// An empty file, or one that holds something other than a key, gives that
/// service none, as a missing file does, and setup makes a key there; one
/// that holds a key is judged by owner and mode.
fn key(path: &Path, name: &str) -> Finding {
    let held = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => protected::holds(path, Form::Token),
        // Missing, a link or a folder: said as of every private file.
        _ => return private(path, name, states::SETUP, 0),
    };
    let lacks = match held {
        Ok(Holds::Secret) => return private(path, name, states::SETUP, 0),
        Ok(Holds::Nothing) => Lacks::Empty,
        Ok(Holds::Other) => Lacks::Other,
        Err(_) => Lacks::Unread,
    };
    Finding::fail(states::no_key(name, lacks, path))
}

/// What of the configuration reads the file `name` and so needs it filled;
/// `None` where an empty file serves. The notification channels' files are
/// judged with the channels.
pub(super) fn reader(config: &Config, name: &str) -> Option<Reader> {
    let scraped = config.collector.metrics_credential.is_some()
        && config.collector.providers.iter().any(|provider| {
            provider.get("type").and_then(toml::Value::as_str) == Some("prometheus")
        });
    if name == "spamhaus-dqs-key" {
        let zone = crate::dqs::asked_with_key(config)?;
        let path = config.credentials_directory.join(name);
        return Some(Reader::Dqs { zone, path });
    }
    (name == "metrics-credential" && scraped).then_some(Reader::Prometheus)
}

/// What a file that may be empty holds, as its reader takes it.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Held {
    /// What its reader takes.
    Usable,
    /// Nothing at all, which means none, or what its reader takes for none.
    Lacking(Lacks),
}

/// What the file `name` at `path` holds, by its reader's own rule: the
/// scrape credential and the key of Spamhaus' Data Query Service as the
/// collector reads them.
pub(super) fn held(config: &Config, name: &str, path: &Path) -> Held {
    let Ok(data) = fs::read(path) else {
        return Held::Lacking(Lacks::Unread);
    };
    if data.trim_ascii().is_empty() {
        return Held::Lacking(Lacks::Empty);
    }
    match name {
        "metrics-credential" if ScrapeCredential::read(&data).is_none() => {
            Held::Lacking(Lacks::NoCredential)
        }
        "spamhaus-dqs-key" => {
            let credentials = Credentials::new(&config.credentials_directory);
            match collector::dqs_key(config, &credentials) {
                DqsKey::Missing(_) => Held::Lacking(Lacks::NoKey),
                DqsKey::Key(_) | DqsKey::Unset => Held::Usable,
            }
        }
        _ => Held::Usable,
    }
}

/// A file that may be empty: empty, in order where nothing reads it; empty
/// or holding what its reader takes for none, a failure with the way to
/// fill it where something reads it. Otherwise owner and mode judge it
/// (`kept`).
pub(super) fn judged(
    name: &str,
    held: &Held,
    mode: u32,
    reader: Option<Reader>,
    kept: Finding,
) -> Finding {
    match (held, reader) {
        (Held::Lacking(lacks), Some(reader)) => {
            Finding::fail(states::unusable(name, *lacks, &reader))
        }
        (Held::Lacking(Lacks::Empty), None) => Finding::ok(states::empty(name, mode)),
        (Held::Usable | Held::Lacking(_), _) => kept,
    }
}

/// A file the units load that may be empty, which means none.
fn optional(config: &Config, name: &str) -> Finding {
    optional_of(config, name, 0)
}

/// [`optional`], with the file owned by `owner`, which is root on a real
/// host.
pub(super) fn optional_of(config: &Config, name: &str, owner: u32) -> Finding {
    let path = config.credentials_directory.join(name);
    let reads = reader(config, name);
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return Finding::fail(match &reads {
            Some(reader) => states::missing_read(name, &path, reader),
            None => states::missing_empty(name, &path),
        });
    };
    let kept = private(&path, name, &states::made_empty(&path), owner);
    if kept.level != Level::Ok {
        return kept;
    }
    let held = held(config, name, &path);
    judged(name, &held, metadata.mode() & 0o777, reads, kept)
}

pub(super) fn files(config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    // The checks' paths, which root reads and the collector, in its unit's
    // sandbox, may not.
    if let Ok(providers) = garrison_collector::build(&config.collector.providers) {
        for said in units::hidden_paths(&providers) {
            findings.push(Finding::fail(states::path_hidden(said)));
        }
    }
    // Setup writes these root's with mode 600, and nothing changes them after.
    for name in KEYS {
        findings.push(key(&config.credentials_directory.join(name), name));
    }
    // The installer keeps these, empty where nothing needs them.
    for name in units::COLLECTOR_FILES
        .into_iter()
        .chain(units::NOTIFICATION_FILES)
    {
        findings.push(optional(config, name));
    }
    findings
}

#[cfg(test)]
mod tests;
