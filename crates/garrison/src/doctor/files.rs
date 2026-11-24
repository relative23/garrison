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

use super::{Finding, Level};
use crate::units;

/// The keys setup writes, which every installation reads.
const KEYS: [&str; 3] = [
    "webhook-signature-key",
    "collector-native-key",
    "broker-native-key",
];

/// One of the files doctor checks: what it is, the command that makes it,
/// and what gives it owner and mode.
struct Private<'a> {
    what: &'a str,
    made_by: &'a str,
    kept: String,
}

/// Owned by `owner`, root on a real host, and readable by nobody else.
fn private(path: &Path, file: &Private<'_>, owner: u32) -> Finding {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Finding::fail(
            format!("{} is missing: {}", file.what, path.display()),
            format!("Run `{}`, which makes it.", file.made_by),
        );
    };
    // Neither the installer nor the services follow a link here or change
    // a folder: only the file itself does.
    if !metadata.is_file() {
        return Finding::fail(
            format!(
                "{} is a link or a folder, not a file: {}",
                file.what,
                path.display()
            ),
            format!(
                "Remove it; then `{}` makes the file itself there.",
                file.made_by
            ),
        );
    }
    let mode = metadata.mode() & 0o777;
    if metadata.uid() == owner && mode & !0o600 == 0 {
        Finding::ok(format!("{} is private ({mode:o})", file.what))
    } else {
        Finding::fail(
            format!(
                "{} is not root-owned with mode 600 or less (mode {mode:o})",
                path.display()
            ),
            file.kept.clone(),
        )
    }
}

/// A key setup writes, which its service reads with every start or check.
/// An empty file, or one that holds something other than a key, gives that
/// service none, as a missing file does, and setup makes a key there; one
/// that holds a key is judged by owner and mode.
fn key(path: &Path, file: &Private<'_>) -> Finding {
    let held = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => protected::holds(path, Form::Token),
        // Missing, a link or a folder: said as of every private file.
        _ => return private(path, file, 0),
    };
    let lacks = match held {
        Ok(Holds::Secret) => return private(path, file, 0),
        Ok(Holds::Nothing) => "is empty",
        Ok(Holds::Other) => "holds something other than a key",
        Err(_) => "cannot be read",
    };
    Finding::fail(
        format!(
            "{} {lacks}, so {} has no key: {}",
            file.what,
            loaders(file.what),
            path.display()
        ),
        format!("Run `{}`, which makes it.", file.made_by),
    )
}

/// What of the configuration reads the file `name` and so needs it filled,
/// with how to fill it; `None` where an empty file serves. The notification
/// channels' files are judged with the channels.
pub(super) fn reader(config: &Config, name: &str) -> Option<(&'static str, String)> {
    let scraped = config.collector.metrics_credential.is_some()
        && config.collector.providers.iter().any(|provider| {
            provider.get("type").and_then(toml::Value::as_str) == Some("prometheus")
        });
    if name == "spamhaus-dqs-key" {
        let zone = crate::dqs::asked_with_key(config)?;
        let path = config.credentials_directory.join(name);
        return Some((
            "the reputation check asks a list of Spamhaus' Data Query Service with it",
            format!(
                "Write the key into it ({zone} is asked with it): install -m 600 /dev/null {0} \
                 && sh -c 'cat > {0}', then paste the key and press Enter and Ctrl-D.",
                path.display()
            ),
        ));
    }
    (name == "metrics-credential" && scraped).then(|| {
        (
            "the prometheus check reads Stalwart's exporter with it",
            garrison_collector::context::SCRAPE_FIX.to_owned(),
        )
    })
}

/// The units that load the file `name`, as a sentence names them.
fn loaders(name: &str) -> String {
    let loading: Vec<&str> = units::SECRETS
        .iter()
        .filter(|(_, _, loaded)| *loaded == name)
        .flat_map(|(_, units, _)| units.iter().copied())
        .collect();
    loading.join(" and ")
}

/// What a file that may be empty holds, as its reader takes it.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Held {
    /// Nothing but line ends and spaces, which means none.
    Nothing,
    /// What its reader takes.
    Usable,
    /// Something its reader takes for none, in the reader's words.
    Unusable(&'static str),
}

/// What the file `name` at `path` holds, by its reader's own rule: the
/// scrape credential and the key of Spamhaus' Data Query Service as the
/// collector reads them.
pub(super) fn held(config: &Config, name: &str, path: &Path) -> Held {
    let Ok(data) = fs::read(path) else {
        return Held::Unusable("cannot be read");
    };
    if data.trim_ascii().is_empty() {
        return Held::Nothing;
    }
    match name {
        "metrics-credential" if ScrapeCredential::read(&data).is_none() => {
            Held::Unusable("holds no credential")
        }
        "spamhaus-dqs-key" => {
            let credentials = Credentials::new(&config.credentials_directory);
            match collector::dqs_key(config, &credentials) {
                DqsKey::Missing(_) => {
                    Held::Unusable("holds no key, one word of letters and digits")
                }
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
    reader: Option<(&str, String)>,
    kept: Finding,
) -> Finding {
    match (held, reader) {
        (Held::Nothing, Some((reads, fill))) => {
            Finding::fail(format!("{name} is empty, but {reads}"), fill)
        }
        (Held::Nothing, None) => {
            Finding::ok(format!("{name} is empty, which means none ({mode:o})"))
        }
        (Held::Unusable(what), Some((reads, fill))) => {
            Finding::fail(format!("{name} {what}, but {reads}"), fill)
        }
        (Held::Usable | Held::Unusable(_), _) => kept,
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
    let made = format!("install -m 600 /dev/null {}", path.display());
    let reads = reader(config, name);
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        let fix = reads.map_or_else(
            || format!("Make it, empty, which means none: {made}"),
            |(_, fill)| fill,
        );
        return Finding::fail(
            format!(
                "{name} is missing: {}; systemd starts {} only with it",
                path.display(),
                loaders(name)
            ),
            fix,
        );
    };
    let kept = private(
        &path,
        &Private {
            what: name,
            made_by: &made,
            kept: format!(
                "Make it root's with mode 600: chown root {0} && chmod 600 {0}",
                path.display()
            ),
        },
        owner,
    );
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
        for (what, fix) in units::hidden_paths(&providers) {
            findings.push(Finding::fail(what, format!("{fix}.")));
        }
    }
    // Setup writes these root's with mode 600, and nothing changes them after.
    for name in KEYS {
        let path = config.credentials_directory.join(name);
        let credential = Private {
            what: name,
            made_by: "garrison stalwart setup",
            kept: format!(
                "Make it root's with mode 600: chown root {0} && chmod 600 {0}",
                path.display()
            ),
        };
        findings.push(key(&path, &credential));
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
