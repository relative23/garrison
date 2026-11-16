//! Files that must stay private: the access policy, root's and readable by
//! the broker's group alone, and the credentials, root's alone. The units
//! load every credential (`LoadCredential=`), and systemd starts none of
//! them without its file, so each must be there; a file that may be empty,
//! which means none, is in order empty unless the configuration reads it.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use garrison_core::config::Config;

use super::{Finding, Level};
use crate::units;

/// The keys setup writes, which every installation reads.
const KEYS: [&str; 3] = [
    "webhook-signature-key",
    "collector-native-key",
    "broker-native-key",
];

/// One of the files doctor checks: what it is, whether its group may read
/// it, the command that makes it, and what gives it owner and mode.
struct Private<'a> {
    what: &'a str,
    group_read: bool,
    made_by: &'a str,
    kept: String,
}

/// Root-owned and readable by nobody else (`group` may read the policy).
fn private(path: &Path, file: &Private<'_>) -> Finding {
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
    let allowed = if file.group_read { 0o640 } else { 0o600 };
    let mode = metadata.mode() & 0o777;
    if metadata.uid() == 0 && mode & !allowed == 0 {
        Finding::ok(format!("{} is private ({mode:o})", file.what))
    } else {
        Finding::fail(
            format!(
                "{} is not root-owned with mode {allowed:o} or less (mode {mode:o})",
                path.display()
            ),
            file.kept.clone(),
        )
    }
}

/// What of the configuration reads the file `name` and so needs it filled,
/// with how to fill it; `None` where an empty file serves. The notification
/// channels' files are judged with the channels.
fn reader(config: &Config, name: &str) -> Option<(&'static str, String)> {
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
            "Run `garrison stalwart setup`, which writes it while Stalwart's exporter is \
             Garrison's or off; for an exporter of another's, write its user name and password \
             into it as configuration.md says (collector.metrics_credential)."
                .to_owned(),
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

/// An empty file that may be empty: in order where nothing reads it, a
/// failure with the way to fill it where something does. A file that holds
/// something is judged by owner and mode alone (`kept`).
fn judged(
    name: &str,
    empty: bool,
    mode: u32,
    reader: Option<(&str, String)>,
    kept: Finding,
) -> Finding {
    match (empty, reader) {
        (true, Some((reads, fill))) => Finding::fail(format!("{name} is empty, but {reads}"), fill),
        (true, None) => Finding::ok(format!("{name} is empty, which means none ({mode:o})")),
        (false, _) => kept,
    }
}

/// A file the units load that may be empty, which means none.
fn optional(config: &Config, name: &str) -> Finding {
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
            group_read: false,
            made_by: &made,
            kept: format!(
                "Make it root's with mode 600: chown root {0} && chmod 600 {0}",
                path.display()
            ),
        },
    );
    if kept.level != Level::Ok {
        return kept;
    }
    let empty = fs::read(&path).is_ok_and(|data| data.trim_ascii().is_empty());
    judged(name, empty, metadata.mode() & 0o777, reads, kept)
}

pub(super) fn files(config: &Config) -> Vec<Finding> {
    // Where the broker reads it. The installer gives it owner and mode.
    let policy = Private {
        what: "the access policy",
        group_read: true,
        made_by: "garrison access init",
        kept: "Run the installer again; it sets owner and mode.".to_owned(),
    };
    let mut findings = vec![private(&config.broker.policy, &policy)];
    // Root reads it; the broker, in its unit's sandbox, may not.
    if let Some((what, fix)) = units::hidden_policy(&config.broker.policy) {
        findings.push(Finding::fail(what, format!("{fix}.")));
    }
    // And the checks' paths, which the collector reads in its own.
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
            group_read: false,
            made_by: "garrison stalwart setup",
            kept: format!(
                "Make it root's with mode 600: chown root {0} && chmod 600 {0}",
                path.display()
            ),
        };
        findings.push(private(&path, &credential));
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
