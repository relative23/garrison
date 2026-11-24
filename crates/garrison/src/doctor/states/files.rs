//! The states of the credentials' files and of the checks' paths
//! (`doctor/files.rs`).

use std::path::{Path, PathBuf};

use garrison_collector::context::SCRAPE_FIX;

use crate::state::State;
use crate::units;

/// What makes a key setup writes.
pub(in crate::doctor) const SETUP: &str = "garrison stalwart setup";

/// What makes a file that may be empty, empty, which means none.
pub(in crate::doctor) fn made_empty(path: &Path) -> String {
    format!("install -m 600 /dev/null {}", path.display())
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

/// What a file holds that its reader does not take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::doctor) enum Lacks {
    /// Nothing but line ends and spaces.
    Empty,
    /// Nothing root can read.
    Unread,
    /// Something other than a key.
    Other,
    /// No scrape credential, as the collector reads one.
    NoCredential,
    /// No key of Spamhaus' Data Query Service, one word of letters and digits.
    NoKey,
}

impl Lacks {
    fn said(self) -> &'static str {
        match self {
            Self::Empty => "is empty",
            Self::Unread => "cannot be read",
            Self::Other => "holds something other than a key",
            Self::NoCredential => "holds no credential",
            Self::NoKey => "holds no key, one word of letters and digits",
        }
    }
}

/// What of the configuration reads a file that may be empty, so that it
/// must be filled.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::doctor) enum Reader {
    /// The prometheus check, with Stalwart's exporter.
    Prometheus,
    /// The reputation check, which asks `zone` with the key at `path`.
    Dqs { zone: String, path: PathBuf },
}

impl Reader {
    fn reads(&self) -> &'static str {
        match self {
            Self::Prometheus => "the prometheus check reads Stalwart's exporter with it",
            Self::Dqs { .. } => {
                "the reputation check asks a list of Spamhaus' Data Query Service with it"
            }
        }
    }

    fn fill(&self) -> String {
        match self {
            Self::Prometheus => SCRAPE_FIX.to_owned(),
            Self::Dqs { zone, path } => format!(
                "Write the key into it ({zone} is asked with it): install -m 600 /dev/null {0} \
                 && sh -c 'cat > {0}', then paste the key and press Enter and Ctrl-D.",
                path.display()
            ),
        }
    }
}

/// A check's path the collector's unit hides from it, in check-config's
/// words.
pub(in crate::doctor) fn path_hidden((what, fix): (String, String)) -> State {
    State::new("doctor-path-hidden", what).with_fix(format!("{fix}."))
}

pub(in crate::doctor) fn missing(name: &str, path: &Path, made_by: &str) -> State {
    let text = format!("{name} is missing: {}", path.display());
    State::new("doctor-credential-missing", text)
        .with_fix(format!("Run `{made_by}`, which makes it."))
}

pub(in crate::doctor) fn not_a_file(name: &str, path: &Path, made_by: &str) -> State {
    let text = format!(
        "{name} is a link or a folder, not a file: {}",
        path.display()
    );
    State::new("doctor-credential-not-a-file", text).with_fix(format!(
        "Remove it; then `{made_by}` makes the file itself there."
    ))
}

pub(in crate::doctor) fn private(name: &str, mode: u32) -> State {
    let text = format!("{name} is private ({mode:o})");
    State::new("doctor-credential-private", text)
}

pub(in crate::doctor) fn open(path: &Path, mode: u32) -> State {
    let text = format!(
        "{} is not root-owned with mode 600 or less (mode {mode:o})",
        path.display()
    );
    State::new("doctor-credential-open", text).with_fix(format!(
        "Make it root's with mode 600: chown root {0} && chmod 600 {0}",
        path.display()
    ))
}

/// A key setup writes that holds no key, so its service has none.
pub(in crate::doctor) fn no_key(name: &str, lacks: Lacks, path: &Path) -> State {
    let text = format!(
        "{name} {}, so {} has no key: {}",
        lacks.said(),
        loaders(name),
        path.display()
    );
    State::new("doctor-credential-no-key", text).with_fix(format!("Run `{SETUP}`, which makes it."))
}

/// A file that may be empty is missing, and systemd starts its units only
/// with it.
pub(in crate::doctor) fn missing_empty(name: &str, path: &Path) -> State {
    let text = format!(
        "{name} is missing: {}; systemd starts {} only with it",
        path.display(),
        loaders(name)
    );
    State::new("doctor-credential-missing-empty", text).with_fix(format!(
        "Make it, empty, which means none: {}",
        made_empty(path)
    ))
}

/// The same, where the configuration reads it, so that it must be filled.
pub(in crate::doctor) fn missing_read(name: &str, path: &Path, reader: &Reader) -> State {
    let text = format!(
        "{name} is missing: {}; systemd starts {} only with it",
        path.display(),
        loaders(name)
    );
    State::new("doctor-credential-missing-read", text).with_fix(reader.fill())
}

pub(in crate::doctor) fn empty(name: &str, mode: u32) -> State {
    let text = format!("{name} is empty, which means none ({mode:o})");
    State::new("doctor-credential-empty", text)
}

/// A file the configuration reads that holds nothing its reader takes.
pub(in crate::doctor) fn unusable(name: &str, lacks: Lacks, reader: &Reader) -> State {
    let text = format!("{name} {}, but {}", lacks.said(), reader.reads());
    State::new("doctor-credential-unusable", text).with_fix(reader.fill())
}

#[cfg(test)]
pub(super) fn rows() -> Vec<(State, &'static str)> {
    let credentials = Path::new("/etc/garrison/credentials");
    let file = |name: &str| credentials.join(name);
    let dqs = Reader::Dqs {
        zone: "zen.dq.spamhaus.net".into(),
        path: file("spamhaus-dqs-key"),
    };
    vec![
        (
            path_hidden((
                "providers[receipt].path is /home/jobs/nightly.json, under /home, which \
                 garrison-collect.service hides from the collector (ProtectHome=true): the check \
                 cannot read it there"
                    .into(),
                "Keep it where the collector sees it".into(),
            )),
            "providers[receipt].path is /home/jobs/nightly.json, under /home, which \
             garrison-collect.service hides from the collector (ProtectHome=true): the check \
             cannot read it there [doctor-path-hidden]\n      Keep it where the collector sees \
             it.",
        ),
        (
            missing("broker-native-key", &file("broker-native-key"), SETUP),
            "broker-native-key is missing: /etc/garrison/credentials/broker-native-key \
             [doctor-credential-missing]\n      Run `garrison stalwart setup`, which makes it.",
        ),
        (
            not_a_file(
                "metrics-credential",
                &file("metrics-credential"),
                &made_empty(&file("metrics-credential")),
            ),
            "metrics-credential is a link or a folder, not a file: \
             /etc/garrison/credentials/metrics-credential [doctor-credential-not-a-file]\n      \
             Remove it; then `install -m 600 /dev/null \
             /etc/garrison/credentials/metrics-credential` makes the file itself there.",
        ),
        (
            private("webhook-signature-key", 0o600),
            "webhook-signature-key is private (600) [doctor-credential-private]",
        ),
        (
            open(&file("broker-native-key"), 0o644),
            "/etc/garrison/credentials/broker-native-key is not root-owned with mode 600 or less \
             (mode 644) [doctor-credential-open]\n      Make it root's with mode 600: chown root \
             /etc/garrison/credentials/broker-native-key && chmod 600 \
             /etc/garrison/credentials/broker-native-key",
        ),
        (
            no_key(
                "webhook-signature-key",
                Lacks::Empty,
                &file("webhook-signature-key"),
            ),
            "webhook-signature-key is empty, so garrison-ingest.service has no key: \
             /etc/garrison/credentials/webhook-signature-key [doctor-credential-no-key]\n      \
             Run `garrison stalwart setup`, which makes it.",
        ),
        (
            missing_empty("ntfy-token", &file("ntfy-token")),
            "ntfy-token is missing: /etc/garrison/credentials/ntfy-token; systemd starts \
             garrison-collect.service and garrison-watch.service only with it \
             [doctor-credential-missing-empty]\n      Make it, empty, which means none: install \
             -m 600 /dev/null /etc/garrison/credentials/ntfy-token",
        ),
        (
            missing_read("spamhaus-dqs-key", &file("spamhaus-dqs-key"), &dqs),
            "spamhaus-dqs-key is missing: /etc/garrison/credentials/spamhaus-dqs-key; systemd \
             starts garrison-collect.service only with it [doctor-credential-missing-read]\n      \
             Write the key into it (zen.dq.spamhaus.net is asked with it): install -m 600 \
             /dev/null /etc/garrison/credentials/spamhaus-dqs-key && sh -c 'cat > \
             /etc/garrison/credentials/spamhaus-dqs-key', then paste the key and press Enter and \
             Ctrl-D.",
        ),
        (
            empty("metrics-credential", 0o600),
            "metrics-credential is empty, which means none (600) [doctor-credential-empty]",
        ),
        (
            unusable(
                "metrics-credential",
                Lacks::NoCredential,
                &Reader::Prometheus,
            ),
            "metrics-credential holds no credential, but the prometheus check reads Stalwart's \
             exporter with it [doctor-credential-unusable]\n      Run `garrison stalwart \
             setup`, which writes it while Stalwart's exporter is Garrison's or off; for an \
             exporter of another's, write its user name and password into it as \
             configuration.md says (collector.metrics_credential).",
        ),
    ]
}
