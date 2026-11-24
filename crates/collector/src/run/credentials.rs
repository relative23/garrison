//! The collector's own secrets, read anew for each run: its API key for
//! Stalwart, the scrape credential of Stalwart's exporter and the key of
//! Spamhaus' Data Query Service, with what the journal says of them.

use std::fmt;
use std::path::{Path, PathBuf};

use garrison_core::config::Config;
use garrison_core::credentials::{Credentials, SecretSource, made_by_setup};
use garrison_core::files::{Form, ProtectedFileError};
use garrison_core::json;
use serde::{Deserialize, Serialize};

use crate::context::{DqsKey, Memory, SCRAPE_FIX, Scrape};

const MAX_CREDENTIAL: usize = 16384;

/// Where the status database keeps what the journal last said of the
/// collector's API key for Stalwart: why it had none, or nothing.
const KEY_SAID: &str = "run.native-key";
/// The same of the scrape credential of Stalwart's metrics exporter.
const SCRAPE_SAID: &str = "run.metrics-credential";

/// Whether the journal is to say `now` of what it keeps under `key`, since
/// it said otherwise last: the runs come every minute, and each reason is
/// said once. `now` is kept for the next run.
fn news(memory: &dyn Memory, key: &str, now: &str) -> bool {
    let changed = memory.recall(key).unwrap_or_default() != now;
    if changed {
        memory.keep(key, now);
    }
    changed
}

/// The file a secret setting names, as an operator fills it: in the
/// configured credentials directory, not systemd's copy of it.
fn configured(config: &Config, source: &SecretSource) -> PathBuf {
    match source {
        SecretSource::Credential(name) => config.credentials_directory.join(name),
        SecretSource::File(path) => path.clone(),
    }
}

/// The collector's API key for Stalwart, read anew for each run. Where it
/// has none, the journal says why, with the file and what makes a key,
/// once for each reason, since the runs come every minute; and once that
/// it has the key again. A card that needs the key says so when its check
/// next reads Stalwart, which a check that keeps its reading does later.
pub(super) fn native_key(
    config: &Config,
    credentials: &Credentials,
    memory: &dyn Memory,
) -> Option<String> {
    let source = &config.collector.native_key;
    let read = credentials.read_secret(source);
    let why = read
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    if news(memory, KEY_SAID, &why) {
        match &read {
            Ok(_) => log::info!(
                "The collector has an API key for Stalwart again, from {}",
                credentials.path(source).display()
            ),
            Err(error) => {
                let file = configured(config, source);
                let why = match unread(error, &file) {
                    (what, Some(mend)) => format!("{} {what}; {mend}", file.display()),
                    (_, None) => format!("{error}{}", made_by_setup(error)),
                };
                log::warn!(
                    "The collector has no API key for Stalwart: {why}. Each card that needs it \
                     says so when its check next reads Stalwart."
                );
            }
        }
    }
    read.ok()
}

/// The scrape credential file, as `garrison stalwart setup` writes it and
/// the collector reads it.
#[derive(Clone, Deserialize, Serialize)]
pub struct ScrapeCredential {
    pub username: String,
    pub secret: String,
}

impl fmt::Debug for ScrapeCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The secret stays out of logs and panic messages.
        formatter
            .debug_struct("ScrapeCredential")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl ScrapeCredential {
    /// The credential a file holds, as setup writes it; none for anything
    /// else, an empty file among it. Setup asks so whether to write one.
    #[must_use]
    pub fn read(data: &[u8]) -> Option<Self> {
        json::object(json::parse(data, MAX_CREDENTIAL).ok()?).ok()
    }
}

/// Why a secret's file that cannot be read gives none, in words that hold
/// nothing of it, and what makes it private where other users may read it.
fn unread(error: &ProtectedFileError, file: &Path) -> (&'static str, Option<String>) {
    match error {
        ProtectedFileError::NotPrivate(_) | ProtectedFileError::TooOpen(_) => (
            "may be read by other users",
            Some(format!(
                "make it root's with mode 600: chown root {0} && chmod 600 {0}",
                file.display()
            )),
        ),
        ProtectedFileError::TooLarge(_) => ("is larger than 16 KiB", None),
        _ => ("cannot be read", None),
    }
}

/// The scrape credential of Stalwart's metrics exporter from its file,
/// read anew for each run as the collector's key is. Why there is none
/// names the file, never what it holds; the exporter's card says it with
/// what fills the file. The journal says it once for each reason, but not
/// of an empty file, which the installer keeps where setup wrote none
/// because the exporter is another's.
pub(super) fn metrics_credential(
    config: &Config,
    credentials: &Credentials,
    memory: &dyn Memory,
) -> Scrape {
    let Some(source) = &config.collector.metrics_credential else {
        return Scrape::Off;
    };
    let file = configured(config, source);
    let missing = |what: &str| format!("{} {what}", file.display());
    let read = credentials.read_private(source, MAX_CREDENTIAL);
    let held = read
        .as_deref()
        .map(|data| (data.trim_ascii().is_empty(), ScrapeCredential::read(data)));
    // Setup's fix mends every reason but a file others may read.
    let setup = format!(" {SCRAPE_FIX}");
    let (scrape, said, fix) = match held {
        Ok((true, _)) => (Scrape::Missing(missing("is empty")), String::new(), setup),
        Ok((false, Some(ScrapeCredential { username, secret }))) => {
            (Scrape::Credential(username, secret), String::new(), setup)
        }
        Ok((false, None)) => (
            Scrape::Missing(missing("holds no credential")),
            missing("holds no credential"),
            setup,
        ),
        Err(error) => match unread(error, &file) {
            (what, None) => (Scrape::Missing(missing(what)), missing(what), setup),
            (what, Some(mend)) => {
                let why = format!("{}; {mend}", missing(what));
                (Scrape::Missing(why.clone()), why, String::new())
            }
        },
    };
    if news(memory, SCRAPE_SAID, &said) {
        match (&scrape, said.is_empty()) {
            (_, false) => log::warn!(
                "The collector has no scrape credential for Stalwart's exporter: {said}.{fix}"
            ),
            (Scrape::Credential(..), true) => {
                log::info!(
                    "The collector has a scrape credential again, from {}",
                    file.display()
                );
            }
            (Scrape::Off | Scrape::Missing(_), true) => {}
        }
    }
    scrape
}

/// The key of Spamhaus' Data Query Service from its credential, read anew
/// for each run as the metrics credential is. Why there is none names the
/// file an operator writes it into, never what it holds. `garrison doctor`
/// judges the file by it.
#[must_use]
pub fn dqs_key(config: &Config, credentials: &Credentials) -> DqsKey {
    let Some(source) = &config.collector.dqs_key else {
        return DqsKey::Unset;
    };
    let file = configured(config, source);
    let missing = |what: &str| {
        DqsKey::Missing(format!(
            "{} {what}; write the key of Spamhaus' Data Query Service into it",
            file.display()
        ))
    };
    // A key is the first label of the zone's name: letters and digits.
    let label = |key: &str| {
        (1..=63).contains(&key.len()) && key.bytes().all(|byte| byte.is_ascii_alphanumeric())
    };
    match credentials.read_optional_secret(source, Form::Address) {
        Ok(Some(key)) if label(&key) => DqsKey::Key(key),
        Ok(Some(_)) | Err(ProtectedFileError::InvalidSecret(_)) => {
            missing("holds no such key, one word of letters and digits")
        }
        Ok(None) => missing("is empty"),
        Err(error) => match unread(&error, &file) {
            (what, None) => missing(what),
            (what, Some(mend)) => DqsKey::Missing(format!("{} {what}; {mend}", file.display())),
        },
    }
}
