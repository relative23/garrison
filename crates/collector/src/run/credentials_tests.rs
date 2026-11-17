//! What a run reads of its own secrets and hands its checks.

use std::sync::{Arc, Mutex};

use garrison_core::credentials::SecretSource;

use super::*;
use crate::context::{Collected, DqsKey, Report, Scrape};
use crate::testing::{Canned, now};

/// What a run handed to its provider: the API key and the metrics credential.
type Handed = Arc<Mutex<Option<(Option<String>, Scrape)>>>;

struct Probe(Handed);

impl Provider for Probe {
    fn name(&self) -> &'static str {
        "probe"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let handed = (
            context.native_key.clone(),
            context.metrics_credential.clone(),
        );
        *self.0.lock().unwrap() = Some(handed);
        Ok(Report::default())
    }
}

fn private(path: &Path, data: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn providers_receive_the_credentials_that_could_be_read() {
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let credentials = Credentials::new(directory.path().join("credentials"));
    let handed = Handed::default();
    let providers = vec![Box::new(Probe(Arc::clone(&handed))) as Box<dyn Provider>];
    let runner = Canned(String::new());
    let run = || {
        collect_from(&providers, &config, &credentials, &runner, now()).unwrap();
        handed.lock().unwrap().take().unwrap()
    };
    // Why there is none names the file as the operator fills it.
    let metrics = config.collector.metrics_credential.as_ref().unwrap();
    let file = config.credentials_directory.join("metrics-credential");
    let missing = |what: &str| Scrape::Missing(format!("{} {what}", file.display()));
    assert_eq!(run(), (None, missing("cannot be read")));
    private(
        &credentials.path(&config.collector.native_key),
        "collector-key-0123456789",
    );
    private(
        &credentials.path(metrics),
        r#"{"username": "scraper", "secret": "s3cret"}"#,
    );
    assert_eq!(
        run(),
        (
            Some("collector-key-0123456789".into()),
            Scrape::Credential("scraper".into(), "s3cret".into())
        )
    );
    private(&credentials.path(metrics), r#"{"username": "scraper"}"#);
    assert_eq!(run().1, missing("holds no credential"));
    // A list of the two values is no credential.
    private(&credentials.path(metrics), r#"["scraper", "s3cret"]"#);
    assert_eq!(run().1, missing("holds no credential"));
    // An empty file, as the installer keeps one, is none.
    private(&credentials.path(metrics), "\n");
    assert_eq!(run().1, missing("is empty"));
    // The setting off reads no file at all.
    let mut off = config.clone();
    off.collector.metrics_credential = None;
    collect_from(&providers, &off, &credentials, &runner, now()).unwrap();
    assert_eq!(handed.lock().unwrap().take().unwrap().1, Scrape::Off);
}

/// What a run handed to its provider of the key of Spamhaus' Data Query Service.
struct Keyed(Arc<Mutex<Option<DqsKey>>>);

impl Provider for Keyed {
    fn name(&self) -> &'static str {
        "keyed"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        *self.0.lock().unwrap() = Some(context.dqs_key.clone());
        Ok(Report::default())
    }
}

/// The key is read from its file for each run; where there is none, the
/// checks are told why, with the file to write it into and never what the
/// file holds.
#[test]
fn the_key_of_spamhaus_dqs_is_read_for_each_run() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = crate::testing::config(directory.path());
    let credentials = Credentials::new(directory.path().join("credentials"));
    let handed = Arc::new(Mutex::new(None));
    let providers = vec![Box::new(Keyed(Arc::clone(&handed))) as Box<dyn Provider>];
    let runner = Canned(String::new());
    let run = |config: &Config| {
        collect_from(&providers, config, &credentials, &runner, now()).unwrap();
        handed.lock().unwrap().take().unwrap()
    };
    assert_eq!(run(&config), DqsKey::Unset);
    config.collector.dqs_key = Some(SecretSource::Credential("spamhaus-dqs-key".into()));
    let file = config.credentials_directory.join("spamhaus-dqs-key");
    let why = |what: &str| {
        DqsKey::Missing(format!(
            "{} {what}; write the key of Spamhaus' Data Query Service into it",
            file.display()
        ))
    };
    assert_eq!(run(&config), why("cannot be read"));
    private(&file, "\n");
    assert_eq!(run(&config), why("is empty"));
    for wrong in ["two words", "key.with.dots", "ünïcode"] {
        private(&file, wrong);
        let said = run(&config);
        assert_eq!(
            said,
            why("holds no such key, one word of letters and digits")
        );
        assert!(!format!("{said:?}").contains(wrong), "{said:?}");
    }
    private(&file, "abcdefghijklmnopqrstuvwxyz\n");
    assert_eq!(
        run(&config),
        DqsKey::Key("abcdefghijklmnopqrstuvwxyz".into())
    );
}

#[test]
fn a_scrape_credential_is_written_as_it_is_read_and_never_shows_its_secret() {
    let credential = ScrapeCredential {
        username: "scraper".to_owned(),
        secret: "s3cret-0123456789".to_owned(),
    };
    let written = serde_json::to_string(&credential).unwrap();
    assert_eq!(
        written,
        r#"{"username":"scraper","secret":"s3cret-0123456789"}"#
    );
    let read: ScrapeCredential = serde_json::from_str(&written).unwrap();
    assert_eq!(
        (read.username, read.secret),
        (credential.username.clone(), credential.secret.clone())
    );
    assert_eq!(
        format!("{credential:?}"),
        r#"ScrapeCredential { username: "scraper", .. }"#
    );
}

/// A file that other users may read, or that is larger than 16 KiB, says
/// so, and the first what makes it private: the scrape credential's and the
/// key's alike.
#[test]
fn a_file_that_cannot_be_read_says_why() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let mut config = crate::testing::config(directory.path());
    config.collector.dqs_key = Some(SecretSource::Credential("spamhaus-dqs-key".into()));
    let credentials = Credentials::new(&config.credentials_directory);
    let memory = crate::testing::Remembered::default();
    let metrics = config.credentials_directory.join("metrics-credential");
    let key = config.credentials_directory.join("spamhaus-dqs-key");
    let open = |file: &Path, data: &str| {
        private(file, data);
        fs::set_permissions(file, fs::Permissions::from_mode(0o644)).unwrap();
    };
    let private_again = |file: &Path| {
        format!(
            "{0} may be read by other users; make it root's with mode 600: chown root {0} && \
             chmod 600 {0}",
            file.display()
        )
    };
    open(&metrics, r#"{"username": "scraper", "secret": "s3cret"}"#);
    open(&key, "abcdefghijklmnopqrstuvwxyz");
    assert_eq!(
        metrics_credential(&config, &credentials, &memory),
        Scrape::Missing(private_again(&metrics))
    );
    assert_eq!(
        dqs_key(&config, &credentials),
        DqsKey::Missing(private_again(&key))
    );
    let large = "x".repeat(16385);
    private(&metrics, &large);
    private(&key, &large);
    assert_eq!(
        metrics_credential(&config, &credentials, &memory),
        Scrape::Missing(format!("{} is larger than 16 KiB", metrics.display()))
    );
    assert_eq!(
        dqs_key(&config, &credentials),
        DqsKey::Missing(format!(
            "{} is larger than 16 KiB; write the key of Spamhaus' Data Query Service into it",
            key.display()
        ))
    );
}
