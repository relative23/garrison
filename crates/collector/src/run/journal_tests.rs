//! What the collector's journal says of its API key for Stalwart and of the
//! scrape credential of Stalwart's exporter: where it has none, why, with
//! the file and what makes one, once for each reason and not in every run;
//! and once that it has it again.

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::testing::{Canned, now};

/// The lines this thread's runs wrote of themselves since the last call
/// that `about` takes.
fn said(about: impl Fn(&str) -> bool) -> Vec<String> {
    crate::journal::lines()
        .into_iter()
        .filter(|line| line.target.starts_with("garrison_collector::run"))
        .map(|line| line.text)
        .filter(|line| about(line))
        .collect()
}

/// A line about the collector's API key.
fn key(line: &str) -> bool {
    line.contains("API key")
}

fn private(path: &Path, data: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// Missing, then empty, then there: the journal says each reason once, with
/// the file and what makes a key, and not again in the runs after; then
/// that the key is there again. Only the cards that need the key go
/// without it, and they say so themselves.
#[test]
fn the_journal_says_once_for_each_reason_why_the_collector_has_no_key() {
    said(key);
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let credentials = Credentials::new(directory.path().join("credentials"));
    let providers: Vec<Box<dyn Provider>> = Vec::new();
    let runner = Canned(String::new());
    let run = || {
        collect_from(&providers, &config, &credentials, &runner, now()).unwrap();
        said(key)
    };
    let key = credentials.path(&config.collector.native_key);
    let no_key = |why: &str| {
        vec![format!(
            "WARN The collector has no API key for Stalwart: {why}: {}; run `garrison stalwart \
             setup`, which makes it. Every card that needs it says so until then.",
            key.display()
        )]
    };
    assert_eq!(run(), no_key("Protected file is unavailable"));
    assert_eq!(run(), Vec::<String>::new());
    private(&key, "");
    assert_eq!(run(), no_key("Protected file is empty"));
    private(&key, "\n");
    assert_eq!(run(), Vec::<String>::new());
    private(&key, "collector-key-0123456789\n");
    assert_eq!(
        run(),
        [format!(
            "INFO The collector has an API key for Stalwart again, from {}",
            key.display()
        )]
    );
    assert_eq!(run(), Vec::<String>::new());
    private(&key, "short\n");
    assert_eq!(run(), no_key("Protected secret has an invalid format"));
}

/// The scrape credential: a file that holds none is said once for each
/// reason, with the file and what fills it, and once that it holds one
/// again; an empty file, which the installer keeps where the exporter is
/// another's, is not said, since the exporter's card says it.
#[test]
fn the_journal_says_once_for_each_reason_why_the_collector_has_no_scrape_credential() {
    let scrape =
        |line: &str| line.contains("scrape credential") || line.contains("metrics credential");
    said(scrape);
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let credentials = Credentials::new(&config.credentials_directory);
    let providers: Vec<Box<dyn Provider>> = Vec::new();
    let runner = Canned(String::new());
    let run = || {
        collect_from(&providers, &config, &credentials, &runner, now()).unwrap();
        said(scrape)
    };
    let file = config.credentials_directory.join("metrics-credential");
    let none = |why: &str| {
        vec![format!(
            "WARN The collector has no scrape credential for Stalwart's exporter: {} {why}. Run \
             `garrison stalwart setup`, which writes it while Stalwart's exporter is Garrison's \
             or off; for an exporter of another's, write its user name and password into it as \
             configuration.md says (collector.metrics_credential).",
            file.display()
        )]
    };
    assert_eq!(run(), none("cannot be read"));
    assert_eq!(run(), Vec::<String>::new());
    private(&file, "{\"username\": \"scraper\"\n");
    assert_eq!(run(), none("holds no credential"));
    assert_eq!(run(), Vec::<String>::new());
    private(&file, r#"{"username": "scraper", "secret": "s3cret"}"#);
    assert_eq!(
        run(),
        [format!(
            "INFO The collector has a scrape credential again, from {}",
            file.display()
        )]
    );
    private(&file, "");
    assert_eq!(run(), Vec::<String>::new());
    assert_eq!(run(), Vec::<String>::new());
}
