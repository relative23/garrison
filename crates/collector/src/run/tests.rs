use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;
use crate::context::{Collected, Report};
use crate::testing::{Canned, now};

fn ids(snapshot: &Snapshot) -> Vec<&str> {
    snapshot
        .observations
        .iter()
        .map(|observation| observation.id.as_str())
        .collect()
}

struct Broken;

impl Provider for Broken {
    fn name(&self) -> &'static str {
        "broken"
    }

    fn collect(&self, _: &Context<'_>) -> Collected {
        panic!("bug");
    }
}

struct Twice;

impl Provider for Twice {
    fn name(&self) -> &'static str {
        "twice"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let one = Observation::new(
            "same.id",
            "twice",
            "Same",
            [ModuleId::Services],
            Evidence::Process,
            State::Ok,
            context.checked_at(),
            "test",
        )?;
        Ok(Report {
            observations: vec![one.clone(), one],
            ..Report::default()
        })
    }
}

/// What a run handed to its provider: the API key and the metrics credential.
type Handed = Arc<Mutex<Option<(Option<String>, Option<(String, String)>)>>>;

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

fn private(path: &std::path::Path, data: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
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
    assert_eq!(run(), (None, None));
    private(
        &credentials.path(&config.collector.native_key),
        "collector-key-0123456789",
    );
    let metrics = config.collector.metrics_credential.as_ref().unwrap();
    private(
        &credentials.path(metrics),
        r#"{"username": "scraper", "secret": "s3cret"}"#,
    );
    assert_eq!(
        run(),
        (
            Some("collector-key-0123456789".into()),
            Some(("scraper".into(), "s3cret".into()))
        )
    );
    private(&credentials.path(metrics), r#"{"username": "scraper"}"#);
    assert_eq!(run().1, None);
    // A list of the two values is no credential.
    private(&credentials.path(metrics), r#"["scraper", "s3cret"]"#);
    assert_eq!(run().1, None);
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

#[test]
fn a_run_builds_the_configured_providers() {
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let credentials = Credentials::new(directory.path().join("credentials"));
    let snapshot = collect(&config, &credentials, &Canned(String::new())).unwrap();
    assert_eq!(ids(&snapshot), ["host.resources"]);
}

#[test]
fn a_failing_provider_does_not_hide_the_others() {
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let credentials = Credentials::new(directory.path().join("credentials"));
    let mut providers = vec![Box::new(Broken) as Box<dyn Provider>];
    providers.extend(crate::providers::build(&config.collector.providers).unwrap());
    let runner = Canned(String::new());
    let snapshot = collect_from(&providers, &config, &credentials, &runner, now()).unwrap();
    assert_eq!(ids(&snapshot), ["collector.broken", "host.resources"]);
    assert_eq!(
        snapshot.provider_errors,
        [ProviderError {
            provider: "broken".into(),
            error: "crashed".into()
        }]
    );
    assert_eq!(snapshot.collected_at, "2026-10-29T12:00:00+00:00");
    let stored = rusqlite::Connection::open(config.database(Database::Status)).unwrap();
    let text: String = stored
        .query_row("SELECT document FROM snapshots", [], |row| row.get(0))
        .unwrap();
    // The stored form names its version and reads back as the same snapshot.
    let document: Value = serde_json::from_str(&text).unwrap();
    let keys: Vec<&String> = document.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "schemaVersion",
            "collectedAt",
            "observations",
            "providerErrors"
        ]
    );
    assert_eq!(document["schemaVersion"], 1);
    assert_eq!(
        document["providerErrors"],
        json!([{"provider": "broken", "error": "crashed"}])
    );
    assert_eq!(
        crate::store::latest_snapshot(&stored).unwrap(),
        Some(snapshot)
    );
}

#[test]
fn duplicate_observation_ids_stop_the_run() {
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let credentials = Credentials::new(directory.path().join("credentials"));
    let providers = vec![Box::new(Twice) as Box<dyn Provider>];
    let runner = Canned(String::new());
    let error = collect_from(&providers, &config, &credentials, &runner, now()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Providers produced duplicate observation IDs: ['same.id']"
    );
    // The status database is opened before the providers run; no snapshot
    // of such a run is stored in it.
    let stored: i64 = rusqlite::Connection::open(config.database(Database::Status))
        .unwrap()
        .query_row("SELECT count(*) FROM snapshots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored, 0, "nothing is stored");
}
