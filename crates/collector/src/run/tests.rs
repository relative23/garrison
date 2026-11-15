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
        let one = Observation::new(Required {
            id: "same.id",
            provider: "twice",
            title: "Same",
            modules: [ModuleId::Services],
            evidence: Evidence::Process,
            state: State::Ok,
            checked_at: &context.checked_at(),
            source: "test",
        })?;
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
fn an_observation_that_two_checks_report_is_kept_once_and_said() {
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let credentials = Credentials::new(directory.path().join("credentials"));
    let mut providers = vec![Box::new(Twice) as Box<dyn Provider>];
    providers.extend(crate::providers::build(&config.collector.providers).unwrap());
    let runner = Canned(String::new());
    let snapshot = collect_from(&providers, &config, &credentials, &runner, now()).unwrap();
    // The first is kept, the others of the run are there, and the run says
    // what happened instead of storing nothing.
    assert_eq!(
        ids(&snapshot),
        ["same.id", "host.resources", "collector.duplicates"]
    );
    let said = snapshot.observations.last().unwrap();
    assert_eq!(said.state, State::Unknown);
    assert!(said.findings[0].contains("kept as it came first: same.id."));
    let stored = rusqlite::Connection::open(config.database(Database::Status)).unwrap();
    assert_eq!(
        crate::store::latest_snapshot(&stored).unwrap(),
        Some(snapshot)
    );
}

#[test]
fn two_checks_of_one_type_that_both_fail_stand_in_under_ids_of_their_own() {
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let credentials = Credentials::new(directory.path().join("credentials"));
    let providers: Vec<Box<dyn Provider>> =
        vec![Box::new(Broken), Box::new(Broken), Box::new(Broken)];
    let runner = Canned(String::new());
    let snapshot = collect_from(&providers, &config, &credentials, &runner, now()).unwrap();
    assert_eq!(
        ids(&snapshot),
        [
            "collector.broken",
            "collector.broken.2",
            "collector.broken.3"
        ]
    );
    // Each says which of the configured providers it stands for, as
    // `garrison check-config` names them, on its card and among the run's
    // failures: a type alone would name three times the same.
    let titles: Vec<&str> = snapshot
        .observations
        .iter()
        .map(|observation| observation.title.as_str())
        .collect();
    assert_eq!(
        titles,
        [
            "Provider broken (providers[0])",
            "Provider broken (providers[1])",
            "Provider broken (providers[2])"
        ]
    );
    let failed: Vec<&str> = snapshot
        .provider_errors
        .iter()
        .map(|error| error.provider.as_str())
        .collect();
    assert_eq!(
        failed,
        [
            "broken (providers[0])",
            "broken (providers[1])",
            "broken (providers[2])"
        ]
    );
    // The observations still name the type as their provider.
    assert_eq!(snapshot.observations[1].provider, "broken");
}

/// A provider that reports one observation after it took its time.
struct Takes(&'static str, Duration);

impl Provider for Takes {
    fn name(&self) -> &'static str {
        self.0
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        std::thread::sleep(self.1);
        Ok(Report::of(Observation::new(Required {
            id: &format!("{}.done", self.0),
            provider: self.0,
            title: "Done",
            modules: [ModuleId::Services],
            evidence: Evidence::Process,
            state: State::Ok,
            checked_at: &context.checked_at(),
            source: "test",
        })?))
    }
}

#[test]
fn a_check_that_uses_up_the_runs_time_costs_only_the_checks_after_it() {
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let credentials = Credentials::new(directory.path().join("credentials"));
    let takes =
        |name, millis| Box::new(Takes(name, Duration::from_millis(millis))) as Box<dyn Provider>;
    let providers = vec![
        takes("first", 0),
        takes("slow", 300),
        takes("late", 0),
        takes("later", 0),
    ];
    let runner = Canned(String::new());
    let time = Time {
        checks: Duration::from_millis(100),
        run: Duration::from_secs(30),
    };
    let snapshot = collect_within(&providers, &config, &credentials, &runner, now(), time).unwrap();
    // What ran is there, the slow check too: it was done, only late. The
    // checks behind it were not begun, and each says so in its place.
    assert_eq!(
        ids(&snapshot),
        [
            "first.done",
            "slow.done",
            "collector.late",
            "collector.later"
        ]
    );
    let late = &snapshot.observations[2];
    assert_eq!(late.state, State::Unknown);
    assert_eq!(
        late.findings,
        ["Not run: the checks before it used up the time of this collection run."]
    );
    assert_eq!(
        snapshot.provider_errors,
        ["late", "later"].map(|provider| ProviderError {
            provider: provider.into(),
            error: "not run".into()
        })
    );
    // The snapshot is stored, with what was found.
    let stored = rusqlite::Connection::open(config.database(Database::Status)).unwrap();
    assert_eq!(
        crate::store::latest_snapshot(&stored).unwrap(),
        Some(snapshot)
    );
    // With the time a run has, every check runs.
    let all = collect_from(&providers, &config, &credentials, &runner, now()).unwrap();
    assert_eq!(
        ids(&all),
        ["first.done", "slow.done", "late.done", "later.done"]
    );
}

/// A counter's reading, and what its run waits for once it has read it.
struct Reading {
    value: f64,
    read: Option<std::sync::mpsc::Sender<()>>,
    until: Option<Mutex<std::sync::mpsc::Receiver<()>>>,
}

impl Provider for Reading {
    fn name(&self) -> &'static str {
        "reading"
    }

    fn collect(&self, _: &Context<'_>) -> Collected {
        if let Some(read) = &self.read {
            read.send(()).unwrap();
        }
        if let Some(until) = &self.until {
            until.lock().unwrap().recv().unwrap();
        }
        let mut report = Report::default();
        report.counters.insert("delivered".to_owned(), self.value);
        Ok(report)
    }
}

/// Two runs at once, such as one by hand beside the timer's, would both
/// count: the one that read the counter first and writes last leaves its
/// older reading behind, and the next run counts the events between the
/// two readings a second time.
#[test]
fn a_run_beside_one_under_way_counts_no_event_twice() {
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let credentials = Credentials::new(directory.path().join("credentials"));
    let start = now().as_second();
    let run = |value: f64, at: i64, read, until| {
        let reading = Reading { value, read, until };
        let providers = vec![Box::new(reading) as Box<dyn Provider>];
        let at = Timestamp::from_second(start + at).unwrap();
        collect_from(
            &providers,
            &config,
            &credentials,
            &Canned(String::new()),
            at,
        )
    };
    run(90.0, 0, None, None).unwrap();
    // The timer's run reads 100 and is still under way when one by hand
    // reads 110.
    let (read, has_read) = std::sync::mpsc::channel();
    let (go, until) = std::sync::mpsc::channel();
    let (first, beside) = std::thread::scope(|scope| {
        let first = scope.spawn(|| run(100.0, 60, Some(read), Some(Mutex::new(until))));
        has_read.recv().unwrap();
        let beside = run(110.0, 70, None, None);
        go.send(()).unwrap();
        (first.join().unwrap(), beside)
    });
    first.unwrap();
    run(120.0, 120, None, None).unwrap();
    // The counter rose from 90 to 120: thirty events, each counted once.
    let stored = rusqlite::Connection::open(config.database(Database::Status)).unwrap();
    let counted: f64 = stored
        .query_row(
            "SELECT total(value) FROM samples WHERE name = 'delivered'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(matches!(beside, Err(Error::Busy)), "{beside:?}");
    assert_eq!(counted, 30.0);
}
