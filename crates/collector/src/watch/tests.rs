use std::collections::BTreeMap;
use std::path::PathBuf;

use garrison_testing::http::{answer, serve};
use serde_json::Value;

use super::*;
use crate::notify::Address;
use crate::snapshot::{SCHEMA, Snapshot};
use crate::store::StatusStore;
use crate::testing::now;

/// A host whose collector last finished a run `ago` seconds before the
/// tests' clock and left `channel` behind.
struct Host {
    directory: tempfile::TempDir,
}

/// A run that finished `ago` seconds before the tests' clock.
fn run(store: &mut StatusStore, ago: i64) {
    let snapshot = Snapshot {
        schema_version: SCHEMA,
        collected_at: "2026-10-29T12:00:00+00:00".into(),
        observations: Vec::new(),
        provider_errors: Vec::new(),
    };
    store
        .write(
            now().as_second() - ago,
            &snapshot,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
}

impl Host {
    fn new(ago: Option<i64>, channel: Option<&Channels>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let host = Host { directory };
        // The store is closed again before the watch reads: a reader of the
        // rollback journal and a writer do not share the file.
        let mut store = StatusStore::open(&host.database(), 90).unwrap();
        if let Some(ago) = ago {
            run(&mut store, ago);
        }
        remember(&store, channel.unwrap_or(&Channels::default()));
        host
    }

    fn database(&self) -> PathBuf {
        self.directory.path().join("status.sqlite")
    }

    fn marker(&self) -> PathBuf {
        self.directory.path().join("collector-stopped")
    }

    /// A run that finishes now.
    fn runs_again(&self) {
        let mut store = StatusStore::open(&self.database(), 90).unwrap();
        run(&mut store, 0);
    }

    fn look(&self, configured: Result<Option<Channels>, ()>) -> Result<Outcome, String> {
        Watch {
            database: &self.database(),
            marker: &self.marker(),
            configured: configured.map(Option::unwrap_or_default),
            secrets: Secrets {
                ntfy: "token-1".to_owned(),
                ..Secrets::default()
            },
            now: now(),
            roots: Arc::new(RootCertStore::empty()),
        }
        .look()
    }
}

fn channel(server: &str) -> Channels {
    Channels {
        host: "garrison.example.org".to_owned(),
        ntfy: Some(Address {
            url: format!("{server}/mailserver"),
            token: "token-1".to_owned(),
        }),
        ..Channels::default()
    }
}

fn body(request: &str) -> Value {
    serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap()
}

#[test]
fn a_stopped_collector_is_told_once_and_its_return_once() {
    let server = serve(vec![answer(200, "{}"), answer(200, "{}")]);
    let channel = channel(&server.url);
    let host = Host::new(Some(LIMIT + 1), Some(&channel));
    assert_eq!(
        host.look(Ok(Some(channel.clone()))),
        Ok(Outcome::ToldStopped)
    );
    // The next looks say nothing more.
    assert_eq!(host.look(Ok(Some(channel.clone()))), Ok(Outcome::Stopped));
    host.runs_again();
    assert_eq!(
        host.look(Ok(Some(channel.clone()))),
        Ok(Outcome::ToldRunning)
    );
    assert_eq!(host.look(Ok(Some(channel))), Ok(Outcome::Running));
    assert!(!host.marker().exists());

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("Authorization: Bearer token-1\r\n"));
    let stopped = body(&requests[0]);
    assert_eq!(stopped["topic"], "mailserver");
    assert_eq!(
        stopped["title"],
        "Garrison on garrison.example.org: the collector has stopped"
    );
    assert_eq!(stopped["priority"], 4);
    let text = stopped["message"].as_str().unwrap();
    assert!(
        text.starts_with("No collection run has finished since 20"),
        "{text}"
    );
    let running = body(&requests[1]);
    assert_eq!(
        running["title"],
        "Garrison on garrison.example.org: the collector runs again"
    );
    assert_eq!(running["priority"], 3);
}

#[test]
fn a_run_within_the_limit_and_a_host_without_runs_are_left_alone() {
    let host = Host::new(Some(LIMIT), None);
    assert_eq!(host.look(Err(())), Ok(Outcome::Running));
    let fresh = Host::new(None, None);
    assert_eq!(fresh.look(Err(())), Ok(Outcome::NeverRan));
    // Before the first run there is no database either.
    let directory = tempfile::tempdir().unwrap();
    let nothing = Watch {
        database: &directory.path().join("status.sqlite"),
        marker: &directory.path().join("collector-stopped"),
        configured: Err(()),
        secrets: Secrets::default(),
        now: now(),
        roots: Arc::new(RootCertStore::empty()),
    };
    assert_eq!(nothing.look(), Ok(Outcome::NeverRan));
}

#[test]
fn without_a_configuration_that_loads_the_channel_of_the_last_run_is_told() {
    let server = serve(vec![answer(200, "{}")]);
    let host = Host::new(Some(3600), Some(&channel(&server.url)));
    assert_eq!(host.look(Err(())), Ok(Outcome::ToldStopped));
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn the_configuration_counts_where_it_loads() {
    // The last run left a topic, but the configuration names none any more.
    let server = serve(Vec::new());
    let host = Host::new(Some(3600), Some(&channel(&server.url)));
    assert_eq!(host.look(Ok(None)), Ok(Outcome::Stopped));
    assert!(!host.marker().exists());
    assert_eq!(server.requests().len(), 0);
}

#[test]
fn a_message_that_does_not_go_out_is_tried_again() {
    let server = serve(vec![answer(403, "forbidden"), answer(200, "{}")]);
    let channel = channel(&server.url);
    let host = Host::new(Some(3600), Some(&channel));
    assert_eq!(
        host.look(Ok(Some(channel.clone()))),
        Err("ntfy: it answered 403".to_owned())
    );
    assert!(!host.marker().exists());
    assert_eq!(host.look(Ok(Some(channel))), Ok(Outcome::ToldStopped));
    server.requests();
}

#[test]
fn a_run_leaves_the_channel_and_takes_it_back() {
    let host = Host::new(Some(0), None);
    let store = StatusStore::open(&host.database(), 90).unwrap();
    let channel = channel("https://ntfy.example.org");
    remember(&store, &channel);
    drop(store);
    // The address is left, the token is not.
    let left = recorded(&host.database()).unwrap().channels;
    assert_eq!(
        left.ntfy
            .as_ref()
            .map(|ntfy| (ntfy.url.as_str(), ntfy.token.as_str())),
        Some(("https://ntfy.example.org/mailserver", ""))
    );
    assert_eq!(left.host, "garrison.example.org");
    let store = StatusStore::open(&host.database(), 90).unwrap();
    remember(&store, &Channels::default());
    drop(store);
    assert_eq!(
        recorded(&host.database()).unwrap().channels,
        Channels::default()
    );
}
