//! Observation ids are an interface: the notifications remember them, the
//! interface shows some of them by id, and operators' scripts read them.
//! `docs/operator/observations.md` lists every id; these tests hold the ids
//! the checks report to that list, in both directions, and the renamed ids
//! there to `RENAMED` in the code.

// Helpers fail the test by panicking, like the test itself.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use garrison_collector::command::{Output, Runner};
use garrison_collector::{build, collect_from};
use garrison_core::config::{self, Database};
use garrison_core::observations::RENAMED;
use garrison_core::time;
use serde_json::Value;

const DOCUMENT: &str = include_str!("../../../docs/operator/observations.md");
const NOW: &str = "2026-10-29T12:00:00Z";
/// Listed ids this test cannot make a check report: the spam by domain needs
/// Stalwart's accounts, which nothing here serves.
const NEEDS_DATA: [&str; 1] = ["flow.spam-domains"];

/// No program can be run.
struct NoPrograms;

impl Runner for NoPrograms {
    fn run(&self, _: &[&str]) -> io::Result<Output> {
        Err(io::Error::from(io::ErrorKind::NotFound))
    }
}

/// Every check type, each pointed at something that is not there: port 9 for
/// network endpoints, missing files and programs for the rest.
fn providers(work: &Path) -> String {
    let work = work.display();
    format!(
        r#"
[[providers]]
type = "host-care"
root = "{work}/root"
disk_path = "{work}"

[[providers]]
type = "systemd"
units = [{{ unit = "example.service", label = "Example", modules = ["services"] }}]

[[providers]]
type = "tls"
endpoints = [{{ host = "localhost", port = 9 }}]

[[providers]]
type = "mail-flow"

[[providers]]
type = "stalwart"

[[providers]]
type = "prometheus"

[[providers]]
type = "dns"
resolver = "127.0.0.1"

[[providers]]
type = "clamav"
milter_config = "{work}/clamav-milter.conf"
clamd_config = "{work}/clamd.conf"

[[providers]]
type = "backup-check"
tool = "restic"

[[providers]]
type = "bulwark"
admin_directory = "{work}/bulwark"

[[providers]]
type = "http"
id = "web"
title = "Web"
url = "http://127.0.0.1:9/"

[[providers]]
type = "version-command"
component = "example"
command = ["/usr/bin/false"]
pattern = "([0-9.]+)"

[[providers]]
type = "reputation"
resolver = "127.0.0.1"

[[providers]]
type = "senders"

[[providers]]
type = "releases"
api = "http://127.0.0.1:9/"

[[providers]]
type = "mail-test"
recipient = "test@example.test"
port = 9

[[providers]]
type = "receipt"
id = "job"
title = "Job"
path = "{work}/receipt.json"
modules = ["backups"]

[notifications]
ntfy_url = "https://ntfy.example.test/topic"
"#
    )
}

/// A sender domain that fails SPF and DMARC and a milter verdict, for the
/// mail flow: it leaves out what has no events.
fn events(path: &Path, now: i64) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch(
        "CREATE TABLE events(seq INTEGER PRIMARY KEY, created_at INTEGER, type TEXT, span_id TEXT, fields TEXT)",
    )
    .unwrap();
    for (kind, fields) in [
        (
            "smtp.spf-from-fail",
            r#"{"from": "x@forged.example", "result": "spf.fail"}"#,
        ),
        (
            "smtp.dmarc-fail",
            r#"{"domain": "forged.example", "result": "dmarc.fail", "policy": "reject"}"#,
        ),
        ("milter.action-accept", "{}"),
    ] {
        db.execute(
            "INSERT INTO events(created_at, type, fields) VALUES(?, ?, ?)",
            (now - 60, kind, fields),
        )
        .unwrap();
    }
}

/// The ids every check type reports with next to nothing within reach.
fn reported() -> BTreeSet<String> {
    let directory = tempfile::tempdir().unwrap();
    let mut text = garrison_testing::config_text(directory.path(), "http://127.0.0.1:9");
    text.push_str(&providers(directory.path()));
    let config = config::parse(&text.parse().unwrap()).unwrap();
    let credentials = garrison_testing::credentials(&config);
    std::fs::create_dir_all(directory.path().join("collector")).unwrap();
    let now = time::parse(NOW).unwrap();
    events(&config.database(Database::Events), now.as_second());
    let providers = build(&config.collector.providers).unwrap();
    let snapshot = collect_from(&providers, &config, &credentials, &NoPrograms, now).unwrap();
    snapshot
        .observations
        .into_iter()
        .map(|observation| observation.id)
        .collect()
}

/// The ids the golden test's checks report with everything they read at hand.
fn golden() -> BTreeSet<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/golden/golden.json");
    let golden: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    golden["providers"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|provider| provider["observations"].as_array().unwrap())
        .map(|observation| observation["id"].as_str().unwrap().to_owned())
        .collect()
}

/// The first one or two code spans of each table row of a part of the list.
fn rows(part: &str, cells: usize) -> Vec<Vec<String>> {
    part.lines()
        .filter(|line| line.starts_with("| `"))
        .map(|line| {
            line.split('`')
                .skip(1)
                .step_by(2)
                .take(cells)
                .map(ToOwned::to_owned)
                .collect()
        })
        .collect()
}

fn listed() -> Vec<String> {
    let (ids, _) = DOCUMENT.split_once("## Renamed").unwrap();
    rows(ids, 1).into_iter().flatten().collect()
}

/// `systemd.<unit>` stands for every id that begins with `systemd.`.
fn matches(entry: &str, id: &str) -> bool {
    match entry.split_once('<') {
        Some((prefix, _)) => id.len() > prefix.len() && id.starts_with(prefix),
        None => entry == id,
    }
}

#[test]
fn every_reported_id_is_listed_and_every_listed_id_reported() {
    let listed = listed();
    let ids: BTreeSet<String> = reported().union(&golden()).cloned().collect();
    let unlisted: Vec<&String> = ids
        .iter()
        .filter(|id| !listed.iter().any(|entry| matches(entry, id)))
        .collect();
    assert!(
        unlisted.is_empty(),
        "Observation ids are an interface: list {unlisted:?} in docs/operator/observations.md; \
         a renamed id goes under Renamed there and into RENAMED (garrison_core::observations)"
    );
    let silent: Vec<&String> = listed
        .iter()
        .filter(|entry| !entry.contains('<') && !NEEDS_DATA.contains(&entry.as_str()))
        .filter(|entry| !ids.contains(*entry))
        .collect();
    assert!(
        silent.is_empty(),
        "listed in docs/operator/observations.md, but no check reports {silent:?}: \
         a renamed id goes under Renamed there and into RENAMED (garrison_core::observations)"
    );
}

#[test]
fn the_renamed_ids_are_those_the_code_renames() {
    let (_, renamed) = DOCUMENT.split_once("## Renamed").unwrap();
    let documented = rows(renamed, 2);
    let code: Vec<Vec<String>> = RENAMED
        .iter()
        .map(|(old, new)| vec![(*old).to_owned(), (*new).to_owned()])
        .collect();
    assert_eq!(documented, code);
    let ids = reported();
    let listed = listed();
    for (old, new) in RENAMED {
        assert!(!ids.contains(*old), "{old} is renamed, but still reported");
        assert!(
            listed.iter().any(|entry| entry == new),
            "{new} is not listed"
        );
    }
}
