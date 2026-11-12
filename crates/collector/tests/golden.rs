//! Every provider reports known observations from known sources, and the store
//! keeps the expected rows.
//!
//! `fixtures/golden` holds a configuration with every provider type, the files
//! they read, canned command output and the stub Stalwart's answers;
//! `golden.json` is what the providers make of them. Host values that depend on
//! the machine (architecture, CPU count, disk) are blanked on both sides. A
//! deliberate change of a finding updates `golden.json` in the same commit.

// Helpers fail the test by panicking, like the test itself.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use garrison_collector::command::{Output, Runner};
use garrison_collector::snapshot::{SCHEMA, Snapshot};
use garrison_collector::store::{StatusStore, history};
use garrison_collector::{Context, build};
use garrison_core::config::{self, Database};
use garrison_core::time;
use garrison_testing::http::{answer, serve};
use rusqlite::types::ValueRef;
use serde_json::{Map, Value, json};

const MTIMES: [(&str, u64); 3] = [
    ("daily.cld", 1_793_270_000_123_456_789),
    ("main.cvd", 1_793_100_000_000_000_000),
    ("bytecode.cvd", 1_793_000_000_999_999_999),
];
const HOST_BLANKS: [&str; 5] = [
    "Architecture",
    "CPU cores",
    "Disk total",
    "Disk free",
    "Free inodes",
];

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/golden")
}

struct Commands;

impl Runner for Commands {
    fn run(&self, arguments: &[&str]) -> io::Result<Output> {
        let stdout = if arguments.contains(&"/usr/bin/systemctl") {
            std::fs::read_to_string(fixtures().join("systemctl.txt"))?
        } else {
            "ClamAV 1.4.3/27800/Wed Oct 29 10:00:00 2026\n".to_owned()
        };
        Ok(Output {
            code: Some(0),
            stdout,
        })
    }
}

fn prepare(work: &Path) {
    // A receipt counts only when no one else can change it; a checkout's
    // modes follow the umask, so they are set here.
    for name in ["restore.json", "tests.json", "backup.json"] {
        let path = fixtures().join(name);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    for (name, nanoseconds) in MTIMES {
        let file = std::fs::File::options()
            .write(true)
            .open(fixtures().join("clamav").join(name))
            .unwrap();
        file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_nanos(nanoseconds))
            .unwrap();
    }
    let fangfrisch = rusqlite::Connection::open(work.join("fangfrisch.sqlite")).unwrap();
    fangfrisch
        .execute_batch(
            "CREATE TABLE refreshlog(path TEXT, updated TEXT);
             INSERT INTO refreshlog VALUES('/var/lib/clamav/daily.cld','2026-10-29 06:00:01.123456');
             INSERT INTO refreshlog VALUES('/var/lib/clamav/main.cvd','2026-10-28 06:00:00');",
        )
        .unwrap();
    std::fs::create_dir(work.join("ingest")).unwrap();
    let events = rusqlite::Connection::open(work.join("ingest/events.sqlite")).unwrap();
    events
        .execute_batch(
            r#"CREATE TABLE events(type TEXT, created_at INTEGER, fields TEXT);
               INSERT INTO events VALUES('server.startup',1792000000,'{"version":"1.1.0"}');
               INSERT INTO events VALUES('server.startup',1793000000,'{"version":"1.1.1"}');"#,
        )
        .unwrap();
}

fn normalize(mut provider: Value, replacements: &[(String, &str)]) -> Value {
    if provider["type"] == "host" {
        for observation in provider["observations"].as_array_mut().unwrap() {
            for field in observation["fields"].as_array_mut().unwrap() {
                if HOST_BLANKS.contains(&field["label"].as_str().unwrap()) {
                    field["value"] = Value::Null;
                }
            }
            observation["state"] = Value::Null;
            let findings = observation["findings"].as_array_mut().unwrap();
            findings.retain(|finding| !finding.as_str().unwrap().contains("disk"));
        }
        provider["gauges"]
            .as_object_mut()
            .unwrap()
            .remove("disk_free_gib");
    }
    let mut text = provider.to_string();
    for (value, marker) in replacements {
        text = text.replace(value.as_str(), marker);
    }
    serde_json::from_str(&text).unwrap()
}

fn rows(db: &rusqlite::Connection, table: &str) -> Value {
    let mut statement = db
        .prepare(&format!("SELECT * FROM {table} ORDER BY 1, 2"))
        .unwrap();
    let names: Vec<String> = statement.column_names().map(ToString::to_string).collect();
    let mut cursor = statement.query([]).unwrap();
    let mut result = Vec::new();
    while let Some(row) = cursor.next().unwrap() {
        let mut object = Map::new();
        for (index, name) in names.iter().enumerate() {
            let value = match row.get_ref(index).unwrap() {
                ValueRef::Integer(number) => json!(number),
                ValueRef::Real(number) => json!(number),
                ValueRef::Text(text) => json!(std::str::from_utf8(text).unwrap()),
                other => panic!("unexpected {other:?}"),
            };
            object.insert(name.clone(), value);
        }
        result.push(Value::Object(object));
    }
    Value::Array(result)
}

#[test]
fn every_provider_reports_the_expected_observations() {
    let golden: Value =
        serde_json::from_str(&std::fs::read_to_string(fixtures().join("golden.json")).unwrap())
            .unwrap();
    let jmap = std::fs::read_to_string(fixtures().join("jmap.json")).unwrap();
    let metrics = std::fs::read_to_string(fixtures().join("metrics.txt")).unwrap();
    // In provider order: management API, exporter, health endpoint.
    let server = serve(vec![
        answer(200, &jmap),
        answer(200, &metrics),
        answer(204, ""),
    ]);
    let work = tempfile::tempdir().unwrap();
    prepare(work.path());
    let replacements = [
        (fixtures().display().to_string(), "@FIXTURES@"),
        (work.path().display().to_string(), "@WORK@"),
        (server.url.clone(), "@STALWART@"),
    ];
    let mut text = std::fs::read_to_string(fixtures().join("config.toml")).unwrap();
    for (value, marker) in &replacements {
        text = text.replace(marker, value);
    }
    let config = config::parse(&text.parse().unwrap()).unwrap();
    let context = Context {
        deployment: &config.deployment,
        now: time::parse("2026-10-29T12:00:00Z").unwrap(),
        native_key: Some("native-key-0123456789".into()),
        metrics_credential: Some(("user".into(), "secret".into())),
        events_database: config.database(Database::Events),
        runner: &Commands,
        memory: &garrison_collector::context::Forgetful,
    };
    let providers = build(&config.collector.providers).unwrap();
    let (mut gauges, mut counters) = (BTreeMap::new(), BTreeMap::new());
    for (index, provider) in providers.iter().enumerate() {
        let report = provider.collect(&context).unwrap();
        gauges.extend(report.gauges.clone());
        counters.extend(report.counters.clone());
        let ours = normalize(
            json!({
                "type": config.collector.providers[index]["type"].as_str().unwrap(),
                "observations": report.observations,
                "gauges": report.gauges,
                "counters": report.counters,
            }),
            &replacements,
        );
        assert_eq!(ours, golden["providers"][index], "provider {index}");
    }
    server.requests();

    gauges.remove("disk_free_gib"); // Depends on the machine.
    let path = work.path().join("status.sqlite");
    let mut store = StatusStore::open(&path, 90).unwrap();
    let stamp = context.now.as_second();
    let halved = counters
        .iter()
        .map(|(name, value)| (name.clone(), value / 2.0))
        .collect();
    let snapshot = Snapshot {
        schema_version: SCHEMA,
        collected_at: time::isoformat(context.now),
        observations: Vec::new(),
        provider_errors: Vec::new(),
    };
    store
        .write(stamp - 60, &snapshot, &gauges, &halved)
        .unwrap();
    store.write(stamp, &snapshot, &gauges, &counters).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    for table in ["samples", "counters", "resets"] {
        assert_eq!(rows(&db, table), golden["stored"][table], "{table}");
    }
    assert_eq!(
        json!(history(&db, stamp - 3600, stamp + 60, 12).unwrap()),
        golden["history"]
    );
}
