//! Each check's `ids()` against the ids its `collect` reports, for every
//! type in the registry. The configuration check refuses two checks that
//! name one id, since a snapshot holds an id once: an id a check reports
//! but does not name lets such a pair through, and one it names but never
//! reports refuses a pair that would never meet.

use std::collections::BTreeSet;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};

use garrison_core::config::{Config, Database};
use garrison_core::recording::{self, GAPS_TABLE, HEARTBEAT_AT, METADATA_TABLE};
use garrison_testing::NATIVE_KEY;
use garrison_testing::http::{answer, json as answer_json, serve};
use serde_json::json;

use super::*;
use crate::context::Context;
use crate::testing::{Canned, config, now, table};

/// A type with a typical configuration, as the checks' own fixtures write
/// it: the golden test's, `tests/observation_ids.rs`' and the checks' tests'.
struct Case {
    kind: &'static str,
    options: String,
    /// What Stalwart answers the collector's key with where it is within
    /// reach, one answer for each request.
    stalwart: Vec<String>,
    /// The ids it reports that depend on what it finds, not on its
    /// configuration: they cannot be named beforehand, as the trait says.
    found: &'static [&'static str],
}

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/golden")
}

/// A resolver's address where nothing listens: a question is refused at
/// once.
fn no_resolver() -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().to_string()
}

fn case(kind: &'static str, options: &str) -> Case {
    Case {
        kind,
        options: options.to_owned(),
        stalwart: Vec::new(),
        found: &[],
    }
}

/// Every type, in the registry's order.
fn cases(work: &Path) -> Vec<Case> {
    let fixtures = golden();
    let jmap = std::fs::read_to_string(fixtures.join("jmap.json")).unwrap();
    let (work, golden) = (work.display(), fixtures.display());
    let domains = answer_json(&json!({"methodResponses": [["x:Domain/get", {"list": [
        {"id": "b", "name": "example.test", "dnsZoneFile": "example.test. IN MX 10 mail.example.test.\n"}
    ]}, "0"]]}));
    vec![
        case(
            "backup-check",
            &format!("tool = \"restic\"\npath = \"{work}/restic.json\""),
        ),
        case(
            "bulwark",
            &format!("admin_directory = \"{golden}/bulwark\"\nplugins = [\"spam-report\"]"),
        ),
        case(
            "clamav",
            &format!(
                "milter_config = \"{golden}/clamav/milter.conf\"\n\
                 clamd_config = \"{golden}/clamav/scan.conf\"\n\
                 database_directory = \"{golden}/clamav\""
            ),
        ),
        Case {
            stalwart: vec![domains],
            // One card for each of Stalwart's domains.
            found: &["dns.example.test"],
            ..case("dns", &format!("resolver = \"{}\"", no_resolver()))
        },
        case(
            "host",
            &format!("proc = \"{golden}/proc\"\ndisk_path = \"{golden}\""),
        ),
        case(
            "host-care",
            &format!("root = \"{work}/root\"\ndisk_path = \"{work}\""),
        ),
        case(
            "http",
            "id = \"health\"\ntitle = \"Health endpoint\"\nurl = \"http://127.0.0.1:9/health\"",
        ),
        case("mail-flow", ""),
        case("mail-test", "recipient = \"test@example.test\"\nport = 9"),
        case("prometheus", ""),
        case(
            "receipt",
            &format!(
                "id = \"restore\"\ntitle = \"Restore test\"\npath = \"{work}/restore.json\"\n\
                 modules = [\"backups\"]"
            ),
        ),
        case("releases", "api = \"http://127.0.0.1:9/\""),
        case(
            "reputation",
            &format!(
                "resolver = \"{}\"\nhosts = [\"mail.example.test\"]",
                no_resolver()
            ),
        ),
        case("senders", ""),
        case("sign-in", ""),
        Case {
            stalwart: vec![answer(200, &jmap)],
            ..case(
                "stalwart",
                "milter_host = \"127.0.0.1\"\nmilter_port = 7357\nmax_accounts = 3",
            )
        },
        case(
            "systemd",
            "units = [{ unit = \"stalwart.service\", label = \"Mail server\", modules = [\"services\"] }]",
        ),
        case("tls", "endpoints = [{ host = \"localhost\", port = 9 }]"),
        case(
            "version-command",
            "component = \"ClamAV\"\ncommand = [\"/usr/bin/clamdscan\", \"--version\"]",
        ),
    ]
}

/// A week in the event history with what the mail flow counts: mail filed
/// as ham, a sender that fails SPF, a milter's verdict.
fn history(config: &Config) {
    let path = config.database(Database::Events);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(&format!(
        "CREATE TABLE events(seq INTEGER PRIMARY KEY, created_at INTEGER, type TEXT, \
         span_id TEXT, fields TEXT); {GAPS_TABLE}; {METADATA_TABLE};"
    ))
    .unwrap();
    let now = now().as_second();
    // A receiver that reports: the history is current.
    recording::set(&db, HEARTBEAT_AT, now).unwrap();
    for (kind, fields) in [
        ("message-ingest.ham", json!({"accountId": 1})),
        (
            "smtp.spf-from-fail",
            json!({"from": "x@forged.example", "result": "spf.fail"}),
        ),
        ("milter.action-accept", json!({})),
    ] {
        db.execute(
            "INSERT INTO events(created_at, type, fields) VALUES(?, ?, ?)",
            (now - 60, kind, fields.to_string()),
        )
        .unwrap();
    }
}

/// The ids `provider` reports with nothing within reach, and with Stalwart
/// giving `case`'s answers to the collector's key and a week of history.
fn reported(provider: &dyn Provider, case: &Case) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for reached in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        // The sign-in page is asked for under the issuer: no name to look up.
        config.deployment.issuer = "https://localhost:9".to_owned();
        let stalwart = (reached && !case.stalwart.is_empty()).then(|| serve(case.stalwart.clone()));
        if let Some(stalwart) = &stalwart {
            config.deployment.stalwart_url.clone_from(&stalwart.url);
        }
        if reached {
            history(&config);
        }
        let runner = Canned(String::new());
        let context = Context {
            native_key: reached.then(|| NATIVE_KEY.to_owned()),
            ..crate::testing::context(&config, &runner)
        };
        let report = provider.collect(&context).unwrap();
        ids.extend(
            report
                .observations
                .into_iter()
                .map(|observation| observation.id),
        );
        if let Some(stalwart) = stalwart {
            stalwart.requests();
        }
    }
    ids
}

/// Each type names every id it reports that its configuration decides,
/// and no other; what it finds, such as Stalwart's domains, it cannot name.
#[test]
fn every_check_names_the_ids_it_reports() {
    let work = tempfile::tempdir().unwrap();
    let cases = cases(work.path());
    let kinds: Vec<&str> = cases.iter().map(|case| case.kind).collect();
    let registered: Vec<&str> = TYPES.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, registered, "a case for every type");
    let mut wrong = Vec::new();
    for case in &cases {
        let raw = table(&format!("type = \"{}\"\n{}", case.kind, case.options));
        let provider = build(&[raw]).unwrap().remove(0);
        let reported = reported(provider.as_ref(), case);
        let found: BTreeSet<String> = case.found.iter().map(ToString::to_string).collect();
        assert!(reported.is_superset(&found), "{}: {reported:?}", case.kind);
        let decided: BTreeSet<String> = reported.difference(&found).cloned().collect();
        let named: BTreeSet<String> = provider.ids().into_iter().collect();
        if decided != named {
            wrong.push(format!(
                "{} reports {decided:?}, names {named:?}",
                case.kind
            ));
        }
    }
    assert_eq!(wrong, Vec::<String>::new());
}
