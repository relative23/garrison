use garrison_core::observations::{Observation, State};
use serde_json::{Value, json};

use super::*;
use crate::context::Provider;
use crate::testing::{Canned, config, context, table};

fn value_of<'a>(observation: &'a Observation, label: &str) -> &'a Value {
    &observation
        .fields
        .iter()
        .find(|field| field.label == label)
        .unwrap()
        .value
}

#[test]
fn clamav_policy_drift_is_a_finding() {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name).display().to_string();
    std::fs::write(
        path("milter.conf"),
        "OnInfected Accept\nOnFail Defer\nMaxFileSize 25M\n",
    )
    .unwrap();
    std::fs::write(path("scan.conf"), "StreamMaxLength 25M\nScanArchive yes\n").unwrap();
    std::fs::write(path("daily.cld"), "signatures").unwrap();
    let provider = Clamav::new(&table(&format!(
        "type = \"clamav\"\nmilter_config = \"{}\"\nclamd_config = \"{}\"\ndatabase_directory = \"{}\"",
        path("milter.conf"),
        path("scan.conf"),
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let report = provider.collect(&context(&config, &runner)).unwrap();
    let configuration = &report.observations[0];
    assert_eq!(configuration.state, State::Warning);
    assert!(configuration.findings[0].contains("Accept"));
    assert_eq!(
        value_of(configuration, "Milter file limit"),
        &json!(25 * 1024 * 1024)
    );
    assert_eq!(value_of(configuration, "Archive scanning"), &json!(true));
    assert_eq!(
        value_of(configuration, "Alert for encrypted content"),
        &Value::Null
    );
    let signatures = &report.observations[1];
    assert_eq!(signatures.state, State::Ok);
    assert_eq!(
        signatures.table.as_ref().unwrap().rows[0][0],
        json!("daily.cld")
    );
    assert!(report.gauges.contains_key("signature_age_hours"));
}

#[test]
fn the_signature_age_gauge_is_that_of_the_newest_daily_database() {
    use std::time::{Duration, SystemTime};
    // An old full database beside the incremental one that updates keep
    // current: the card judges the newer, and so must the dashboard.
    let directory = tempfile::tempdir().unwrap();
    let provider = Clamav::new(&table(&format!(
        "type = \"clamav\"\nmilter_config = \"{0}/milter.conf\"\nclamd_config = \"{0}/scan.conf\"\ndatabase_directory = \"{0}\"",
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = context(&config, &runner);
    let checked = SystemTime::UNIX_EPOCH
        + Duration::from_secs(u64::try_from(context.now.as_second()).unwrap());
    for (name, hours) in [("daily.cvd", 100), ("daily.cld", 2)] {
        let path = directory.path().join(name);
        std::fs::write(&path, "signatures").unwrap();
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(checked - Duration::from_secs(hours * 3600))
            .unwrap();
    }
    let report = provider.collect(&context).unwrap();
    assert_eq!(report.observations[1].state, State::Ok);
    let age = report.gauges["signature_age_hours"];
    assert!((age - 2.0).abs() < 1e-9, "{age}");
}

#[test]
fn signatures_that_were_not_updated_for_two_days_are_a_warning() {
    use std::time::{Duration, SystemTime};
    let directory = tempfile::tempdir().unwrap();
    let daily = directory.path().join("daily.cld");
    std::fs::write(&daily, "signatures").unwrap();
    std::fs::write(directory.path().join("main.cvd"), "signatures").unwrap();
    let provider = Clamav::new(&table(&format!(
        "type = \"clamav\"\nmilter_config = \"{0}/milter.conf\"\nclamd_config = \"{0}/scan.conf\"\ndatabase_directory = \"{0}\"",
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = context(&config, &runner);
    let checked = SystemTime::UNIX_EPOCH
        + Duration::from_secs(u64::try_from(context.now.as_second()).unwrap());
    let aged = |hours: u64| {
        // The main database is years old on every host; only the daily one
        // says whether updates arrive.
        for (path, age) in [(&daily, hours), (&directory.path().join("main.cvd"), 9000)] {
            let file = std::fs::File::options().write(true).open(path).unwrap();
            file.set_modified(checked - Duration::from_secs(age * 3600))
                .unwrap();
        }
        provider.collect(&context).unwrap().observations.remove(1)
    };
    let fresh = aged(47);
    assert_eq!((fresh.state, fresh.findings.len()), (State::Ok, 0));
    let old = aged(49);
    assert_eq!(old.state, State::Warning);
    assert_eq!(
        old.findings,
        [
            "daily.cld was last updated 49 hours ago; ClamAV's signatures change every day, so \
          the updates do not arrive."
        ]
    );
    // Without the daily database nothing says how current the scanner is.
    std::fs::remove_file(&daily).unwrap();
    let without = provider.collect(&context).unwrap().observations.remove(1);
    assert_eq!(without.state, State::Unknown);
    assert_eq!(
        without.findings,
        [
            "No daily signature database (daily.cld or daily.cvd) is among the files; how \
          current the signatures are is not known."
        ]
    );
}

/// The antivirus configuration card over a milter file of `text` and a
/// scanner file of `scan`, with `options` for the check.
fn configuration(text: &str, scan: &str, options: &str) -> (Observation, String) {
    let directory = tempfile::tempdir().unwrap();
    let (milter, scanner) = (
        directory.path().join("milter.conf"),
        directory.path().join("scan.conf"),
    );
    std::fs::write(&milter, text).unwrap();
    std::fs::write(&scanner, scan).unwrap();
    let provider = Clamav::new(&table(&format!(
        "type = \"clamav\"\nmilter_config = \"{}\"\nclamd_config = \"{}\"\ndatabase_directory = \"{}\"\n{options}",
        milter.display(),
        scanner.display(),
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let card = provider
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0);
    (card, milter.display().to_string())
}

/// A file for clamav-milter, the check's options, and what the card must
/// make of them: its state, the two actions it shows and its findings, in
/// which `{file}` stands for the file's path.
struct Case {
    text: &'static str,
    options: &'static str,
    state: State,
    malware: Option<&'static str>,
    failure: Option<&'static str>,
    findings: &'static [&'static str],
}

/// What clamav-milter 1.4 does with each file, as measured: a directive the
/// file does not set has the default, Quarantine for an infected message and
/// Defer for a failure; a value counts in any case; of two lines the first
/// counts; a value outside the actions keeps it from starting.
const POLICIES: [Case; 8] = [
    Case {
        text: "",
        options: "",
        state: State::Warning,
        malware: Some("Quarantine"),
        failure: Some("Defer"),
        findings: &[
            "Detected malware is handled with Quarantine, not Reject: {file} does not set \
                     OnInfected, and Quarantine is clamav-milter's default.",
        ],
    },
    Case {
        text: "",
        options: "expect_on_infected = \"Quarantine\"",
        state: State::Ok,
        malware: Some("Quarantine"),
        failure: Some("Defer"),
        findings: &[],
    },
    Case {
        text: "OnInfected reject\n",
        options: "",
        state: State::Ok,
        malware: Some("Reject"),
        failure: Some("Defer"),
        findings: &[],
    },
    Case {
        text: "OnInfected accept\nOnFail DEFER\n",
        options: "",
        state: State::Warning,
        malware: Some("Accept"),
        failure: Some("Defer"),
        findings: &["Detected malware is handled with Accept, not Reject."],
    },
    Case {
        text: "OnInfected Quarantine\nOnInfected Reject\n",
        options: "",
        state: State::Warning,
        malware: Some("Quarantine"),
        failure: Some("Defer"),
        findings: &[
            "Detected malware is handled with Quarantine, not Reject.",
            "OnInfected is set 2 times in {file}; clamav-milter takes the first, Quarantine.",
        ],
    },
    Case {
        text: "OnInfected Reject\nOnInfected Reject\n",
        options: "",
        state: State::Ok,
        malware: Some("Reject"),
        failure: Some("Defer"),
        findings: &["OnInfected is set 2 times in {file}; clamav-milter takes the first, Reject."],
    },
    Case {
        text: "OnInfected Drop\n",
        options: "",
        state: State::Warning,
        malware: None,
        failure: Some("Defer"),
        findings: &[
            "OnInfected \"Drop\" is none of the actions clamav-milter takes there (Accept, \
                     Reject, Defer, Blackhole, Quarantine), so it does not start with {file}.",
        ],
    },
    Case {
        text: "OnInfected Reject\nOnFail Quarantine\n",
        options: "",
        state: State::Warning,
        malware: Some("Reject"),
        failure: None,
        findings: &[
            "OnFail \"Quarantine\" is none of the actions clamav-milter takes there (Accept, \
                     Reject, Defer), so it does not start with {file}.",
        ],
    },
];

/// A case as the card came out, or as it must.
type Seen = (
    &'static str,
    &'static str,
    State,
    Option<String>,
    Option<String>,
    Vec<String>,
);

#[test]
fn the_milter_policy_is_judged_as_clamav_milter_takes_its_file() {
    let mut found: Vec<Seen> = Vec::new();
    let mut expected: Vec<Seen> = Vec::new();
    for case in &POLICIES {
        let (card, file) = configuration(case.text, "StreamMaxLength 25M\n", case.options);
        let action = |label: &str| value_of(&card, label).as_str().map(str::to_owned);
        found.push((
            case.text,
            case.options,
            card.state,
            action("Detected malware"),
            action("Scanner failure"),
            card.findings.clone(),
        ));
        expected.push((
            case.text,
            case.options,
            case.state,
            case.malware.map(str::to_owned),
            case.failure.map(str::to_owned),
            case.findings
                .iter()
                .map(|finding| finding.replace("{file}", &file))
                .collect(),
        ));
    }
    assert_eq!(found, expected);
}

#[test]
fn the_scanner_files_are_read_as_clamav_reads_them() {
    // Of two lines that set a limit the first counts; every scanner socket
    // counts, as clamav-milter takes turns with them.
    let (card, _) = configuration(
        "OnInfected Reject\nClamdSocket unix:/run/a.sock\nClamdSocket tcp:192.0.2.1:3310\n",
        "StreamMaxLength 10M\nStreamMaxLength 20M\nAlertEncrypted yes\nAlertEncrypted no\n",
        "",
    );
    assert_eq!(card.state, State::Ok, "{:?}", card.findings);
    assert_eq!(
        value_of(&card, "Scanner socket"),
        &json!("unix:/run/a.sock, tcp:192.0.2.1:3310")
    );
    assert_eq!(value_of(&card, "Scanner stream limit"), &json!(10 << 20));
    assert_eq!(value_of(&card, "Alert for encrypted content"), &json!(true));
}

#[test]
fn a_milter_file_that_cannot_be_read_is_named_with_why() {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name);
    std::fs::write(path("large.conf"), "#".repeat(64 * 1024 + 1)).unwrap();
    std::fs::write(path("quote.conf"), "OnInfected Reject\nRejectMsg 'open\n").unwrap();
    std::fs::write(path("scan.conf"), "StreamMaxLength 25M\n").unwrap();
    for (name, why) in [
        ("missing.conf", "No such file or directory (os error 2)"),
        ("large.conf", "it is larger than 64 KiB"),
        (
            "quote.conf",
            "line 2 opens a quote it does not close, or ends in a backslash",
        ),
    ] {
        let provider = Clamav::new(&table(&format!(
            "type = \"clamav\"\nmilter_config = \"{}\"\nclamd_config = \"{}\"\ndatabase_directory = \"{}\"",
            path(name).display(),
            path("scan.conf").display(),
            directory.path().display()
        )))
        .unwrap();
        let config = config(directory.path());
        let runner = Canned(String::new());
        let card = provider
            .collect(&context(&config, &runner))
            .unwrap()
            .observations
            .remove(0);
        assert_eq!(
            (card.state, card.findings),
            (
                State::Unknown,
                vec![format!(
                    "{} could not be read: {why}.",
                    path(name).display()
                )]
            ),
            "{name}"
        );
    }
}

#[test]
fn the_expected_actions_are_ones_clamav_milter_takes() {
    let clamav = |options: &str| Clamav::new(&table(&format!("type = \"clamav\"\n{options}")));
    assert!(clamav("expect_on_infected = \"quarantine\"\nexpect_on_fail = \"accept\"").is_ok());
    for (wrong, words) in [
        (
            "expect_on_infected = \"Quarantine2\"",
            "providers[clamav].expect_on_infected must be one of Accept, Reject, Defer, \
             Blackhole, Quarantine",
        ),
        (
            "expect_on_fail = \"Quarantine\"",
            "providers[clamav].expect_on_fail must be one of Accept, Reject, Defer",
        ),
    ] {
        assert_eq!(clamav(wrong).unwrap_err().0, words, "{wrong}");
    }
}

#[test]
fn the_refresh_log_keeps_only_the_files_the_card_lists() {
    // Whoever writes Fangfrisch's database can fill its log with names: only
    // the listed files' rows are kept, each with its first time.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fangfrisch.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE refreshlog(path TEXT, updated TEXT); BEGIN;")
        .unwrap();
    let row = |name: &str, updated: &str| {
        let path = format!("/var/lib/clamav/{name}");
        db.execute(
            "INSERT INTO refreshlog VALUES(?, ?)",
            [path.as_str(), updated],
        )
        .unwrap();
    };
    for index in 0..5_000 {
        row(&format!("other-{index}.ndb"), "2026-10-29 06:00:00");
    }
    row("junk.ndb", "2026-10-29 05:00:00");
    row("junk.ndb", "2026-10-29 07:00:00");
    row("phish.ndb", "2026-10-28 06:00:00");
    db.execute_batch("COMMIT").unwrap();
    let listed = ["junk.ndb", "phish.ndb", "daily.cld"].map(str::to_owned);
    let log = clamav::refresh_log(&path, &listed).unwrap();
    assert_eq!(
        log,
        std::collections::BTreeMap::from([
            (
                "junk.ndb".to_owned(),
                "2026-10-29T05:00:00+00:00".to_owned()
            ),
            (
                "phish.ndb".to_owned(),
                "2026-10-28T06:00:00+00:00".to_owned()
            ),
        ]),
        "{} names kept",
        log.len()
    );
}
