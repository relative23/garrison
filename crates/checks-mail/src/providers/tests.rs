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
