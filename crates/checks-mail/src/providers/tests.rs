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
