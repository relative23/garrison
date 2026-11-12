use serde_json::json;

use super::*;
use crate::testing::{Canned, config, context, table};

fn provider(text: &str) -> Receipt {
    Receipt::new(&table(text)).unwrap()
}

/// A receipt only this user can change, whatever the umask.
fn write(path: &std::path::Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn age_result_and_selected_fields() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("restore.json");
    let document = json!({
        "date": "2026-10-28T04:00:00+00:00",
        "result": "failed",
        "secret": "never shown",
        "accounts": 3,
    });
    write(&path, &document.to_string());
    let receipt = provider(&format!(
        r#"type = "receipt"
id = "restore"
title = "Restore"
path = "{}"
modules = ["backups"]
max_age_hours = 30
ok_when = {{ key = "result", equals = ["passed"] }}
fields = [{{ key = "accounts", label = "Accounts", format = "number" }}]"#,
        path.display()
    ));
    let config = config(directory.path());
    let runner = Canned(String::new());
    let report = receipt.collect(&context(&config, &runner)).unwrap();
    let observation = &report.observations[0];
    assert_eq!(observation.state, State::Failed);
    assert_eq!(observation.findings.len(), 2);
    let labels: Vec<&str> = observation
        .fields
        .iter()
        .map(|field| field.label.as_str())
        .collect();
    assert_eq!(labels, ["Reported at", "Accounts"]);
    assert!(
        !serde_json::to_string(observation)
            .unwrap()
            .contains("never shown")
    );
    assert_eq!(report.gauges["receipt_age_hours.restore"], 32.0);
}

#[test]
fn list_receipts_use_the_newest_row() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("tests.json");
    let document = json!([
        {"test": "EICAR SMTP 25", "ok": true, "date": "2026-10-28T10:00:00+00:00"},
        {"test": "EICAR JMAP", "ok": false, "date": "2026-10-28T13:00:00+02:00"},
    ]);
    write(&path, &document.to_string());
    let receipt = provider(&format!(
        r#"type = "receipt"
id = "mail-tests"
title = "Tests"
path = "{}"
modules = ["antivirus"]
rows = []
row_date = "date"
ok_rows = {{ key = "ok", equals = [true] }}
columns = [{{ key = "test", label = "Test" }}]"#,
        path.display()
    ));
    let config = config(directory.path());
    let runner = Canned(String::new());
    let observation = receipt
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(observation.state, State::Failed);
    // The offset the job wrote is kept.
    assert_eq!(
        observation.fields[0].value,
        json!("2026-10-28T13:00:00+02:00")
    );
    assert_eq!(observation.table.unwrap().rows.len(), 2);
}

#[test]
fn a_missing_receipt_is_unknown_not_failed() {
    let directory = tempfile::tempdir().unwrap();
    let receipt = provider(&format!(
        "type = \"receipt\"\nid = \"x\"\ntitle = \"X\"\npath = \"{}\"\nmodules = [\"backups\"]",
        directory.path().join("none.json").display()
    ));
    let config = config(directory.path());
    let runner = Canned(String::new());
    let observation = receipt
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(observation.state, State::Unknown);
    assert_eq!(observation.findings, ["No readable receipt."]);
}

#[test]
fn dates_accept_plain_dates_but_not_naive_timestamps() {
    assert!(date(&json!("2026-10-28")).is_some());
    assert!(date(&json!("2026-10-28T10:00:00Z")).is_some());
    assert!(date(&json!("2026-10-28T10:00:00")).is_none());
    assert!(date(&json!(20_261_028)).is_none());
}

#[test]
fn lookups_follow_keys_and_summarize_lists() {
    let document = json!({"a": {"b": [1, 2, 3], "c": "x".repeat(400), "d": {"e": 1}}});
    let key = |parts: &[&str]| parts.iter().map(ToString::to_string).collect::<Vec<_>>();
    assert_eq!(lookup(&document, &key(&["a", "b"])), json!(3));
    assert_eq!(
        lookup(&document, &key(&["a", "c"])).as_str().unwrap().len(),
        300
    );
    assert_eq!(lookup(&document, &key(&["a", "d"])), Value::Null);
    assert_eq!(
        lookup(&document, &key(&["a", "missing", "deeper"])),
        Value::Null
    );
}

#[test]
fn settings_are_checked_with_precise_messages() {
    let error = |text: &str| Receipt::new(&table(text)).unwrap_err().0;
    let base = "type = \"receipt\"\ntitle = \"T\"\npath = \"/x.json\"\nmodules = [\"backups\"]\n";
    assert_eq!(
        error(&format!("{base}id = \"Bad\"")),
        "providers[receipt].id must be a lowercase identifier"
    );
    assert_eq!(
        error(&format!("{base}id = \"a\"\ndate = 5")),
        "receipt.date must be a key or a list of keys"
    );
    assert_eq!(
        error(&format!("{base}id = \"a\"\nok_when = {{ key = \"r\" }}")),
        "providers[receipt].ok_when needs key and equals"
    );
    assert_eq!(
        error(&format!(
            "{base}id = \"a\"\nfields = [{{ key = \"k\", label = \"L\", format = \"odd\" }}]"
        )),
        "providers[receipt].fields entries need key, label, format"
    );
    assert_eq!(
        error(&format!("{base}id = \"a\"\nscope = 1")),
        "providers[receipt].scope must be text"
    );
}

/// What a receipt provider observes in `document`, with `settings` added.
fn observe(document: &Value, settings: &str) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("receipt.json");
    write(&path, &document.to_string());
    let receipt = provider(&format!(
        "type = \"receipt\"\nid = \"r\"\ntitle = \"R\"\npath = \"{}\"\nmodules = [\"backups\"]\n{settings}",
        path.display()
    ));
    let (config, runner) = (config(directory.path()), Canned(String::new()));
    receipt
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0)
}

#[test]
fn a_receipt_is_old_only_after_its_maximum_age() {
    // The tests collect at 2026-10-29T12:00:00Z; 30 hours earlier is 06:00.
    let exactly = observe(
        &json!({"date": "2026-10-28T06:00:00Z"}),
        "max_age_hours = 30",
    );
    assert_eq!((exactly.state, exactly.findings.len()), (State::Ok, 0));
    let older = observe(
        &json!({"date": "2026-10-28T05:59:59Z"}),
        "max_age_hours = 30",
    );
    assert_eq!(older.state, State::Warning);
    // Large receipts are read too; 1 MiB is the limit.
    let large = observe(
        &json!({"date": "2026-10-29T11:00:00Z", "log": "x".repeat(512 * 1024)}),
        "",
    );
    assert_eq!(large.state, State::Ok);
}

#[test]
fn rows_pass_when_every_row_passes_and_the_first_newest_date_wins() {
    let rows = json!([
        {"ok": true, "date": "2026-10-28T10:00:00+00:00"},
        {"ok": true, "date": "2026-10-28T12:00:00+02:00"},
    ]);
    let observation = observe(
        &rows,
        "rows = []\nrow_date = \"date\"\nok_rows = { key = \"ok\", equals = [true] }",
    );
    assert_eq!(observation.state, State::Ok);
    // Both rows name the same instant; the first one is reported as written.
    assert_eq!(
        observation.fields[0].value,
        json!("2026-10-28T10:00:00+00:00")
    );
}

#[test]
fn keys_have_one_to_six_parts_of_safe_characters() {
    let text = |value: &str| toml::Value::String(value.into());
    let list = |count: usize| {
        toml::Value::Array((0..count).map(|index| text(&format!("k{index}"))).collect())
    };
    assert!(key(Some(&text(&"k".repeat(120))), "k").is_ok());
    assert!(key(Some(&list(6)), "k").is_ok());
    for invalid in [
        text(""),
        text(&"k".repeat(121)),
        text("a b"),
        list(0),
        list(7),
        toml::Value::Array(vec![1.into()]),
    ] {
        assert!(key(Some(&invalid), "k").is_err(), "{invalid:?}");
    }
}

#[test]
fn every_documented_format_is_accepted() {
    let names = [
        "text", "number", "bytes", "datetime", "duration", "boolean", "url",
    ];
    let formats = names.map(format_of);
    assert_eq!(
        formats,
        [
            Some(Format::Text),
            Some(Format::Number),
            Some(Format::Bytes),
            Some(Format::Datetime),
            Some(Format::Duration),
            Some(Format::Boolean),
            Some(Format::Url),
        ]
    );
    assert_eq!(format_of("date"), None);
}

#[test]
fn a_condition_has_exactly_a_key_and_its_values() {
    let error = |condition: &str| {
        let text = format!(
            "type = \"receipt\"\nid = \"a\"\ntitle = \"T\"\npath = \"/x.json\"\nmodules = [\"backups\"]\nok_when = {condition}"
        );
        Receipt::new(&table(&text)).unwrap_err().0
    };
    for condition in [
        "{ key = \"r\", equals = [\"x\"], extra = 1 }",
        "{ equals = [\"x\"], other = 1 }",
    ] {
        assert_eq!(
            error(condition),
            "providers[receipt].ok_when needs key and equals",
            "{condition}"
        );
    }
}

#[test]
fn a_receipt_that_others_can_change_is_unknown() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("backup.json");
    write(
        &path,
        r#"{"date": "2026-10-29T12:00:00+00:00", "result": "passed"}"#,
    );
    let receipt = provider(&format!(
        r#"type = "receipt"
id = "backup"
title = "Backup"
path = "{}"
modules = ["backups"]
ok_when = {{ key = "result", equals = ["passed"] }}"#,
        path.display()
    ));
    let config = config(directory.path());
    let runner = Canned(String::new());
    let collect = || receipt.collect(&context(&config, &runner)).unwrap();
    assert_eq!(collect().observations[0].state, State::Ok);
    // Group or other write access: anybody in that group could forge "passed".
    for mode in [0o664, 0o646] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let report = collect();
        let observation = &report.observations[0];
        assert_eq!(observation.state, State::Unknown, "{mode:o}");
        assert!(
            observation.findings[0].contains("its result is not trusted"),
            "{:?}",
            observation.findings
        );
        assert!(report.gauges.is_empty());
    }
}
