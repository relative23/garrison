use std::os::unix::fs::PermissionsExt;

use serde_json::{Value, json};

use super::*;
use crate::testing::{Canned, config, now, table};

/// A moment `ago` seconds before the tests' clock, as a report writes it.
fn at(ago: i64) -> String {
    time::isoformat(time::Timestamp::from_second(now().as_second() - ago).unwrap())
}

/// A report whose newest snapshot was made and listed an hour ago.
fn report() -> Value {
    json!({
        "tool": "restic", "repository": "/srv/restic", "problem": null,
        "snapshots": {"at": at(3600), "count": 14, "newest": at(3700), "sizeBytes": 52_428_800},
        "verify": {"at": at(2 * DAY), "ok": true, "detail": "no errors were found"},
        "restore": {"at": at(3 * DAY), "ok": true, "detail": "/var/vmail/a: 12 files, 4096 bytes"},
    })
}

/// The observation for `report` written with `mode`, under `options`.
fn observed(report: Option<&Value>, mode: u32, options: &str) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("restic.json");
    if let Some(report) = report {
        fs::write(&path, report.to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }
    let provider = BackupCheck::new(&table(&format!(
        "type = \"backup-check\"\npath = \"{}\"\n{options}",
        path.display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = crate::testing::context(&config, &runner);
    provider.collect(&context).unwrap().observations.remove(0)
}

fn field<'a>(observation: &'a Observation, label: &str) -> &'a Value {
    &observation
        .fields
        .iter()
        .find(|field| field.label == label)
        .unwrap()
        .value
}

#[test]
fn a_fresh_snapshot_with_passed_checks_is_in_order() {
    let observation = observed(Some(&report()), 0o644, "verify_days = 8\nrestore_days = 35");
    assert_eq!(
        (observation.state, observation.findings.len()),
        (State::Ok, 0)
    );
    assert_eq!(observation.id, "backup-check.restic");
    assert_eq!(observation.title, "restic repository");
    assert_eq!(observation.modules, [ModuleId::Backups].into());
    assert_eq!(field(&observation, "Snapshots"), &json!(14));
    assert_eq!(field(&observation, "Stored size"), &json!(52_428_800));
    assert_eq!(
        field(&observation, "Last integrity check"),
        &json!("passed")
    );
    assert_eq!(
        field(&observation, "What was restored"),
        &json!("/var/vmail/a: 12 files, 4096 bytes")
    );
}

#[test]
fn an_old_snapshot_and_an_overdue_check_are_warnings() {
    let mut old = report();
    old["snapshots"]["newest"] = json!(at(31 * HOUR));
    let observation = observed(Some(&old), 0o644, "");
    assert_eq!(observation.state, State::Warning);
    assert_eq!(
        observation.findings,
        ["The newest snapshot is older than 30 hours."]
    );

    // The checks are in the report, but not as often as they are expected.
    let observation = observed(Some(&report()), 0o644, "verify_days = 1\nrestore_days = 2");
    assert_eq!(
        observation.findings,
        [
            "The last integrity check is older than 1 days.",
            "The last test restore is older than 2 days.",
        ]
    );
    // Expected, but never run.
    let mut never = report();
    never["verify"] = Value::Null;
    never["restore"] = Value::Null;
    let observation = observed(Some(&never), 0o644, "restore_days = 35");
    assert_eq!(
        observation.findings,
        ["No test restore has been reported; one is expected every 35 days."]
    );
    assert_eq!(observed(Some(&never), 0o644, "").state, State::Ok);

    // A report nobody writes any more says nothing of today.
    let mut stale = report();
    stale["snapshots"]["at"] = json!(at(40 * HOUR));
    stale["snapshots"]["newest"] = json!(at(3700));
    let observation = observed(Some(&stale), 0o644, "");
    assert!(
        observation.findings[0].starts_with("The report itself is older than 30 hours"),
        "{:?}",
        observation.findings
    );
}

#[test]
fn a_failed_check_or_restore_and_an_unreadable_repository_are_failures() {
    let mut broken = report();
    broken["verify"] =
        json!({"at": at(60), "ok": false, "detail": "Fatal: repository contains errors"});
    broken["restore"] = json!({"at": at(60), "ok": false, "detail": "/var/vmail/a was not in the newest snapshot: nothing was restored"});
    let observation = observed(Some(&broken), 0o644, "");
    assert_eq!(observation.state, State::Failed);
    assert_eq!(
        observation.findings,
        [
            "The last integrity check failed: Fatal: repository contains errors.",
            "The last test restore failed: /var/vmail/a was not in the newest snapshot: nothing was restored.",
        ]
    );
    assert_eq!(field(&observation, "What was restored"), &Value::Null);

    let mut locked = report();
    locked["snapshots"] = Value::Null;
    locked["problem"] = json!("Fatal: wrong password or no key found");
    let observation = observed(Some(&locked), 0o644, "");
    assert_eq!(observation.state, State::Failed);
    assert_eq!(
        observation.findings[0],
        "restic could not list the repository: Fatal: wrong password or no key found."
    );
    let mut empty = report();
    empty["snapshots"]["newest"] = Value::Null;
    assert_eq!(
        observed(Some(&empty), 0o644, "").findings,
        ["The repository holds no snapshot."]
    );
}

#[test]
fn a_missing_report_and_one_that_others_can_write_are_unknown() {
    let missing = observed(None, 0o644, "");
    assert_eq!(missing.state, State::Unknown);
    assert!(
        missing.findings[0].contains("`garrison backup-check restic` writes it"),
        "{:?}",
        missing.findings
    );
    let open = observed(Some(&report()), 0o666, "");
    assert_eq!(open.state, State::Unknown);
    assert_eq!(
        open.findings,
        [
            "The repository's state is not known: users other than root can change the report; it is not trusted."
        ]
    );
    let other = observed(Some(&json!({"result": "passed"})), 0o644, "");
    assert_eq!(
        other.findings,
        ["The repository's state is not known: the file is no report of backup-check."]
    );
    // A report of the other tool is not this provider's.
    let borg = observed(Some(&report()), 0o644, "tool = \"borg\"");
    assert_eq!(
        borg.findings,
        ["The repository's state is not known: the report is one of restic."]
    );
    assert_eq!(borg.title, "borg repository");
}

#[test]
fn options_are_checked() {
    let default = BackupCheck::new(&table("type = \"backup-check\"\ntool = \"borg\"")).unwrap();
    assert_eq!(
        default.path,
        PathBuf::from("/var/lib/garrison/backup-check/borg.json")
    );
    for wrong in [
        "tool = \"tar\"",
        "max_age_hours = 0",
        "verify_days = -1",
        "repo = \"/srv\"",
    ] {
        assert!(
            BackupCheck::new(&table(&format!("type = \"backup-check\"\n{wrong}"))).is_err(),
            "{wrong}"
        );
    }
}
