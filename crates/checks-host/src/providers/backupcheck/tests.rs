use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

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
        "tool": "restic", "repository": "/srv/restic", "repositoryId": "477c", "problem": null,
        "snapshots": {"at": at(3600), "count": 14, "newest": at(3700), "sizeBytes": 52_428_800},
        "verify": {"at": at(2 * DAY), "ok": true, "detail": "no errors were found"},
        "restore": {"at": at(3 * DAY), "ok": true, "detail": "/var/vmail/a: 12 files, 4096 bytes"},
    })
}

/// The observation for what `make` puts at the report's path, under `options`.
fn observed_at(make: impl FnOnce(&Path), options: &str) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("restic.json");
    make(&path);
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

/// `text` written as the report with `mode`.
fn written(path: &Path, text: &str, mode: u32) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// The observation for `report` written with `mode`, under `options`.
fn observed(report: Option<&Value>, mode: u32, options: &str) -> Observation {
    observed_at(
        |path| {
            if let Some(report) = report {
                written(path, &report.to_string(), mode);
            }
        },
        options,
    )
}

/// What the provider says of a report it cannot read.
const UNREADABLE: &str = "The repository's state is not known: the report cannot be read: it must \
                          be a file, not a link, of at most 256 KiB of valid JSON.";

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

/// An earlier release kept a check and a restore whatever repository they
/// were of, and wrote no ID: its report shows neither. One this release
/// wrote without an ID holds its own run's, which it shows.
#[test]
fn a_report_an_earlier_release_wrote_shows_no_check_or_restore() {
    let mut earlier = report();
    earlier.as_object_mut().unwrap().remove("repositoryId");
    let observation = observed(Some(&earlier), 0o644, "verify_days = 8");
    assert_eq!(field(&observation, "Last integrity check"), &Value::Null);
    assert_eq!(field(&observation, "Last test restore"), &Value::Null);
    assert_eq!(field(&observation, "Snapshots"), &json!(14));
    assert_eq!(
        observation.findings,
        ["No integrity check has been reported; one is expected every 8 days."]
    );
    let mut unknown = report();
    unknown["repositoryId"] = Value::Null;
    let observation = observed(Some(&unknown), 0o644, "");
    assert_eq!(
        field(&observation, "Last integrity check"),
        &json!("passed")
    );
}

#[test]
fn a_report_behind_a_link_is_not_read() {
    // Whoever may replace the path's file could point it at a report that
    // says something else; the link itself proves nothing of who wrote it.
    let linked = observed_at(
        |path| {
            let real = path.with_file_name("elsewhere.json");
            written(&real, &report().to_string(), 0o644);
            std::os::unix::fs::symlink(&real, path).unwrap();
        },
        "",
    );
    assert_eq!(linked.state, State::Unknown);
    assert_eq!(linked.findings, [UNREADABLE]);
}

#[test]
fn a_report_that_is_no_strict_json_object_is_not_read() {
    // serde reads a struct from a list of its fields' values as well; no
    // report of backup-check is ever written that way.
    let listed = observed_at(
        |path| {
            let report = report();
            let fields = [
                "tool",
                "repository",
                "snapshots",
                "problem",
                "verify",
                "restore",
            ];
            let list: Vec<Value> = fields.iter().map(|field| report[field].clone()).collect();
            written(path, &Value::Array(list).to_string(), 0o644);
        },
        "",
    );
    assert_eq!(listed.state, State::Unknown);
    assert_eq!(
        listed.findings,
        ["The repository's state is not known: the file is no report of backup-check."]
    );
    // Two values for one key, which two readers could read differently.
    let twice = observed_at(
        |path| {
            let text = report().to_string();
            let doubled = text.replacen("{\"", "{\"repository\":\"/srv/other\",\"", 1);
            written(path, &doubled, 0o644);
        },
        "",
    );
    assert_eq!(twice.state, State::Unknown);
    assert_eq!(twice.findings, [UNREADABLE]);
}

#[test]
fn a_report_over_its_size_or_no_regular_file_is_not_read() {
    let mut large = report();
    large["repository"] = json!("r".repeat(256 * 1024));
    let oversized = observed(Some(&large), 0o644, "");
    assert_eq!(oversized.state, State::Unknown);
    assert_eq!(oversized.findings, [UNREADABLE]);
    // A pipe has no size to check and would keep the run waiting for a
    // writer: it is no report, at once.
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let fifo = observed_at(
            |path| {
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    path,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::from_raw_mode(0o644),
                    0,
                )
                .unwrap();
            },
            "",
        );
        let _ = sender.send(fifo);
    });
    let fifo = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("the provider waited for a writer of the pipe");
    assert_eq!(fifo.state, State::Unknown);
    assert_eq!(fifo.findings, [UNREADABLE]);
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

#[test]
fn a_snapshot_or_a_report_from_the_future_is_not_a_fresh_one() {
    // A clock that is wrong, here or where the report was written: such a
    // time says nothing of how old the backup is.
    let mut ahead = report();
    ahead["snapshots"]["newest"] = json!(at(-3600));
    let observation = observed(Some(&ahead), 0o644, "");
    assert_eq!(observation.state, State::Warning);
    assert_eq!(
        observation.findings,
        [
            "The newest snapshot is dated 60 minutes ahead of this host's clock; one of the two \
          clocks is wrong, so its age is not known."
        ]
    );
    let mut listed = report();
    listed["snapshots"]["at"] = json!(at(-900));
    let observation = observed(Some(&listed), 0o644, "");
    assert_eq!(observation.state, State::Warning);
    assert!(
        observation.findings[0].starts_with("The report is dated 15 minutes ahead"),
        "{:?}",
        observation.findings
    );
    // A few minutes are two clocks that differ a little.
    let mut near = report();
    near["snapshots"]["newest"] = json!(at(-240));
    near["snapshots"]["at"] = json!(at(-240));
    assert_eq!(observed(Some(&near), 0o644, "").state, State::Ok);
}
