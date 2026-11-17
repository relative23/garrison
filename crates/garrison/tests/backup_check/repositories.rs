//! What a report keeps of the run before it: the last integrity check and
//! test restore of the same repository, as the tool's own ID for it says,
//! whatever its name, and nothing of another's, which the card would show
//! as this repository's.

use serde_json::{Value, json};

use super::support::text;
use super::{Tools, read};

const OLD: &str = "0a0b0c0d0e0f00112233445566778899aabbccddeeff00112233445566778899";
const NEW: &str = "f0e1d2c3b4a5968778695a4b3c2d1e0ffedcba98765432100123456789abcdef";

/// The last check and restore of the report after a run of `arguments` in
/// `environment`, and what the run said on standard error.
fn kept(
    tools: &Tools,
    report: &std::path::Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> (Value, Value, String) {
    let mut asked = arguments.to_vec();
    asked.extend(["--report", report.to_str().unwrap()]);
    let ran = tools.run_with(&asked, environment);
    assert_eq!(ran.status.code(), Some(0), "{}", text(&ran.stderr));
    let written = read(report);
    (
        written["verify"]["ok"].clone(),
        written["restore"]["ok"].clone(),
        text(&ran.stderr),
    )
}

/// A run with `--verify --restore` of `arguments` with the repository `id`.
fn checked(tools: &Tools, report: &std::path::Path, arguments: &[&str], id: &str) {
    let mut asked = arguments.to_vec();
    asked.extend(["--verify", "--restore", "/etc/hosts"]);
    let both = kept(tools, report, &asked, &[("REPO_ID", id)]);
    assert_eq!((both.0, both.1), (json!(true), json!(true)));
}

#[test]
fn a_check_and_a_restore_are_kept_only_for_the_repository_whose_id_they_were_made_for() {
    let tools = Tools::new();
    let report = tools.report("restic");
    let to = report.to_str().unwrap();
    checked(&tools, &report, &["restic", "--repo", "/srv/repo"], OLD);
    assert_eq!(read(&report)["repositoryId"], OLD);
    // The same repository named in the environment, as a backup job's unit
    // names it, or under another name: its check and restore stay.
    let environment = [("RESTIC_REPOSITORY", "/srv/repo"), ("REPO_ID", OLD)];
    assert_eq!(
        kept(&tools, &report, &["restic"], &environment),
        (json!(true), json!(true), String::new())
    );
    let renamed = [("REPO_ID", OLD)];
    assert_eq!(
        kept(
            &tools,
            &report,
            &["restic", "--repo", "/mnt/repo"],
            &renamed
        ),
        (json!(true), json!(true), String::new())
    );
    // Another repository under the same name, as another disk mounted at
    // the same place: neither stays, and the command says why.
    let other = [("REPO_ID", NEW)];
    assert_eq!(
        kept(&tools, &report, &["restic", "--repo", "/mnt/repo"], &other),
        (
            Value::Null,
            Value::Null,
            format!(
                "The last report, {to}, is of the restic repository /mnt/repo (ID {OLD}), and \
                 this run asks the restic repository /mnt/repo (ID {NEW}): its last integrity \
                 check and test restore are not kept.\n"
            )
        )
    );
    assert_eq!(read(&report)["repositoryId"], NEW);
    // The other tool under the same report, with the same ID: neither stays.
    checked(&tools, &report, &["restic", "--repo", "/srv/repo"], NEW);
    let borg = kept(&tools, &report, &["borg", "--repo", "/srv/repo"], &other);
    assert_eq!((borg.0, borg.1), (Value::Null, Value::Null));
    assert!(
        borg.2.contains("and this run asks the borg repository"),
        "{}",
        borg.2
    );
}

/// restic may read the repository's place from a file its environment
/// names: the file may come to name another repository.
#[test]
fn a_repository_named_in_a_file_is_known_by_its_id_and_not_by_the_file() {
    let tools = Tools::new();
    let report = tools.report("restic");
    let to = report.to_str().unwrap();
    let file = ("RESTIC_REPOSITORY_FILE", "/etc/restic/mail");
    let checked = tools.run_with(
        &["restic", "--verify", "--report", to],
        &[file, ("REPO_ID", OLD)],
    );
    assert_eq!(checked.status.code(), Some(0), "{}", text(&checked.stderr));
    assert_eq!(read(&report)["repository"], "(named in /etc/restic/mail)");
    let same = kept(&tools, &report, &["restic"], &[file, ("REPO_ID", OLD)]);
    assert_eq!((same.0, same.2), (json!(true), String::new()));
    // The file now names another repository.
    let moved = kept(&tools, &report, &["restic"], &[file, ("REPO_ID", NEW)]);
    assert_eq!((moved.0, moved.1), (Value::Null, Value::Null));
    assert!(moved.2.contains(&format!("(ID {NEW})")), "{}", moved.2);
    // An empty RESTIC_REPOSITORY is none, as restic takes it (0.18.1): the
    // repository is the file's.
    let empty = tools.run_with(
        &["restic", "--report", to],
        &[
            ("RESTIC_REPOSITORY", ""),
            ("RESTIC_REPOSITORY_FILE", "/etc/restic/archive"),
        ],
    );
    assert_eq!(empty.status.code(), Some(0), "{}", text(&empty.stderr));
    assert_eq!(
        read(&report)["repository"],
        "(named in /etc/restic/archive)"
    );
}

/// A report that an earlier release wrote holds no ID: its check and
/// restore are kept once where tool and name are the same, with the ID of
/// the repository recorded, and from then on only the ID counts.
#[test]
fn a_report_of_an_earlier_release_is_kept_once_and_then_by_its_id() {
    let tools = Tools::new();
    let report = tools.report("restic");
    let to = report.to_str().unwrap();
    let earlier = json!({
        "tool": "restic", "repository": "/srv/repo", "problem": null,
        "snapshots": {"at": "2026-11-11T03:00:00+00:00", "count": 2,
                      "newest": "2026-11-11T02:00:04+00:00", "sizeBytes": 300_006},
        "verify": {"at": "2026-11-10T03:00:00+00:00", "ok": true, "detail": "no errors were found"},
        "restore": null,
    });
    std::fs::write(&report, earlier.to_string()).unwrap();
    // Under another name it is no report of this repository.
    let elsewhere = ["restic", "--repo", "/srv/else"];
    let other = kept(&tools, &report, &elsewhere, &[("REPO_ID", OLD)]);
    assert_eq!(other.0, Value::Null);
    std::fs::write(&report, earlier.to_string()).unwrap();
    let here = ["restic", "--repo", "/srv/repo"];
    let first = kept(&tools, &report, &here, &[("REPO_ID", OLD)]);
    assert_eq!(
        first,
        (
            json!(true),
            Value::Null,
            format!(
                "The last report, {to}, holds no repository ID, as an earlier release wrote it: \
                 its last integrity check and test restore are kept this once as those of \
                 /srv/repo, whose ID {OLD} is recorded with them.\n"
            )
        )
    );
    assert_eq!(read(&report)["repositoryId"], OLD);
    let next = kept(&tools, &report, &here, &[("REPO_ID", NEW)]);
    assert_eq!((next.0, next.1), (Value::Null, Value::Null));
}

/// Where the tool gives no ID for the repository, the run cannot tell
/// whose its last check and restore are, and keeps neither.
#[test]
fn a_run_without_the_repositorys_id_keeps_neither() {
    let tools = Tools::new();
    let report = tools.report("restic");
    let to = report.to_str().unwrap();
    checked(&tools, &report, &["restic", "--repo", "/srv/repo"], OLD);
    let unknown = tools.run_with(
        &["restic", "--repo", "/srv/repo", "--report", to],
        &[("REPO_ID", OLD), ("BROKEN", "cat")],
    );
    assert_eq!(unknown.status.code(), Some(0), "{}", text(&unknown.stderr));
    let written = read(&report);
    assert_eq!(
        (
            written["verify"].clone(),
            written["restore"].clone(),
            written["repositoryId"].clone()
        ),
        (Value::Null, Value::Null, Value::Null)
    );
    assert_eq!(
        text(&unknown.stderr),
        format!(
            "The last report, {to}, is not known to be of this repository, since restic gave no \
             ID for it: its last integrity check and test restore are not kept.\n"
        )
    );
}
