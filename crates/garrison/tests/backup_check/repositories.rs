//! What a report keeps of the run before it: the last integrity check and
//! test restore of the same tool and the same repository, and nothing of
//! another's, which the card would show as this repository's.

use serde_json::{Value, json};

use super::support::text;
use super::{Tools, read};

/// The last check and restore of the report, and what the run said of them.
fn kept(tools: &Tools, report: &std::path::Path, arguments: &[&str]) -> (Value, Value, String) {
    let to = report.to_str().unwrap();
    let mut asked = arguments.to_vec();
    asked.extend(["--report", to]);
    let ran = tools.run_with(&asked, &[]);
    assert_eq!(ran.status.code(), Some(0), "{}", text(&ran.stderr));
    let written = read(report);
    (
        written["verify"]["ok"].clone(),
        written["restore"]["ok"].clone(),
        text(&ran.stderr),
    )
}

#[test]
fn a_check_and_a_restore_are_kept_only_for_their_own_repository() {
    let tools = Tools::new();
    let report = tools.report("restic");
    let to = report.to_str().unwrap();
    let checked = [
        "restic",
        "--repo",
        "/srv/old",
        "--verify",
        "--restore",
        "/etc/hosts",
    ];
    assert_eq!(
        kept(&tools, &report, &checked),
        (json!(true), json!(true), String::new())
    );
    // The same repository named in the environment, as a backup job's unit
    // names it: the daily listing keeps the weekly check and restore.
    let listed = tools.run_with(
        &["restic", "--report", to],
        &[("RESTIC_REPOSITORY", "/srv/old")],
    );
    assert_eq!(listed.status.code(), Some(0), "{}", text(&listed.stderr));
    assert_eq!(text(&listed.stderr), "");
    assert_eq!(read(&report)["verify"]["ok"], true);
    assert_eq!(read(&report)["restore"]["ok"], true);
    // Another repository under the same report: neither is kept, and the
    // command says why.
    assert_eq!(
        kept(&tools, &report, &["restic", "--repo", "/srv/new"]),
        (
            Value::Null,
            Value::Null,
            format!(
                "The last report, {to}, is of the restic repository /srv/old, and this run asks \
                 the restic repository /srv/new: its last integrity check and test restore are \
                 not kept.\n"
            )
        )
    );
    assert_eq!(read(&report)["repository"], "/srv/new");
    // The other tool under the same report, for a repository of that name.
    kept(
        &tools,
        &report,
        &["restic", "--repo", "/srv/new", "--verify"],
    );
    assert_eq!(
        kept(&tools, &report, &["borg", "--repo", "/srv/new"]),
        (
            Value::Null,
            Value::Null,
            format!(
                "The last report, {to}, is of the restic repository /srv/new, and this run asks \
                 the borg repository /srv/new: its last integrity check and test restore are not \
                 kept.\n"
            )
        )
    );
}

/// restic may read the repository's place from a file its environment
/// names: two repositories named so are told apart by their files.
#[test]
fn a_repository_named_in_a_file_is_known_by_that_file() {
    let tools = Tools::new();
    let report = tools.report("restic");
    let to = report.to_str().unwrap();
    let checked = tools.run_with(
        &["restic", "--verify", "--report", to],
        &[("RESTIC_REPOSITORY_FILE", "/etc/restic/mail")],
    );
    assert_eq!(checked.status.code(), Some(0), "{}", text(&checked.stderr));
    assert_eq!(read(&report)["repository"], "(named in /etc/restic/mail)");
    let same = tools.run_with(
        &["restic", "--report", to],
        &[("RESTIC_REPOSITORY_FILE", "/etc/restic/mail")],
    );
    assert_eq!(text(&same.stderr), "");
    assert_eq!(read(&report)["verify"]["ok"], true);
    let other = tools.run_with(
        &["restic", "--report", to],
        &[("RESTIC_REPOSITORY_FILE", "/etc/restic/archive")],
    );
    assert_eq!(other.status.code(), Some(0), "{}", text(&other.stderr));
    assert_eq!(read(&report)["verify"], Value::Null);
    assert!(
        text(&other.stderr).contains("(named in /etc/restic/mail), and this run asks"),
        "{}",
        text(&other.stderr)
    );
}
