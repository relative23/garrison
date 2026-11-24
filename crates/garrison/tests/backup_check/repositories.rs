//! What a report keeps of the run before it: the last integrity check and
//! test restore of the same repository alone, which is one of the same
//! tool, under the same name and with the same ID as the tool gives it. A
//! report of another repository, or of one that is not known, keeps
//! neither, since the card would show them as this repository's.

use std::os::unix::fs::PermissionsExt;

use serde_json::{Map, Value, json};

use super::case::{Case, HERE, NEW, OLD, Way, id, way};
use super::spellings;
use super::stand_in::read;
use super::support::text;

/// The repository asked again, under the name it had or under another.
fn places(tool: &str) -> Vec<Way> {
    let mut ways = vec![
        way("the same repository again", true, |case| {
            case.checked(&HERE, &id(OLD));
            Some(case.run(&HERE, &id(OLD)))
        }),
        way(
            "the same repository, named in the environment",
            true,
            |case| {
                case.checked(&HERE, &id(OLD));
                Some(case.run(&[], &[(case.variable(), "/srv/repo"), ("REPO_ID", OLD)]))
            },
        ),
        way(
            "another repository under the same name, as another disk mounted there",
            false,
            |case| {
                case.checked(&HERE, &id(OLD));
                Some(case.run(&HERE, &id(NEW)))
            },
        ),
        way(
            "a copy of the repository under another name",
            false,
            |case| {
                case.checked(&HERE, &id(OLD));
                Some(case.run(&["--repo", "/mnt/copy"], &id(OLD)))
            },
        ),
        way(
            "a run that is not told where its repository is",
            false,
            |case| {
                case.checked(&[], &id(OLD));
                Some(case.run(&[], &id(OLD)))
            },
        ),
    ];
    if tool == "restic" {
        ways.extend([
            way(
                "the same repository, named in restic's repository file",
                true,
                |case| {
                    case.checked(&HERE, &id(OLD));
                    let file = case.file("  /srv/repo\n\n");
                    Some(case.run(&[], &[("RESTIC_REPOSITORY_FILE", &file), ("REPO_ID", OLD)]))
                },
            ),
            way(
                "the same, in that file beside an empty RESTIC_REPOSITORY",
                true,
                |case| {
                    case.checked(&HERE, &id(OLD));
                    let file = case.file("/srv/repo\n");
                    let named = [
                        ("RESTIC_REPOSITORY", ""),
                        ("RESTIC_REPOSITORY_FILE", &file),
                        ("REPO_ID", OLD),
                    ];
                    Some(case.run(&[], &named))
                },
            ),
            way(
                "restic's repository file, which now names a copy elsewhere",
                false,
                |case| {
                    let file = case.file("/srv/repo\n");
                    let named = [("RESTIC_REPOSITORY_FILE", file.as_str()), ("REPO_ID", OLD)];
                    case.checked(&[], &named);
                    case.file("/mnt/copy\n");
                    Some(case.run(&[], &named))
                },
            ),
        ]);
    }
    ways
}

/// The report before, as another tool, an earlier release or a run without
/// an ID wrote it, or as it lies at the report's path.
fn reports(tool: &str) -> Vec<Way> {
    let other = if tool == "restic" { "borg" } else { "restic" };
    let earlier = |report: &mut Map<String, Value>| {
        report.remove("repositoryId");
    };
    vec![
        way(
            "a report of the other tool, of the same name and ID",
            false,
            move |case| {
                case.checked_as(other, &HERE, &id(OLD));
                Some(case.run(&HERE, &id(OLD)))
            },
        ),
        way(
            "a report an earlier release wrote, which holds no ID",
            false,
            move |case| {
                case.checked(&HERE, &id(OLD));
                case.changed(earlier);
                Some(case.run(&HERE, &id(OLD)))
            },
        ),
        way(
            "such a report, before this release's first run",
            false,
            move |case| {
                case.checked(&HERE, &id(OLD));
                case.changed(earlier);
                None
            },
        ),
        way("a report of a run that got no ID", false, |case| {
            case.checked(&HERE, &id(""));
            Some(case.run(&HERE, &id(OLD)))
        }),
        way("a report another user could have changed", false, |case| {
            case.checked(&HERE, &id(OLD));
            let open = std::fs::Permissions::from_mode(0o666);
            std::fs::set_permissions(&case.report, open).unwrap();
            Some(case.run(&HERE, &id(OLD)))
        }),
        way("a link to a report of the repository", false, |case| {
            case.checked(&HERE, &id(OLD));
            let elsewhere = case.report.with_file_name("elsewhere.json");
            std::fs::rename(&case.report, &elsewhere).unwrap();
            std::os::unix::fs::symlink(&elsewhere, &case.report).unwrap();
            Some(case.run(&HERE, &id(OLD)))
        }),
    ]
}

/// This run, where the tool gives no ID or cannot list the repository.
fn runs(tool: &str) -> Vec<Way> {
    let listing = if tool == "restic" {
        "snapshots"
    } else {
        "list"
    };
    vec![
        way("a run that gets no ID", false, |case| {
            case.checked(&HERE, &id(OLD));
            Some(case.run(&HERE, &id("")))
        }),
        way(
            "a run that cannot list the repository",
            false,
            move |case| {
                case.checked(&HERE, &id(OLD));
                Some(case.run(&HERE, &[("REPO_ID", OLD), ("BROKEN", listing)]))
            },
        ),
    ]
}

/// Every part of the report but what a run found there, changed or taken
/// out: each tells which repository the report is of, so that a part a
/// report gains fails here until a run compares it.
fn parts(tool: &'static str) -> Vec<Way> {
    let probe = Case::new(tool);
    probe.checked(&HERE, &id(OLD));
    let found = ["snapshots", "problem", "verify", "restore"];
    let written = read(&probe.report);
    let mut ways = Vec::new();
    for key in written.as_object().unwrap().keys() {
        if found.contains(&key.as_str()) {
            continue;
        }
        let (changed, gone) = (key.clone(), key.clone());
        ways.push(way(
            &format!("a report whose {key} is another"),
            false,
            move |case| {
                case.checked(&HERE, &id(OLD));
                case.changed(|report| {
                    let value = report.get_mut(&changed).unwrap();
                    *value = match value.take() {
                        Value::String(text) => json!(format!("{text}0")),
                        _ => json!("0"),
                    };
                });
                Some(case.run(&HERE, &id(OLD)))
            },
        ));
        ways.push(way(
            &format!("a report without its {key}"),
            false,
            move |case| {
                case.checked(&HERE, &id(OLD));
                case.changed(|report| {
                    report.remove(&gone);
                });
                Some(case.run(&HERE, &id(OLD)))
            },
        ));
    }
    ways
}

/// For each tool, every way the report before a run can be of another
/// repository or of none known, beside the ways it is of the same one: the
/// card shows a check and a restore only where it is the same, and a run
/// that keeps neither of a report that held them says why.
#[test]
fn no_check_or_restore_of_another_repository_or_of_none_known_reaches_the_card() {
    let mut wrong = Vec::new();
    for tool in ["restic", "borg"] {
        let ways = [
            places(tool),
            spellings::ways(tool),
            reports(tool),
            runs(tool),
            parts(tool),
        ];
        for (name, kept, steps) in ways.into_iter().flatten() {
            let case = Case::new(tool);
            let last = steps(&case);
            let held = if kept { json!("passed") } else { Value::Null };
            let shown = case.card();
            if shown != (held.clone(), held) {
                wrong.push(format!("{tool}, {name}: the card shows {shown:?}"));
            }
            if let Some(said) = last.map(|ran| text(&ran.stderr)) {
                let right = if kept {
                    said.is_empty()
                } else {
                    said.contains("are not kept")
                };
                if !right {
                    wrong.push(format!("{tool}, {name}: the run said {said:?}"));
                }
            }
        }
    }
    assert_eq!(wrong, Vec::<String>::new());
}

/// What a run says where it keeps nothing of the last report's check and
/// restore, and how it names a repository restic reads from a file.
#[test]
fn a_run_says_why_it_keeps_nothing_and_names_what_the_file_names() {
    let case = Case::new("restic");
    let to = case.report.display().to_string();
    let lost = "its last integrity check and test restore are not kept.\n";
    let after = |arguments: &[&str], environment: &[(&str, &str)]| {
        case.checked(&HERE, &id(OLD));
        let ran = case.run(arguments, environment);
        assert_eq!(ran.status.code(), Some(0), "{}", text(&ran.stderr));
        text(&ran.stderr)
    };
    assert_eq!(
        after(&HERE, &id(NEW)),
        format!(
            "The last report, {to}, is of the restic repository /srv/repo (ID {OLD}), and this \
             run asks the restic repository /srv/repo (ID {NEW}): {lost}"
        )
    );
    assert_eq!(
        after(&["--repo", "/mnt/copy"], &id(OLD)),
        format!(
            "The last report, {to}, is of the restic repository /srv/repo (ID {OLD}), and this \
             run asks the restic repository /mnt/copy (ID {OLD}): its last integrity check and \
             test restore are not kept. The same ID at another place is a copy, which needs a \
             --report of its own; name one repository alike in every run.\n"
        )
    );
    assert_eq!(
        after(&HERE, &id("")),
        format!(
            "The last report, {to}, is not known to be of this repository, since restic gave no \
             ID for it: {lost}"
        )
    );
    assert_eq!(read(&case.report)["repositoryId"], Value::Null);
    // A listing that fails is said first, and is the cause.
    case.checked(&HERE, &id(OLD));
    let unlisted = case.run(&HERE, &[("REPO_ID", OLD), ("BROKEN", "snapshots")]);
    assert_eq!(unlisted.status.code(), Some(1));
    assert_eq!(
        text(&unlisted.stderr),
        format!(
            "restic did not list its snapshots: Fatal: the repository is locked by another \
             process\nThe last report, {to}, is not known to be of this repository, since restic \
             could not list it: {lost}"
        )
    );
    assert_eq!(
        after(&[], &id(OLD)),
        format!(
            "The last report, {to}, is not known to be of this repository, since the command is \
             not told where this one is: {lost}"
        )
    );
    case.checked(&HERE, &id(OLD));
    case.changed(|report| {
        report.remove("repositoryId");
    });
    let earlier = case.run(&HERE, &id(OLD));
    assert_eq!(
        text(&earlier.stderr),
        format!("The last report, {to}, holds no repository ID: {lost}")
    );
    case.checked(&HERE, &id(OLD));
    let open = std::fs::Permissions::from_mode(0o666);
    std::fs::set_permissions(&case.report, open).unwrap();
    assert_eq!(
        text(&case.run(&HERE, &id(OLD)).stderr),
        format!("The last report, {to}, can be changed by users other than root: {lost}")
    );
    // restic's repository file names it by what it holds, as restic reads
    // it, and by itself where it cannot be read.
    let file = case.file("  /srv/restic/mail\n\n");
    case.run(&[], &[("RESTIC_REPOSITORY_FILE", &file)]);
    assert_eq!(read(&case.report)["repository"], "/srv/restic/mail");
    let missing = case.tools.directory.path().join("missing");
    case.run(
        &[],
        &[("RESTIC_REPOSITORY_FILE", missing.to_str().unwrap())],
    );
    assert_eq!(
        read(&case.report)["repository"],
        format!("(named in {})", missing.display())
    );
}
