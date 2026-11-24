//! What a report keeps of the run before it: the last integrity check and
//! test restore of the same repository alone, which is one of the same
//! tool, under the same name and with the same ID as the tool gives it. A
//! report of another repository, or of one that is not known, keeps
//! neither, since the card would show them as this repository's.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Map, Value, json};

use super::support::{finished, text};
use super::{Tools, read};

const OLD: &str = "0a0b0c0d0e0f00112233445566778899aabbccddeeff00112233445566778899";
const NEW: &str = "f0e1d2c3b4a5968778695a4b3c2d1e0ffedcba98765432100123456789abcdef";
/// The repository's place, as the runs name it.
const HERE: [&str; 2] = ["--repo", "/srv/repo"];

/// The stand-ins' ID of the repository; an empty one is none.
fn id(id: &'static str) -> [(&'static str, &'static str); 1] {
    [("REPO_ID", id)]
}

/// One tool's runs against one report, with stand-ins of their own.
struct Case {
    tools: Tools,
    tool: &'static str,
    report: PathBuf,
}

impl Case {
    fn new(tool: &'static str) -> Case {
        let tools = Tools::new();
        let report = tools.report("report");
        Case {
            tools,
            tool,
            report,
        }
    }

    /// The variable that names the repository to the tool.
    fn variable(&self) -> &'static str {
        if self.tool == "restic" {
            "RESTIC_REPOSITORY"
        } else {
            "BORG_REPO"
        }
    }

    /// One run of `tool` with `arguments` in `environment`, which writes the
    /// report.
    fn run_as(&self, tool: &str, arguments: &[&str], environment: &[(&str, &str)]) -> Output {
        let mut asked = vec![tool];
        asked.extend_from_slice(arguments);
        asked.extend(["--report", self.report.to_str().unwrap()]);
        self.tools.run_with(&asked, environment)
    }

    fn run(&self, arguments: &[&str], environment: &[(&str, &str)]) -> Output {
        self.run_as(self.tool, arguments, environment)
    }

    /// A run of `tool` that checks and restores, as the weekly one does, and
    /// passes.
    fn checked_as(&self, tool: &str, arguments: &[&str], environment: &[(&str, &str)]) {
        let mut asked = arguments.to_vec();
        asked.extend(["--verify", "--restore", "/etc/hosts"]);
        let ran = self.run_as(tool, &asked, environment);
        assert_eq!(ran.status.code(), Some(0), "{}", text(&ran.stderr));
        let written = read(&self.report);
        assert_eq!(
            (&written["verify"]["ok"], &written["restore"]["ok"]),
            (&json!(true), &json!(true))
        );
    }

    fn checked(&self, arguments: &[&str], environment: &[(&str, &str)]) {
        self.checked_as(self.tool, arguments, environment);
    }

    /// The report as `change` leaves it, in its place.
    fn changed(&self, change: impl FnOnce(&mut Map<String, Value>)) {
        let mut report = read(&self.report);
        change(report.as_object_mut().unwrap());
        std::fs::write(&self.report, report.to_string()).unwrap();
    }

    /// The file restic reads the repository's place from, holding `place`.
    fn file(&self, place: &str) -> String {
        let file = self.tools.directory.path().join("repository");
        std::fs::write(&file, place).unwrap();
        file.to_str().unwrap().to_owned()
    }

    /// The last integrity check and test restore on the card, as one
    /// collection run shows the report.
    fn card(&self) -> (Value, Value) {
        let directory = tempfile::tempdir().unwrap();
        let configuration = directory.path().join("garrison.toml");
        let provider = format!(
            "\n[[providers]]\ntype = \"backup-check\"\ntool = \"{}\"\npath = \"{}\"\n",
            self.tool,
            self.report.display()
        );
        let base = garrison_testing::config_text(directory.path(), "http://127.0.0.1:9");
        std::fs::write(&configuration, base + &provider).unwrap();
        let ran = finished(
            Command::new(env!("CARGO_BIN_EXE_garrison"))
                .arg("--config")
                .arg(&configuration)
                .arg("collect")
                .env_remove("CREDENTIALS_DIRECTORY"),
        );
        assert!(ran.status.success(), "{}", text(&ran.stderr));
        let database =
            rusqlite::Connection::open(directory.path().join("collector/status.sqlite")).unwrap();
        let document: String = database
            .query_row("SELECT document FROM snapshots", [], |row| row.get(0))
            .unwrap();
        let document: Value = serde_json::from_str(&document).unwrap();
        let id = format!("backup-check.{}", self.tool);
        let observations = document["observations"].as_array().unwrap();
        let card = observations
            .iter()
            .find(|card| card["id"] == id.as_str())
            .unwrap();
        let field = |label: &str| {
            card["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|field| field["label"] == label)
                .map_or(Value::Null, |field| field["value"].clone())
        };
        (field("Last integrity check"), field("Last test restore"))
    }
}

/// One way for the report before a run to be what it is: its name, whether
/// the card may show the check and restore that report held, and the runs,
/// the last of which it gives where it ends with one.
type Way = (String, bool, Box<dyn Fn(&Case) -> Option<Output>>);

fn way(name: &str, kept: bool, runs: impl Fn(&Case) -> Option<Output> + 'static) -> Way {
    (name.to_owned(), kept, Box::new(runs))
}

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
        let ways = [places(tool), reports(tool), runs(tool), parts(tool)];
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
             run asks the restic repository /mnt/copy (ID {OLD}): {lost}"
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
