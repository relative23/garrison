//! One tool's runs of the command against one report, with stand-ins of
//! their own, and the card one collection run makes of that report.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Map, Value, json};

use super::stand_in::{Tools, read};
use super::support::{finished, text};

pub(super) const OLD: &str = "0a0b0c0d0e0f00112233445566778899aabbccddeeff00112233445566778899";
pub(super) const NEW: &str = "f0e1d2c3b4a5968778695a4b3c2d1e0ffedcba98765432100123456789abcdef";
/// The repository's place, as the runs name it.
pub(super) const HERE: [&str; 2] = ["--repo", "/srv/repo"];

/// The stand-ins' ID of the repository; an empty one is none.
pub(super) fn id(id: &'static str) -> [(&'static str, &'static str); 1] {
    [("REPO_ID", id)]
}

/// One tool's runs against one report, with stand-ins of their own.
pub(super) struct Case {
    pub(super) tools: Tools,
    pub(super) tool: &'static str,
    pub(super) report: PathBuf,
}

impl Case {
    pub(super) fn new(tool: &'static str) -> Case {
        let tools = Tools::new();
        let report = tools.report("report");
        Case {
            tools,
            tool,
            report,
        }
    }

    /// The variable that names the repository to the tool.
    pub(super) fn variable(&self) -> &'static str {
        if self.tool == "restic" {
            "RESTIC_REPOSITORY"
        } else {
            "BORG_REPO"
        }
    }

    /// One run of `tool` with `arguments` in `environment`, which writes the
    /// report.
    pub(super) fn run_as(
        &self,
        tool: &str,
        arguments: &[&str],
        environment: &[(&str, &str)],
    ) -> Output {
        let mut asked = vec![tool];
        asked.extend_from_slice(arguments);
        asked.extend(["--report", self.report.to_str().unwrap()]);
        self.tools.run_with(&asked, environment)
    }

    pub(super) fn run(&self, arguments: &[&str], environment: &[(&str, &str)]) -> Output {
        self.run_as(self.tool, arguments, environment)
    }

    /// A run of `tool` that checks and restores, as the weekly one does, and
    /// passes.
    pub(super) fn checked_as(&self, tool: &str, arguments: &[&str], environment: &[(&str, &str)]) {
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

    pub(super) fn checked(&self, arguments: &[&str], environment: &[(&str, &str)]) {
        self.checked_as(self.tool, arguments, environment);
    }

    /// The report as `change` leaves it, in its place.
    pub(super) fn changed(&self, change: impl FnOnce(&mut Map<String, Value>)) {
        let mut report = read(&self.report);
        change(report.as_object_mut().unwrap());
        std::fs::write(&self.report, report.to_string()).unwrap();
    }

    /// The file restic reads the repository's place from, holding `place`.
    pub(super) fn file(&self, place: &str) -> String {
        let file = self.tools.directory.path().join("repository");
        std::fs::write(&file, place).unwrap();
        file.to_str().unwrap().to_owned()
    }

    /// The last integrity check and test restore on the card, as one
    /// collection run shows the report.
    pub(super) fn card(&self) -> (Value, Value) {
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
pub(super) type Way = (String, bool, Box<dyn Fn(&Case) -> Option<Output>>);

pub(super) fn way(name: &str, kept: bool, runs: impl Fn(&Case) -> Option<Output> + 'static) -> Way {
    (name.to_owned(), kept, Box::new(runs))
}
