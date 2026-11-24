//! `garrison backup-check restic|borg`: ask the backup tool about its
//! repository and write the answer down for the collector.
//!
//! Run it as root from the backup job's own unit, with that job's
//! environment (`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE`, `BORG_REPO`,
//! `BORG_PASSPHRASE` and the like): the command adds no secret of its own
//! and keeps none. Every run lists the snapshots and reads the repository's
//! size and its own ID. `--verify` also runs the tool's integrity check, `--restore PATH`
//! restores that path from the newest snapshot into a directory of its own
//! and removes it again, after what interrupted restores left. The report
//! keeps the last check and the last restore of the same repository until
//! the next one; runs of one report take turns.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use garrison_collector::backups::{
    Report, Run, Snapshots, Tool, borg_archives, borg_id, borg_location, borg_size, restic_id,
    restic_size, restic_snapshots,
};
use garrison_core::files::atomic_write;
use garrison_core::time;

use crate::{complain, say};
use report::{given, kept, last_report, place, turn};

mod report;
mod restore;

/// Where the reports go, one file for each tool.
pub(crate) const REPORTS: &str = "/var/lib/garrison/backup-check";
const MAX_DETAIL: usize = 200;

/// What the command was asked to do.
#[derive(Debug)]
pub(crate) struct Asked {
    pub(crate) tool: String,
    pub(crate) repo: Option<String>,
    pub(crate) verify: bool,
    pub(crate) restore: Option<String>,
    pub(crate) report: Option<PathBuf>,
}

/// What a run of the tool gave.
struct Ran {
    ok: bool,
    stdout: String,
    /// The last line it wrote, to either output.
    last: String,
}

fn last_line(texts: &[&str]) -> String {
    let line = texts
        .iter()
        .rev()
        .flat_map(|text| text.lines().rev())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default();
    // With `--json` restic words its errors as JSON too; the message is what counts.
    let message = serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| value["message"].as_str().map(str::to_owned));
    message
        .unwrap_or_else(|| line.to_owned())
        .chars()
        .take(MAX_DETAIL)
        .collect()
}

/// Run `tool` with `arguments` in `directory`; its environment is this
/// command's, which is the backup job's.
fn run(tool: Tool, arguments: &[&str], directory: Option<&Path>) -> Ran {
    let mut command = Command::new(tool.name());
    command.args(arguments).stdin(Stdio::null());
    if tool == Tool::Borg {
        // borg writes its times without an offset, in its own time zone.
        command.env("TZ", "UTC");
    }
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    match command.output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr);
            Ran {
                ok: output.status.success(),
                last: last_line(&[&stdout, &stderr]),
                stdout,
            }
        }
        Err(error) => Ran {
            ok: false,
            stdout: String::new(),
            last: format!("{} could not be run: {error}", tool.name()),
        },
    }
}

fn now() -> String {
    let now = time::now();
    time::Timestamp::from_second(now.as_second())
        .map_or_else(|_| time::isoformat(now), time::isoformat)
}

/// What a listing gave: the snapshots, the repository's own ID where the
/// tool gave one, and for borg the newest archive's name and where borg
/// says the repository is.
struct Listed {
    snapshots: Snapshots,
    id: Option<String>,
    newest: Option<String>,
    location: Option<String>,
}

/// One tool's way of being asked.
struct Repository {
    tool: Tool,
    /// The repository as an argument; without it the tool reads its environment.
    given: Option<String>,
}

impl Repository {
    /// The repository's arguments for restic, which names it with `-r`.
    fn restic(&self) -> Vec<&str> {
        self.given
            .as_deref()
            .map_or_else(Vec::new, |repo| vec!["-r", repo])
    }

    /// The repository, or one of its archives, as borg names it.
    fn borg(&self, archive: Option<&str>) -> String {
        let repo = self.given.as_deref().unwrap_or_default();
        archive.map_or_else(|| repo.to_owned(), |archive| format!("{repo}::{archive}"))
    }

    /// The snapshots and the size, the repository's ID, and for borg the
    /// newest archive's name.
    fn snapshots(&self) -> Result<Listed, String> {
        let at = now();
        match self.tool {
            Tool::Restic => {
                let mut arguments = self.restic();
                arguments.extend(["snapshots", "--json", "--no-lock"]);
                let listed = run(self.tool, &arguments, None);
                if !listed.ok {
                    return Err(listed.last);
                }
                let (count, newest) = restic_snapshots(&listed.stdout)?;
                let mut arguments = self.restic();
                arguments.extend(["stats", "--json", "--mode", "raw-data", "--no-lock"]);
                let size_bytes = restic_size(&run(self.tool, &arguments, None).stdout);
                // The listing does not name the repository; its config does.
                let mut arguments = self.restic();
                arguments.extend(["cat", "config", "--no-lock"]);
                let config = run(self.tool, &arguments, None);
                Ok(Listed {
                    snapshots: Snapshots {
                        at,
                        count,
                        newest,
                        size_bytes,
                    },
                    id: config.ok.then(|| restic_id(&config.stdout)).flatten(),
                    newest: None,
                    location: None,
                })
            }
            Tool::Borg => {
                let repo = self.borg(None);
                let mut arguments = vec!["list", "--json"];
                arguments.extend((!repo.is_empty()).then_some(repo.as_str()));
                let listed = run(self.tool, &arguments, None);
                if !listed.ok {
                    return Err(listed.last);
                }
                let (count, newest, name) = borg_archives(&listed.stdout)?;
                arguments[0] = "info";
                let size_bytes = borg_size(&run(self.tool, &arguments, None).stdout);
                Ok(Listed {
                    snapshots: Snapshots {
                        at,
                        count,
                        newest,
                        size_bytes,
                    },
                    id: borg_id(&listed.stdout),
                    newest: name,
                    location: borg_location(&listed.stdout),
                })
            }
        }
    }

    fn verify(&self) -> Run {
        let ran = match self.tool {
            Tool::Restic => {
                let mut arguments = self.restic();
                arguments.push("check");
                run(self.tool, &arguments, None)
            }
            Tool::Borg => {
                let repo = self.borg(None);
                let mut arguments = vec!["check"];
                arguments.extend((!repo.is_empty()).then_some(repo.as_str()));
                run(self.tool, &arguments, None)
            }
        };
        // borg says nothing where it finds nothing.
        let detail = if ran.ok && ran.last.is_empty() {
            "no problems found".to_owned()
        } else {
            ran.last
        };
        Run {
            at: now(),
            ok: ran.ok,
            detail,
        }
    }
}

/// What a run says of its listing.
fn listing(tool: Tool, snapshots: &Snapshots) -> String {
    let noun = if tool == Tool::Restic {
        "snapshot"
    } else {
        "archive"
    };
    format!(
        "{}: {} {noun}{}, the newest of {}.",
        tool.name(),
        snapshots.count,
        if snapshots.count == 1 { "" } else { "s" },
        snapshots.newest.as_deref().unwrap_or("no date")
    )
}

pub(crate) fn run_check(asked: &Asked) -> u8 {
    let Some(tool) = Tool::named(&asked.tool) else {
        complain("The backup tool is restic or borg.");
        return 2;
    };
    let path = asked
        .report
        .clone()
        .unwrap_or_else(|| Path::new(REPORTS).join(format!("{}.json", tool.name())));
    let _turn = match turn(&path) {
        Ok(lock) => lock,
        Err(refusal) => {
            complain(&refusal);
            return 1;
        }
    };
    let repository = Repository {
        tool,
        given: asked.repo.clone(),
    };
    let listed = repository.snapshots();
    let id = listed.as_ref().ok().and_then(|listed| listed.id.clone());
    let location = listed
        .as_ref()
        .ok()
        .and_then(|listed| listed.location.as_deref());
    let (name, placed) = match place(tool, given(asked, tool), location) {
        Ok(place) => (place, true),
        Err(unplaced) => (unplaced, false),
    };
    let mut report = Report {
        tool,
        repository: name,
        repository_id: id,
        snapshots: None,
        problem: None,
        verify: None,
        restore: None,
    };
    let mut failed = false;
    let mut newest = None;
    match listed {
        Ok(listed) => {
            say(&listing(tool, &listed.snapshots));
            report.snapshots = Some(listed.snapshots);
            newest = listed.newest;
        }
        Err(problem) => {
            failed = true;
            complain(&format!(
                "{} did not list its snapshots: {problem}",
                tool.name()
            ));
            report.problem = Some(problem);
        }
    }
    // What the last run wrote of this repository stays, where this one does
    // not run that part.
    if let Some(before) = last_report(&path).and_then(|before| kept(&path, before, &report, placed))
    {
        report.verify = before.verify;
        report.restore = before.restore;
    }
    if asked.verify && report.problem.is_none() {
        let run = repository.verify();
        say(&format!(
            "Integrity check: {} ({})",
            if run.ok { "passed" } else { "FAILED" },
            run.detail
        ));
        failed |= !run.ok;
        report.verify = Some(run);
    }
    if let Some(wanted) = asked
        .restore
        .as_deref()
        .filter(|_| report.problem.is_none())
    {
        let (run, failing) = restore::tested(&repository, wanted, newest.as_deref());
        failed |= failing;
        report.restore = Some(run);
    }
    let text = serde_json::to_vec_pretty(&report).unwrap_or_default();
    if let Err(error) = atomic_write(&path, &text, 0o644) {
        complain(&format!(
            "The report could not be written to {}: {error}",
            path.display()
        ));
        return 1;
    }
    say(&format!("Report written to {}.", path.display()));
    u8::from(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_line_is_the_tools_last_word() {
        assert_eq!(
            last_line(&["created\nno errors were found\n\n", ""]),
            "no errors were found"
        );
        assert_eq!(
            last_line(&[
                "partial output\n",
                "Fatal: wrong password or no key found\n"
            ]),
            "Fatal: wrong password or no key found"
        );
        assert_eq!(last_line(&["", ""]), "");
        assert_eq!(
            last_line(&[
                r#"{"message_type":"exit_error","code":12,"message":"Fatal: wrong password or no key found"}"#
            ]),
            "Fatal: wrong password or no key found"
        );
        assert_eq!(last_line(&[&"x".repeat(500)]).len(), MAX_DETAIL);
    }

    #[test]
    fn a_repository_is_named_to_each_tool_in_its_own_way() {
        let given = Repository {
            tool: Tool::Restic,
            given: Some("/srv/restic".to_owned()),
        };
        assert_eq!(given.restic(), ["-r", "/srv/restic"]);
        assert_eq!(given.borg(Some("nightly")), "/srv/restic::nightly");
        let environment = Repository {
            tool: Tool::Borg,
            given: None,
        };
        assert_eq!(environment.restic(), Vec::<&str>::new());
        assert_eq!(environment.borg(None), "");
        assert_eq!(environment.borg(Some("nightly")), "::nightly");
    }
}
