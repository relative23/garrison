//! `garrison backup-check restic|borg`: ask the backup tool about its
//! repository and write the answer down for the collector.
//!
//! Run it as root from the backup job's own unit, with that job's
//! environment (`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE`, `BORG_REPO`,
//! `BORG_PASSPHRASE` and the like): the command adds no secret of its own
//! and keeps none. Every run lists the snapshots and reads the repository's
//! size. `--verify` also runs the tool's integrity check, `--restore PATH`
//! restores that path from the newest snapshot into a directory of its own
//! and removes it again. The report keeps the last check and the last
//! restore until the next one.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use garrison_collector::backups::{
    Report, Run, Snapshots, Tool, borg_archives, borg_size, named, restic_size, restic_snapshots,
};
use garrison_core::files::atomic_write;
use garrison_core::time;

use crate::{complain, say};

/// Where the reports go, one file for each tool.
pub(crate) const REPORTS: &str = "/var/lib/garrison/backup-check";
/// Restores go to disk, not into `/tmp`, which may be memory.
const RESTORES: &str = "/var/tmp";
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

/// The files below `directory` and their bytes; links are not followed.
fn restored(directory: &Path) -> (u64, u64) {
    let (mut files, mut bytes) = (0, 0);
    let mut open = vec![directory.to_path_buf()];
    while let Some(next) = open.pop() {
        for entry in fs::read_dir(&next).into_iter().flatten().flatten() {
            let Ok(kind) = entry.metadata().map(|_| entry.file_type()) else {
                continue;
            };
            match kind {
                Ok(kind) if kind.is_dir() => open.push(entry.path()),
                Ok(kind) if kind.is_file() => {
                    files += 1;
                    bytes += entry.metadata().map_or(0, |metadata| metadata.len());
                }
                _ => {}
            }
        }
    }
    (files, bytes)
}

/// A directory of its own for one restore, readable by root alone.
fn restore_directory() -> Result<PathBuf, String> {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|error| error.to_string())?;
    let name = garrison_core::hex::encode(&random);
    let path = Path::new(RESTORES).join(format!("garrison-restore-{name}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
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

    /// The snapshots and the size, and for borg the newest archive's name.
    fn snapshots(&self) -> Result<(Snapshots, Option<String>), String> {
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
                Ok((
                    Snapshots {
                        at,
                        count,
                        newest,
                        size_bytes,
                    },
                    None,
                ))
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
                Ok((
                    Snapshots {
                        at,
                        count,
                        newest,
                        size_bytes,
                    },
                    name,
                ))
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

    /// Restore `path` from the newest snapshot into a directory of its own,
    /// count what arrived and remove it again.
    fn restore(&self, path: &str, newest: Option<&str>) -> Run {
        let at = now();
        let failed = |detail: String| Run {
            at: at.clone(),
            ok: false,
            detail,
        };
        let directory = match restore_directory() {
            Ok(directory) => directory,
            Err(error) => return failed(error),
        };
        let ran = match self.tool {
            Tool::Restic => {
                let target = directory.display().to_string();
                let mut arguments = self.restic();
                arguments.extend([
                    "restore",
                    "latest",
                    "--no-lock",
                    "--target",
                    &target,
                    "--include",
                    path,
                ]);
                run(self.tool, &arguments, None)
            }
            Tool::Borg => match newest {
                Some(newest) => {
                    // borg restores into the directory it runs in, and names
                    // paths without their first slash.
                    let archive = self.borg(Some(newest));
                    run(
                        self.tool,
                        &["extract", &archive, path.trim_start_matches('/')],
                        Some(&directory),
                    )
                }
                None => Ran {
                    ok: false,
                    stdout: String::new(),
                    last: "the repository has no archive".to_owned(),
                },
            },
        };
        let (files, bytes) = restored(&directory);
        let _ = fs::remove_dir_all(&directory);
        if !ran.ok {
            return failed(ran.last);
        }
        if files == 0 {
            return failed(format!(
                "{path} was not in the newest snapshot: nothing was restored"
            ));
        }
        Run {
            at,
            ok: true,
            detail: format!("{path}: {files} files, {bytes} bytes"),
        }
    }
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
    // What the last run wrote stays, where this one does not run that part.
    let before: Option<Report> = fs::read(&path)
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok());
    let variable = if tool == Tool::Restic {
        "RESTIC_REPOSITORY"
    } else {
        "BORG_REPO"
    };
    let known = asked.repo.clone().or_else(|| std::env::var(variable).ok());
    let repository = Repository {
        tool,
        given: asked.repo.clone(),
    };
    let mut report = Report {
        tool,
        repository: named(
            known
                .as_deref()
                .unwrap_or("(named in the tool's own configuration)"),
        ),
        snapshots: None,
        problem: None,
        verify: before.as_ref().and_then(|before| before.verify.clone()),
        restore: before.as_ref().and_then(|before| before.restore.clone()),
    };
    let mut failed = false;
    let mut newest = None;
    match repository.snapshots() {
        Ok((snapshots, name)) => {
            let noun = if tool == Tool::Restic {
                "snapshot"
            } else {
                "archive"
            };
            say(&format!(
                "{}: {} {noun}{}, the newest of {}.",
                tool.name(),
                snapshots.count,
                if snapshots.count == 1 { "" } else { "s" },
                snapshots.newest.as_deref().unwrap_or("no date")
            ));
            report.snapshots = Some(snapshots);
            newest = name;
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
        let run = repository.restore(wanted, newest.as_deref());
        say(&format!(
            "Restore test: {} ({})",
            if run.ok { "passed" } else { "FAILED" },
            run.detail
        ));
        failed |= !run.ok;
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
    fn what_a_restore_brought_is_counted_without_following_links() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("data/mail")).unwrap();
        fs::write(directory.path().join("data/mail/a.txt"), "hello\n").unwrap();
        fs::write(directory.path().join("data/b.bin"), [0u8; 100]).unwrap();
        std::os::unix::fs::symlink("/etc", directory.path().join("data/link")).unwrap();
        assert_eq!(restored(directory.path()), (2, 106));
        assert_eq!(restored(&directory.path().join("missing")), (0, 0));
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
