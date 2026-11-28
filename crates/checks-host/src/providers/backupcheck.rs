//! The backup repository as `garrison backup-check` reported it: how old the
//! newest snapshot is, how large the repository, and whether the last
//! integrity check and the last test restore passed.
//!
//! The provider reads a report and never the repository, whose password
//! stays with root. A report counts only where nobody but root could have
//! written it.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use garrison_core::files::{answered_by, changed_only_by_trusted, read_json_with_metadata};
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, Required, State};
use garrison_core::{json, time};

use crate::backups::{MAX_REPORT, Report as Backup, Run, Tool};
use crate::context::{Collected, Context, HostPath, Provider, Report, Use};
use crate::options::{Checked, Options, fail};
use crate::providers::hidden::{self, Seen};
use crate::providers::ran::{SECONDS, patience, silent};

/// The place under which the collector's unit hides the report at `path`,
/// seen as `seen`, where the look at it failed with `error` for that: the
/// report is not found or not to be looked at there.
fn hidden_under(path: &Path, seen: &Seen, error: &io::Error) -> Option<PathBuf> {
    let denied = error.kind() == io::ErrorKind::PermissionDenied;
    if !denied && error.kind() != io::ErrorKind::NotFound {
        return None;
    }
    let stop = hidden::stop(path);
    stop.hidden_under(&stop.seen(seen), denied)
}

const HOUR: i64 = 3600;
const DAY: i64 = 86_400;

#[derive(Debug)]
pub struct BackupCheck {
    tool: Tool,
    path: PathBuf,
    modules: BTreeSet<ModuleId>,
    /// The newest snapshot may be this old.
    max_age_hours: i64,
    /// An integrity check is expected this often; 0 expects none.
    verify_days: i64,
    /// A test restore is expected this often; 0 expects none.
    restore_days: i64,
}

impl BackupCheck {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(
            raw,
            &[
                "tool",
                "path",
                "modules",
                "max_age_hours",
                "verify_days",
                "restore_days",
            ],
        )?;
        let name = options.text("tool", Some("restic"))?;
        let Some(tool) = Tool::named(&name) else {
            return fail("providers[backup-check].tool is restic or borg");
        };
        let default = format!("/var/lib/garrison/backup-check/{}.json", tool.name());
        Ok(BackupCheck {
            tool,
            path: options.path("path", Some(&default))?,
            modules: options.modules(&["backups"])?,
            max_age_hours: options.integer("max_age_hours", 30, 1, 24 * 366)?,
            verify_days: options.integer("verify_days", 0, 0, 366)?,
            restore_days: options.integer("restore_days", 0, 0, 366)?,
        })
    }

    /// The report, if it is there, small enough and root's own, as its file
    /// system answers by `until`, its path `seen` as this process sees it.
    /// It is read as `receipt` reads its file: no link followed, no file
    /// that is not a regular one, at most `MAX_REPORT` bytes of strict
    /// JSON, and the owner and mode of the very file that was read.
    fn read(&self, until: Instant, seen: &Seen) -> Result<Backup, String> {
        let (path, seen) = (self.path.clone(), seen.clone());
        // The look says which of the two it is; the read decides. Both ask
        // the report's file system, which may give no answer.
        let asked = answered_by(until, move || match fs::symlink_metadata(&path) {
            Err(error) => Err(hidden_under(&path, &seen, &error)),
            Ok(_) => Ok(read_json_with_metadata(&path, MAX_REPORT)),
        });
        let shown = self.path.display();
        let read = match asked {
            Err(error) if silent(&error) => {
                return Err(format!(
                    "the report at {shown} could not be read: its file system did not answer \
                     within {SECONDS} seconds"
                ));
            }
            Err(error) => return Err(format!("the report at {shown} could not be read: {error}")),
            // Writing it again where it was mends nothing there.
            Ok(Err(Some(place))) => {
                return Err(format!(
                    "the report at {shown} lies under {}, which the collector's unit hides from \
                     it: let `garrison backup-check {} --report FILE` write it where the \
                     collector sees it, as under /var/lib/garrison/backup-check, and set `path` \
                     to that file (docs/operator/checks.md, \"Paths the collector cannot see\")",
                    place.display(),
                    self.tool.name()
                ));
            }
            Ok(Err(None)) => {
                return Err(format!(
                    "no report at {shown}; `garrison backup-check {}` writes it",
                    self.tool.name()
                ));
            }
            Ok(Ok(read)) => read,
        };
        let Some((value, metadata)) = read else {
            return Err(format!(
                "the report cannot be read: it must be a file, not a link, of at most {} KiB of \
                 valid JSON",
                MAX_REPORT / 1024
            ));
        };
        if !changed_only_by_trusted(&metadata) {
            return Err(
                "users other than root can change the report; it is not trusted".to_owned(),
            );
        }
        // An earlier release wrote no repository ID, and kept a check and a
        // restore whatever repository they were of: neither is shown.
        let earlier = value.get("repositoryId").is_none();
        let mut report: Backup =
            json::object(value).map_err(|_| "the file is no report of backup-check")?;
        if report.tool != self.tool {
            return Err(format!("the report is one of {}", report.tool.name()));
        }
        if earlier {
            report.verify = None;
            report.restore = None;
        }
        Ok(report)
    }

    /// What the times of the newest snapshot and of the report say against
    /// the repository, where they say anything: `newest` as the report
    /// gives it, `None` for a repository without one. A time that does not
    /// read judges nothing.
    fn by_time(
        &self,
        context: &Context<'_>,
        newest: Option<&str>,
        listed: Option<time::Timestamp>,
        noun: &str,
    ) -> Option<(State, String)> {
        let now = context.now.as_second();
        let limit = self.max_age_hours * HOUR;
        let Some(newest) = newest else {
            return Some((State::Failed, format!("The repository holds no {noun}.")));
        };
        let newest = time::parse(newest);
        if let Some(newest) = newest
            && now - newest.as_second() > limit
        {
            return Some((
                State::Warning,
                format!(
                    "The newest {noun} is older than {} hours.",
                    self.max_age_hours
                ),
            ));
        }
        // A time ahead of this host's clock is no fresh one.
        let from_the_future = newest
            .and_then(|newest| ahead(context, newest, &format!("newest {noun}")))
            .or_else(|| listed.and_then(|listed| ahead(context, listed, "report")));
        if let Some(finding) = from_the_future {
            return Some((State::Warning, finding));
        }
        // A report that is no longer written says nothing of today.
        listed
            .is_some_and(|listed| now - listed.as_second() > limit)
            .then(|| {
                (
                    State::Warning,
                    format!(
                        "The report itself is older than {} hours: `garrison backup-check` no \
                         longer runs.",
                        self.max_age_hours
                    ),
                )
            })
    }

    /// `failed` counts the findings that make the card failed, which come
    /// first, before one that alone would make it a warning: a notification
    /// carries the first finding.
    fn judged(
        context: &Context<'_>,
        what: &str,
        run: Option<&Run>,
        days: i64,
        (state, failed): (&mut State, &mut usize),
        findings: &mut Vec<String>,
    ) {
        match run {
            Some(run) if !run.ok => {
                *state = State::Failed;
                findings.insert(*failed, format!("The last {what} failed: {}.", run.detail));
                *failed += 1;
            }
            Some(run) if days > 0 => {
                let age = time::parse(&run.at).map(|at| context.now.as_second() - at.as_second());
                // A time that does not read judges nothing.
                if age.is_some_and(|age| age > days * DAY) && *state != State::Failed {
                    *state = State::Warning;
                    findings.push(format!("The last {what} is older than {days} days."));
                }
            }
            None if days > 0 && *state != State::Failed => {
                *state = State::Warning;
                findings.push(format!(
                    "No {what} has been reported; one is expected every {days} days."
                ));
            }
            _ => {}
        }
    }
}

/// Two clocks may differ by this many seconds before a time counts as one
/// from the future.
const AHEAD: i64 = 300;

/// What to say of a time that lies ahead of this host's clock: it is no
/// fresh one, since a clock is wrong, and nothing is known of its age.
fn ahead(context: &Context<'_>, at: time::Timestamp, what: &str) -> Option<String> {
    let seconds = at.as_second() - context.now.as_second();
    (seconds > AHEAD).then(|| {
        format!(
            "The {what} is dated {} minutes ahead of this host's clock; one of the two clocks \
             is wrong, so its age is not known.",
            seconds / 60
        )
    })
}

/// A time of the report as the card shows it, one instant for every viewer:
/// with its offset, as written; one without, which a browser reads in its
/// own time zone, or that is no time, is not shown, and `unshown` says so.
fn shown(label: &str, at: Option<&str>, unshown: &mut Vec<String>) -> Option<String> {
    let at = at?;
    let written = time::parse_written(at).map(time::isoformat_written);
    if written.is_none() {
        unshown.push(format!(
            "{label} is not shown: {at:?} is no time with its offset, such as \
             2026-11-17T03:00:00Z."
        ));
    }
    written
}

/// The card's fields: the repository, its snapshots and the two kinds of run.
fn fields(report: &Backup, noun: &str, unshown: &mut Vec<String>) -> Vec<Field> {
    let run = |run: Option<&Run>| run.map(|run| if run.ok { "passed" } else { "failed" });
    let snapshots = report.snapshots.as_ref();
    let newest = format!("Newest {noun}");
    let newest_at = shown(
        &newest,
        snapshots.and_then(|found| found.newest.as_deref()),
        unshown,
    );
    let listed = shown("Listed", snapshots.map(|found| found.at.as_str()), unshown);
    let checked = shown(
        "Checked",
        report.verify.as_ref().map(|run| run.at.as_str()),
        unshown,
    );
    let restored = shown(
        "Restored",
        report.restore.as_ref().map(|run| run.at.as_str()),
        unshown,
    );
    vec![
        Field::text("Repository", report.repository.clone()),
        Field::new(newest, newest_at, Format::Datetime),
        Field::new(
            format!("{}s", noun[..1].to_uppercase() + &noun[1..]),
            snapshots.map(|found| found.count),
            Format::Number,
        ),
        Field::new(
            "Stored size",
            snapshots.and_then(|found| found.size_bytes),
            Format::Bytes,
        ),
        Field::new("Listed", listed, Format::Datetime),
        Field::text("Last integrity check", run(report.verify.as_ref())),
        Field::new("Checked", checked, Format::Datetime),
        Field::text("Last test restore", run(report.restore.as_ref())),
        Field::new("Restored", restored, Format::Datetime),
        Field::text(
            "What was restored",
            report
                .restore
                .as_ref()
                .filter(|run| run.ok)
                .map(|run| run.detail.clone()),
        ),
    ]
}

impl Provider for BackupCheck {
    fn name(&self) -> &'static str {
        "backup-check"
    }

    fn ids(&self) -> Vec<String> {
        vec![format!("backup-check.{}", self.tool.name())]
    }

    fn paths(&self) -> Vec<HostPath<'_>> {
        vec![HostPath {
            option: "path",
            path: &self.path,
            used: Use::Reads,
        }]
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let (noun, title) = match self.tool {
            Tool::Restic => ("snapshot", "restic repository"),
            Tool::Borg => ("archive", "borg repository"),
        };
        let base = |state| {
            Observation::new(Required {
                id: &format!("backup-check.{}", self.tool.name()),
                provider: self.name(),
                title,
                modules: self.modules.iter().copied(),
                evidence: Evidence::Receipt,
                state,
                checked_at: &context.checked_at(),
                source: &self.path.display().to_string(),
            })
        };
        let report = match self.read(patience(), &hidden::seen(&self.path)) {
            Ok(report) => report,
            Err(reason) => {
                let unknown = base(State::Unknown)?
                    .with_findings(vec![format!(
                        "The repository's state is not known: {reason}."
                    )])
                    .with_max_age(900);
                return Ok(Report::of(unknown));
            }
        };
        let mut state = State::Ok;
        let mut findings = Vec::new();
        let mut failed = 0;
        match (&report.snapshots, &report.problem) {
            (_, Some(problem)) => {
                state = State::Failed;
                failed = 1;
                findings.push(format!(
                    "{} could not list the repository: {problem}.",
                    self.tool.name()
                ));
            }
            (None, None) => {
                state = State::Unknown;
                findings.push("The report holds no list of the repository.".to_owned());
            }
            (Some(snapshots), None) => {
                let listed = time::parse(&snapshots.at);
                let newest = snapshots.newest.as_deref();
                if let Some((by_time, finding)) = self.by_time(context, newest, listed, noun) {
                    state = by_time;
                    failed = usize::from(by_time == State::Failed);
                    findings.push(finding);
                }
            }
        }
        Self::judged(
            context,
            "integrity check",
            report.verify.as_ref(),
            self.verify_days,
            (&mut state, &mut failed),
            &mut findings,
        );
        Self::judged(
            context,
            "test restore",
            report.restore.as_ref(),
            self.restore_days,
            (&mut state, &mut failed),
            &mut findings,
        );
        // A time the card would judge that does not read leaves its age, and
        // the repository's state, not known.
        let unread = |at: Option<&str>| at.is_some_and(|at| time::parse(at).is_none());
        let unjudged = report.snapshots.as_ref().is_some_and(|found| {
            unread(found.newest.as_deref()) || unread(Some(found.at.as_str()))
        }) || (self.verify_days > 0
            && unread(report.verify.as_ref().map(|run| run.at.as_str())))
            || (self.restore_days > 0
                && unread(report.restore.as_ref().map(|run| run.at.as_str())));
        if unjudged && state == State::Ok {
            state = State::Unknown;
        }
        let mut unshown = Vec::new();
        let fields = fields(&report, noun, &mut unshown);
        findings.extend(unshown);
        let observation = base(state)?
            .with_scope(
                "What the backup tool said of its repository when `garrison backup-check` last asked \
                 it. A test restore proves that the newest snapshot can be read with the password; \
                 it does not compare the restored files with the originals.",
            )
            .with_fields(fields)
            .with_findings(findings)
            .with_max_age(900);
        Ok(Report::of(observation))
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unseen_tests;
