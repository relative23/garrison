//! The backup repository as `garrison backup-check` reported it: how old the
//! newest snapshot is, how large the repository, and whether the last
//! integrity check and the last test restore passed.
//!
//! The provider reads a report and never the repository, whose password
//! stays with root. A report counts only where nobody but root could have
//! written it.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use garrison_core::files::changed_only_by_trusted;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, State};
use garrison_core::time;

use crate::backups::{Report as Backup, Run, Tool};
use crate::context::{Collected, Context, Provider, Report};
use crate::options::{Checked, Options, fail};

const MAX_REPORT: u64 = 256 * 1024;
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

    /// The report, if it is there, small enough and root's own.
    fn read(&self) -> Result<Backup, String> {
        let metadata = fs::metadata(&self.path).map_err(|_| {
            format!(
                "no report at {}; `garrison backup-check {}` writes it",
                self.path.display(),
                self.tool.name()
            )
        })?;
        if !changed_only_by_trusted(&metadata) {
            return Err(
                "users other than root can change the report; it is not trusted".to_owned(),
            );
        }
        if metadata.len() > MAX_REPORT {
            return Err("the report is larger than a report is".to_owned());
        }
        let data = fs::read(&self.path).map_err(|error| error.to_string())?;
        let report: Backup =
            serde_json::from_slice(&data).map_err(|_| "the file is no report of backup-check")?;
        if report.tool != self.tool {
            return Err(format!("the report is one of {}", report.tool.name()));
        }
        Ok(report)
    }

    /// What a check or a restore that is expected every `days` days says.
    /// What the times of the newest snapshot and of the report say against
    /// the repository, where they say anything.
    fn by_time(
        &self,
        context: &Context<'_>,
        newest: Option<time::Timestamp>,
        listed: Option<time::Timestamp>,
        noun: &str,
    ) -> Option<(State, String)> {
        let now = context.now.as_second();
        let limit = self.max_age_hours * HOUR;
        let Some(newest) = newest else {
            return Some((State::Failed, format!("The repository holds no {noun}.")));
        };
        if now - newest.as_second() > limit {
            return Some((
                State::Warning,
                format!(
                    "The newest {noun} is older than {} hours.",
                    self.max_age_hours
                ),
            ));
        }
        // A time ahead of this host's clock is no fresh one.
        let from_the_future = ahead(context, newest, &format!("newest {noun}"))
            .or_else(|| listed.and_then(|listed| ahead(context, listed, "report")));
        if let Some(finding) = from_the_future {
            return Some((State::Warning, finding));
        }
        // A report that is no longer written says nothing of today.
        listed
            .is_none_or(|listed| now - listed.as_second() > limit)
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

    fn judged(
        context: &Context<'_>,
        what: &str,
        run: Option<&Run>,
        days: i64,
        state: &mut State,
        findings: &mut Vec<String>,
    ) {
        match run {
            Some(run) if !run.ok => {
                *state = State::Failed;
                findings.push(format!("The last {what} failed: {}.", run.detail));
            }
            Some(run) if days > 0 => {
                let age = time::parse(&run.at).map(|at| context.now.as_second() - at.as_second());
                if age.is_none_or(|age| age > days * DAY) && *state != State::Failed {
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

/// The card's fields: the repository, its snapshots and the two kinds of run.
fn fields(report: &Backup, noun: &str) -> Vec<Field> {
    let run = |run: Option<&Run>| run.map(|run| if run.ok { "passed" } else { "failed" });
    let snapshots = report.snapshots.as_ref();
    vec![
        Field::text("Repository", report.repository.clone()),
        Field::new(
            format!("Newest {noun}"),
            snapshots.and_then(|found| found.newest.clone()),
            Format::Datetime,
        ),
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
        Field::new(
            "Listed",
            snapshots.map(|found| found.at.clone()),
            Format::Datetime,
        ),
        Field::text("Last integrity check", run(report.verify.as_ref())),
        Field::new(
            "Checked",
            report.verify.as_ref().map(|run| run.at.clone()),
            Format::Datetime,
        ),
        Field::text("Last test restore", run(report.restore.as_ref())),
        Field::new(
            "Restored",
            report.restore.as_ref().map(|run| run.at.clone()),
            Format::Datetime,
        ),
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

    fn collect(&self, context: &Context<'_>) -> Collected {
        let (noun, title) = match self.tool {
            Tool::Restic => ("snapshot", "restic repository"),
            Tool::Borg => ("archive", "borg repository"),
        };
        let base = |state| {
            Observation::new(
                format!("backup-check.{}", self.tool.name()),
                self.name(),
                title,
                self.modules.iter().copied(),
                Evidence::Receipt,
                state,
                context.checked_at(),
                self.path.display().to_string(),
            )
        };
        let report = match self.read() {
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
        match (&report.snapshots, &report.problem) {
            (_, Some(problem)) => {
                state = State::Failed;
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
                let newest = snapshots.newest.as_deref().and_then(time::parse);
                let listed = time::parse(&snapshots.at);
                if let Some((by_time, finding)) = self.by_time(context, newest, listed, noun) {
                    state = by_time;
                    findings.push(finding);
                }
            }
        }
        Self::judged(
            context,
            "integrity check",
            report.verify.as_ref(),
            self.verify_days,
            &mut state,
            &mut findings,
        );
        Self::judged(
            context,
            "test restore",
            report.restore.as_ref(),
            self.restore_days,
            &mut state,
            &mut findings,
        );
        let observation = base(state)?
            .with_scope(
                "What the backup tool said of its repository when `garrison backup-check` last asked \
                 it. A test restore proves that the newest snapshot can be read with the password; \
                 it does not compare the restored files with the originals.",
            )
            .with_fields(fields(&report, noun))
            .with_findings(findings)
            .with_max_age(900);
        Ok(Report::of(observation))
    }
}

#[cfg(test)]
mod tests;
