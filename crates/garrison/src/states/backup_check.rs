//! The states of `garrison backup-check`: its refusals, what it says of a
//! run and of the report the run before it wrote. The report's own fields
//! are the collector's data, not states.

use std::fmt::Display;
use std::io;
use std::path::Path;

use crate::state::State;

pub(crate) fn unknown_tool() -> State {
    State::new(
        "backup-check-unknown-tool",
        "The backup tool is restic or borg.",
    )
}

/// What the system said of `what`; for an operator who is not root, that
/// root's rights mend a refusal for want of them.
pub(crate) fn io(what: impl Display, error: &io::Error) -> State {
    let hint = if error.kind() == io::ErrorKind::PermissionDenied
        && !rustix::process::geteuid().is_root()
    {
        " Run `garrison backup-check` as root."
    } else {
        ""
    };
    State::new("backup-check-io", format!("{what}: {error}.{hint}"))
}

pub(crate) fn lock_taken(lock: &Path, error: &io::Error) -> State {
    io(
        format_args!("The report's lock {} cannot be taken", lock.display()),
        error,
    )
}

pub(crate) fn folder_unmade(folder: &Path, error: &io::Error) -> State {
    io(
        format_args!("The report's folder {} cannot be made", folder.display()),
        error,
    )
}

pub(crate) fn lock_other(lock: &Path) -> State {
    State::new(
        "backup-check-lock-other",
        format!(
            "{} is no lock of `garrison backup-check`'s, but a link, another user's file or no \
             file: remove it, then run the command again.",
            lock.display()
        ),
    )
}

pub(crate) fn waits(report: &Path) -> State {
    State::new(
        "backup-check-waits",
        format!(
            "Another `garrison backup-check` writes {}; this run waits until it has ended.",
            report.display()
        ),
    )
}

/// What a listing found: `count` snapshots or archives, `newest` the date of
/// the newest.
pub(crate) fn listed(tool: &str, count: u64, newest: Option<&str>) -> State {
    let noun = if tool == "restic" {
        "snapshot"
    } else {
        "archive"
    };
    State::new(
        "backup-check-listed",
        format!(
            "{tool}: {count} {noun}{}, the newest of {}.",
            if count == 1 { "" } else { "s" },
            newest.unwrap_or("no date")
        ),
    )
}

/// `problem`: the tool's own last words.
pub(crate) fn unlisted(tool: &str, problem: &str) -> State {
    State::new(
        "backup-check-unlisted",
        format!("{tool} did not list its snapshots: {problem}"),
    )
}

/// `detail`: what the tool said of its integrity check.
pub(crate) fn verified(detail: &str) -> State {
    State::new(
        "backup-check-verified",
        format!("Integrity check: passed ({detail})"),
    )
}

pub(crate) fn verify_failed(detail: &str) -> State {
    State::new(
        "backup-check-verify-failed",
        format!("Integrity check: FAILED ({detail})"),
    )
}

/// `detail`: what the test restore found.
pub(crate) fn restored(detail: &str) -> State {
    State::new(
        "backup-check-restored",
        format!("Restore test: passed ({detail})"),
    )
}

/// `detail`: why the test restore failed.
pub(crate) fn restore_failed(detail: &str) -> State {
    State::new(
        "backup-check-restore-failed",
        format!("Restore test: FAILED ({detail})"),
    )
}

pub(crate) fn not_removed(path: &Path, error: &io::Error) -> State {
    State::new(
        "backup-check-not-removed",
        format!(
            "{} could not be removed ({error}); it holds a copy of what the backup holds: remove \
             it as root with rm -r {}",
            path.display(),
            path.display()
        ),
    )
}

pub(crate) fn leftover_removed(copy: &Path) -> State {
    State::new(
        "backup-check-leftover-removed",
        format!(
            "Removed {}, a copy of restored data that an interrupted test restore left.",
            copy.display()
        ),
    )
}

pub(crate) fn leftover_kept(why: &State) -> State {
    State::new(
        "backup-check-leftover-kept",
        format!("A copy that an interrupted test restore left: {why}"),
    )
}

pub(crate) fn copy_kept(why: &State) -> State {
    State::new(
        "backup-check-copy-kept",
        format!("This test restore's copy: {why}"),
    )
}

pub(crate) fn report_foreign(report: &Path) -> State {
    State::new(
        "backup-check-report-foreign",
        format!(
            "The last report, {}, can be changed by users other than root: its last integrity \
             check and test restore are not kept.",
            report.display()
        ),
    )
}

pub(crate) fn report_unread(report: &Path, kib: usize) -> State {
    State::new(
        "backup-check-report-unread",
        format!(
            "The last report, {}, cannot be read: it must be a file, not a link, of at most {kib} \
             KiB of valid JSON. Its last integrity check and test restore are not kept.",
            report.display()
        ),
    )
}

/// The last report is not known to be of the repository this run asks,
/// since nothing places that one ...
pub(crate) fn report_unplaced(report: &Path) -> State {
    State::new(
        "backup-check-report-unplaced",
        unknown(report, "the command is not told where this one is"),
    )
}

/// ... `tool` could not list it ...
pub(crate) fn report_unlisted(report: &Path, tool: &str) -> State {
    State::new(
        "backup-check-report-unlisted",
        unknown(report, &format!("{tool} could not list it")),
    )
}

/// ... or `tool` gave no ID for it.
pub(crate) fn report_unidentified(report: &Path, tool: &str) -> State {
    State::new(
        "backup-check-report-unidentified",
        unknown(report, &format!("{tool} gave no ID for it")),
    )
}

pub(crate) fn report_anonymous(report: &Path) -> State {
    State::new(
        "backup-check-report-anonymous",
        not_kept(report, "holds no repository ID", ""),
    )
}

/// The last report is of another repository: `theirs` and `ours` are each
/// one's tool, place and ID.
pub(crate) fn report_other(
    report: &Path,
    theirs: (&str, &str, &str),
    ours: (&str, &str, &str),
) -> State {
    State::new(
        "backup-check-report-other",
        not_kept(report, &other(theirs, ours), ""),
    )
}

/// The last report is of the repository with the same ID at another place:
/// a copy.
pub(crate) fn report_copy(
    report: &Path,
    theirs: (&str, &str, &str),
    ours: (&str, &str, &str),
) -> State {
    let fix = " The same ID at another place is a copy, which needs a --report of its own; name \
               one repository alike in every run.";
    State::new(
        "backup-check-report-copy",
        not_kept(report, &other(theirs, ours), fix),
    )
}

fn unknown(report: &Path, since: &str) -> String {
    let why = format!("is not known to be of this repository, since {since}");
    not_kept(report, &why, "")
}

fn other(theirs: (&str, &str, &str), ours: (&str, &str, &str)) -> String {
    format!(
        "is of the {} repository {} (ID {}), and this run asks the {} repository {} (ID {})",
        theirs.0, theirs.1, theirs.2, ours.0, ours.1, ours.2
    )
}

fn not_kept(report: &Path, why: &str, fix: &str) -> String {
    format!(
        "The last report, {}, {why}: its last integrity check and test restore are not kept.{fix}",
        report.display()
    )
}

pub(crate) fn unwritten(report: &Path, error: impl Display) -> State {
    State::new(
        "backup-check-unwritten",
        format!(
            "The report could not be written to {}: {error}",
            report.display()
        ),
    )
}

pub(crate) fn written(report: &Path) -> State {
    State::new(
        "backup-check-written",
        format!("Report written to {}.", report.display()),
    )
}
