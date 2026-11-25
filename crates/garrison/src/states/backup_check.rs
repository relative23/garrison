//! The states of `garrison backup-check`: its refusals, what it says of a
//! run and of the report the run before it wrote. The report's own fields
//! are the collector's data, not states.

use std::fmt::Display;
use std::io;
use std::path::Path;

use crate::state::{State, states};

states! {
    pub(crate) fn unknown_tool() = "backup-check-unknown-tool":
        "The backup tool is restic or borg.";
    pub(crate) fn lock_other(lock: &Path) = "backup-check-lock-other":
        "{} is no lock of `garrison backup-check`'s, but a link, another user's file or no \
         file: remove it, then run the command again.", lock.display();
    pub(crate) fn waits(report: &Path) = "backup-check-waits":
        "Another `garrison backup-check` writes {}; this run waits until it has ended.",
        report.display();
    /// `problem`: the tool's own last words.
    pub(crate) fn unlisted(tool: &str, problem: &str) = "backup-check-unlisted":
        "{tool} did not list its snapshots: {problem}";
    /// `detail`: what the tool said of its integrity check.
    pub(crate) fn verified(detail: &str) = "backup-check-verified":
        "Integrity check: passed ({detail})";
    pub(crate) fn verify_failed(detail: &str) = "backup-check-verify-failed":
        "Integrity check: FAILED ({detail})";
    /// `detail`: what the test restore found.
    pub(crate) fn restored(detail: &str) = "backup-check-restored":
        "Restore test: passed ({detail})";
    /// `detail`: why the test restore failed.
    pub(crate) fn restore_failed(detail: &str) = "backup-check-restore-failed":
        "Restore test: FAILED ({detail})";
    pub(crate) fn not_removed(path: &Path, error: &io::Error) = "backup-check-not-removed":
        "{} could not be removed ({error}); it holds a copy of what the backup holds: remove \
         it as root with rm -r {}", path.display(), path.display();
    pub(crate) fn leftover_removed(copy: &Path) = "backup-check-leftover-removed":
        "Removed {}, a copy of restored data that an interrupted test restore left.",
        copy.display();
    pub(crate) fn leftover_kept(why: &State) = "backup-check-leftover-kept":
        "A copy that an interrupted test restore left: {why}";
    pub(crate) fn copy_kept(why: &State) = "backup-check-copy-kept":
        "This test restore's copy: {why}";
    pub(crate) fn report_foreign(report: &Path) = "backup-check-report-foreign":
        "The last report, {}, can be changed by users other than root: its last integrity \
         check and test restore are not kept.", report.display();
    pub(crate) fn report_unread(report: &Path, kib: usize) = "backup-check-report-unread":
        "The last report, {}, cannot be read: it must be a file, not a link, of at most {kib} \
         KiB of valid JSON. Its last integrity check and test restore are not kept.",
        report.display();
    pub(crate) fn unwritten(report: &Path, error: impl Display) = "backup-check-unwritten":
        "The report could not be written to {}: {error}", report.display();
    pub(crate) fn written(report: &Path) = "backup-check-written":
        "Report written to {}.", report.display();
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
