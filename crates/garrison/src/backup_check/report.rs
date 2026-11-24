//! Which repository a run asks, and what it keeps of the report before
//! it: the place the tool takes, the last report as the collector reads it,
//! and its last check and restore where that report is of the same
//! repository.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use garrison_collector::backups::{MAX_REPORT, Report, Tool, named};
use garrison_core::files::{changed_only_by_trusted, read_json_with_metadata};
use garrison_core::json;
use rustix::fs::{FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;

use super::Asked;
use crate::complain;

/// The turn of one run of the report at `report`: the lock beside it,
/// `<report>.lock`, a file of this user's own that nobody else may open. A
/// run holds it from before it lists until its report is written, so that
/// it reads what the run before it wrote and never writes back a check or
/// a restore that a run which ended meanwhile replaced. One that finds it
/// held says so and waits.
pub(super) fn turn(report: &Path) -> Result<File, String> {
    let mut name = report.as_os_str().to_owned();
    name.push(".lock");
    let lock = PathBuf::from(name);
    // Root's rights mend a refusal for want of them, and nothing else.
    let failed = |what: String, error: std::io::Error| {
        let root = error.kind() == std::io::ErrorKind::PermissionDenied
            && !rustix::process::geteuid().is_root();
        let hint = if root {
            " Run `garrison backup-check` as root."
        } else {
            ""
        };
        format!("{what}: {error}.{hint}")
    };
    let taken = |error: Errno| {
        let what = format!("The report's lock {} cannot be taken", lock.display());
        failed(what, error.into())
    };
    if let Some(folder) = lock
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty())
    {
        fs::create_dir_all(folder).map_err(|error| {
            failed(
                format!("The report's folder {} cannot be made", folder.display()),
                error,
            )
        })?;
    }
    let flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let other = || {
        format!(
            "{} is no lock of `garrison backup-check`'s, but a link, another user's file or no \
             file: remove it, then run the command again.",
            lock.display()
        )
    };
    let file = File::from(
        match rustix::fs::open(&lock, flags, Mode::RUSR | Mode::WUSR) {
            Err(Errno::LOOP) => return Err(other()),
            opened => opened.map_err(taken)?,
        },
    );
    let status = rustix::fs::fstat(&file).map_err(taken)?;
    // Another user's file there, which they could hold, is no lock of ours.
    if FileType::from_raw_mode(status.st_mode) != FileType::RegularFile
        || status.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(other());
    }
    match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(Errno::WOULDBLOCK) => {
            complain(&format!(
                "Another `garrison backup-check` writes {}; this run waits until it has ended.",
                report.display()
            ));
            rustix::fs::flock(&file, FlockOperation::LockExclusive).map_err(taken)?;
        }
        Err(error) => return Err(taken(error)),
    }
    Ok(file)
}

/// The report the last run wrote, read as the collector reads it: no link
/// followed, nothing but a regular file opened, no more than a report's size
/// read, and none that a user other than root could have changed, since
/// `--report` may name a place others can write to.
pub(super) fn last_report(path: &Path) -> Option<Report> {
    // Only to say nothing where there is none yet.
    fs::symlink_metadata(path).ok()?;
    let read = read_json_with_metadata(path, MAX_REPORT);
    if read
        .as_ref()
        .is_some_and(|(_, metadata)| !changed_only_by_trusted(metadata))
    {
        complain(&format!(
            "The last report, {}, can be changed by users other than root: its last integrity \
             check and test restore are not kept.",
            path.display()
        ));
        return None;
    }
    let report = read.and_then(|(value, _)| json::object(value).ok());
    if report.is_none() {
        complain(&format!(
            "The last report, {}, cannot be read: it must be a file, not a link, of at most {} \
             KiB of valid JSON. Its last integrity check and test restore are not kept.",
            path.display(),
            MAX_REPORT / 1024
        ));
    }
    report
}

/// The most of the file `RESTIC_REPOSITORY_FILE` that is read as a place.
const MAX_PLACE: usize = 4096;

/// Where the repository is, as the tool is told: `--repo`, else its
/// variable where that is not empty, else for restic what the file
/// `RESTIC_REPOSITORY_FILE` names holds, without the spaces and line ends
/// around it (measured on restic 0.19.1). Where nothing says where it is,
/// how the report names it instead.
pub(super) fn given(asked: &Asked, tool: Tool) -> Result<String, String> {
    let variable = if tool == Tool::Restic {
        "RESTIC_REPOSITORY"
    } else {
        "BORG_REPO"
    };
    let given = asked.repo.clone().or_else(|| {
        std::env::var(variable)
            .ok()
            .filter(|named| !named.is_empty())
    });
    if let Some(given) = given {
        return Ok(given);
    }
    let Some(file) = std::env::var_os("RESTIC_REPOSITORY_FILE")
        .filter(|file| tool == Tool::Restic && !file.is_empty())
    else {
        return Err("(named in the tool's own configuration)".to_owned());
    };
    let file = PathBuf::from(file);
    // As restic does, through a link: the file is the backup job's own.
    let mut held = String::new();
    let read = File::open(&file)
        .and_then(|opened| opened.take(MAX_PLACE as u64 + 1).read_to_string(&mut held));
    match read {
        Ok(size) if size <= MAX_PLACE && !held.trim().is_empty() => Ok(held.trim().to_owned()),
        _ => Err(format!("(named in {})", file.display())),
    }
}

/// The folder on this host that a place names, where it names one: for
/// restic a name with `local:`, one that starts with a slash or one with no
/// colon at all, as restic 0.19.1 reads them (measured; any other name is
/// one of its backends or refused); for borg one with `file://` or neither
/// `ssh://` nor the `[user@]host:` of a repository elsewhere.
fn folder(tool: Tool, place: &str) -> Option<&str> {
    let (scheme, elsewhere) = match tool {
        Tool::Restic => ("local:", place.contains(':') && !place.starts_with('/')),
        Tool::Borg => (
            "file://",
            place.starts_with("ssh://")
                || place
                    .split_once(':')
                    .is_some_and(|(host, _)| !host.is_empty() && !host.contains('/')),
        ),
    };
    place.strip_prefix(scheme).or((!elsewhere).then_some(place))
}

/// The place in the form that every name of it reaches, which runs compare:
/// a folder on this host as the kernel resolves it, which is the folder the
/// tool opens, whatever slashes, dots, links or relative name lead there;
/// any other place, and a folder that is not there, as named, without a
/// password and without the slashes at its end, which neither tool reads.
fn reached(tool: Tool, place: &str) -> String {
    let folder = folder(tool, place);
    let real = folder
        .and_then(|folder| fs::canonicalize(folder).ok())
        .and_then(|real| real.into_os_string().into_string().ok());
    if let Some(real) = real {
        return real;
    }
    let named = named(folder.unwrap_or(place));
    match named.trim_end_matches('/') {
        "" => named,
        trimmed => trimmed.to_owned(),
    }
}

/// Where the repository is, in the form runs compare: borg's own location
/// of it where its listing gave one, which writes every name of a
/// repository elsewhere alike, else where the tool was told it is. `Err`
/// says how the report names a repository that nothing places.
pub(super) fn place(
    tool: Tool,
    given: Result<String, String>,
    location: Option<&str>,
) -> Result<String, String> {
    let place = match location {
        Some(location) => location.to_owned(),
        None => given?,
    };
    Ok(reached(tool, &place))
}

/// The last report where it is one of the repository this run asks: of the
/// same tool, at the same place, as [`place`] writes it, and with the same
/// ID as the tool gives it. A byte copy has the ID too, so the place tells
/// a copy elsewhere from this repository. Of another repository, or of one
/// this run cannot tell from another, nothing is kept, since the card would
/// show it as this repository's; that is said where the report held a
/// check or a restore. `name` is `None` where nothing places the repository.
pub(super) fn kept(
    path: &Path,
    before: Report,
    tool: Tool,
    name: Option<&str>,
    id: Option<&str>,
) -> Option<Report> {
    let unknown = "is not known to be of this repository, since";
    let mut fix = "";
    let why = match (name, id, before.repository_id.as_deref()) {
        (None, _, _) => format!("{unknown} the command is not told where this one is"),
        (_, None, _) => format!("{unknown} {} gave no ID for it", tool.name()),
        (_, _, None) => "holds no repository ID".to_owned(),
        (Some(name), Some(id), Some(theirs)) => {
            if before.tool == tool && before.repository == name && theirs == id {
                return Some(before);
            }
            if before.tool == tool && theirs == id {
                fix = " The same ID at another place is a copy, which needs a --report of its \
                       own; name one repository alike in every run.";
            }
            format!(
                "is of the {} repository {} (ID {theirs}), and this run asks the {} repository \
                 {name} (ID {id})",
                before.tool.name(),
                before.repository,
                tool.name()
            )
        }
    };
    if before.verify.is_some() || before.restore.is_some() {
        complain(&format!(
            "The last report, {}, {why}: its last integrity check and test restore are not \
             kept.{fix}",
            path.display()
        ));
    }
    None
}
