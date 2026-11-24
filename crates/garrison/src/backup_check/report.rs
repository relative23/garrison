//! Which repository a run asks, and what it keeps of the report before
//! it: the place the tool takes, the last report as the collector reads it,
//! and its last check and restore where that report is of the same
//! repository.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use garrison_collector::backups::{MAX_REPORT, Report, Tool};
use garrison_core::files::{changed_only_by_trusted, read_json_with_metadata};
use garrison_core::json;

use super::Asked;
use crate::complain;

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

/// Where the repository is, as the tool takes it: `--repo`, else its
/// variable where that is not empty, else for restic what the file
/// `RESTIC_REPOSITORY_FILE` names holds, without the spaces and line ends
/// around it (measured on restic 0.19.1). Where nothing says where it is,
/// how the report names it instead.
pub(super) fn place(asked: &Asked, tool: Tool) -> Result<String, String> {
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
    let read = fs::File::open(&file)
        .and_then(|opened| opened.take(MAX_PLACE as u64 + 1).read_to_string(&mut held));
    match read {
        Ok(size) if size <= MAX_PLACE && !held.trim().is_empty() => Ok(held.trim().to_owned()),
        _ => Err(format!("(named in {})", file.display())),
    }
}

/// The last report where it is one of the repository this run asks: of the
/// same tool, under the same name and with the same ID as the tool gives
/// it. Of another repository, or of one this run cannot tell from another,
/// nothing is kept, since the card would show it as this repository's;
/// that is said where the report held a check or a restore. `name` is
/// `None` where nothing says where the repository is.
pub(super) fn kept(
    path: &Path,
    before: Report,
    tool: Tool,
    name: Option<&str>,
    id: Option<&str>,
) -> Option<Report> {
    let unknown = "is not known to be of this repository, since";
    let why = match (name, id, before.repository_id.as_deref()) {
        (None, _, _) => format!("{unknown} the command is not told where this one is"),
        (_, None, _) => format!("{unknown} {} gave no ID for it", tool.name()),
        (_, _, None) => "holds no repository ID".to_owned(),
        (Some(name), Some(id), Some(theirs)) => {
            if before.tool == tool && before.repository == name && theirs == id {
                return Some(before);
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
            "The last report, {}, {why}: its last integrity check and test restore are not kept.",
            path.display()
        ));
    }
    None
}
