//! Reading a receipt, and why the card could not, with what mends it.

use std::fs::Metadata;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use garrison_core::files::{answered_by, open_regular_file, read_json_with_metadata};
use serde_json::Value;

use super::{MAX_DOCUMENT, Receipt};
use crate::providers::hidden::{self, Seen};
use crate::providers::ran::{SECONDS, silent};

impl Receipt {
    /// The receipt, a JSON object or list, and the metadata of the very file
    /// read, as its file system answers by `until`; or what the card says
    /// of why there is none.
    pub(super) fn read(&self, until: Instant) -> Result<(Value, Metadata), String> {
        let path = self.path.clone();
        match answered_by(until, move || read_json_with_metadata(&path, MAX_DOCUMENT)) {
            Ok(Some((document, metadata))) if document.is_object() || document.is_array() => {
                Ok((document, metadata))
            }
            Ok(_) => Err(self.unread(&hidden::seen(&self.path), until)),
            Err(error) => Err(self.unanswered(&error)),
        }
    }

    /// Why there is no receipt to read, with what mends it, as the looks at
    /// it answer by `until`, its path `seen` as this process sees it: a place
    /// that the collector's sandbox hides; none at its path, which a job of
    /// the operator's writes; a folder on the way that the collector's user
    /// may not search; a file it may not open, as one a job writes under
    /// umask 027 or 077; a link or no plain file; or a file too large or no
    /// JSON object or list. What a mount shows of another place of the host
    /// is named by that place.
    pub(super) fn unread(&self, seen: &Seen, until: Instant) -> String {
        let (path, seen) = (self.path.clone(), seen.clone());
        answered_by(until, move || why(&path, &seen))
            .unwrap_or_else(|error| self.unanswered(&error))
    }

    /// What the card says where the receipt could not be asked for: its
    /// file system gave no answer by the check's time, or the call failed.
    pub(super) fn unanswered(&self, error: &io::Error) -> String {
        let path = self.path.display();
        if silent(error) {
            format!(
                "The receipt at {path} could not be read: its file system did not answer within \
                 {SECONDS} seconds."
            )
        } else {
            format!("The receipt at {path} could not be read: {error}.")
        }
    }
}

/// Where a look at a path stops: the path as the links on the way lead, the
/// deepest folder of it that can be looked at, and the first link on the
/// way with where it leads, if there is one.
struct Stop {
    path: PathBuf,
    folder: PathBuf,
    link: Option<(PathBuf, PathBuf)>,
}

/// [`Stop`] for `path`, following up to eight links on the way.
fn stop(path: &Path) -> Stop {
    let mut path = path.to_path_buf();
    let mut link = None;
    for _ in 0..8 {
        let folder = path
            .ancestors()
            .skip(1)
            .find(|folder| std::fs::symlink_metadata(folder).is_ok())
            .unwrap_or(&path)
            .to_path_buf();
        let Ok(target) = std::fs::read_link(&folder) else {
            return Stop { path, folder, link };
        };
        // A link that names no root leads from the folder that holds it.
        let target = normal(&folder.parent().unwrap_or(Path::new("/")).join(target));
        let rest = path
            .strip_prefix(&folder)
            .map(Path::to_path_buf)
            .unwrap_or_default();
        link.get_or_insert_with(|| (folder, target.clone()));
        path = target.join(rest);
    }
    let folder = path.clone();
    Stop { path, folder, link }
}

/// `path` without its `.` and `..`, as far as the names alone tell.
fn normal(path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                normal.pop();
            }
            Component::CurDir => {}
            part => normal.push(part),
        }
    }
    normal
}

/// [`Receipt::unread`] for the receipt at `path`, as the file system answers.
fn why(path: &Path, seen: &Seen) -> String {
    let shown = path.display();
    let denied = |error: &io::Error| error.kind() == io::ErrorKind::PermissionDenied;
    let looked = std::fs::symlink_metadata(path);
    if let Err(error) = &looked
        && (denied(error) || error.kind() == io::ErrorKind::NotFound)
    {
        let stop = stop(path);
        // Where a link leads, that place is what is seen.
        let seen = match &stop.link {
            Some(_) => hidden::seen(&stop.path),
            None => seen.clone(),
        };
        // Neither a mode nor the job mends what the sandbox hides, and a
        // home folder, which the collector's unit hides, is opened to nobody.
        let home = denied(error)
            && hidden::HOMES
                .iter()
                .any(|home| stop.folder == Path::new(home));
        let place = match &seen {
            Seen::Hidden(place) => Some(place.clone()),
            Seen::Host | Seen::Bound { .. } => home.then(|| stop.folder.clone()),
        };
        if let Some(place) = place {
            let through = stop.link.as_ref().map_or_else(String::new, |(link, _)| {
                format!(", through the link {},", link.display())
            });
            return format!(
                "The receipt at {shown} lies{through} under {}, which the collector's unit hides \
                 from it: let the job write it where the collector sees it, as under /var/lib, \
                 and set `path` to it (docs/operator/checks.md, \"Paths the collector cannot \
                 see\").",
                place.display()
            );
        }
        if error.kind() == io::ErrorKind::NotFound {
            return format!(
                "No receipt at {shown}: the job that writes it has written none there."
            );
        }
        // Opening the folder to every user would open what else it holds.
        let leads = stop
            .link
            .as_ref()
            .map_or_else(String::new, |(link, target)| {
                format!(
                    "the link {} leads to {}, and ",
                    link.display(),
                    target.display()
                )
            });
        let mounted = seen.on_host(&stop.folder).map_or_else(String::new, |host| {
            format!(", a mount of the host's {}", host.display())
        });
        return format!(
            "The receipt at {shown} cannot be looked for: {leads}the collector's user may not \
             search the folder {}{mounted}; let the job write it where that user may search, \
             and set `path` to it.",
            stop.folder.display()
        );
    }
    match looked {
        Err(error) => format!("The receipt at {shown} cannot be looked for: {error}."),
        Ok(metadata) if metadata.is_symlink() => format!(
            "The receipt at {shown} is a link, which is not followed: let the job write the file \
             there itself."
        ),
        Ok(metadata) if !metadata.is_file() => {
            format!("The receipt at {shown} is no plain file: let the job write it there as one.")
        }
        // Opened as the read was, so that a FIFO put here since the look
        // above is not waited for.
        Ok(_) if open_regular_file(path).is_err_and(|error| denied(&error)) => {
            let file = seen.on_host(path).map_or_else(
                || shown.to_string(),
                |host| format!("{} on the host, which a mount shows there", host.display()),
            );
            format!(
                "The receipt at {shown} is there, but the collector's user may not open it: let \
                 the job write it with mode 0644 (chmod 0644 {file})."
            )
        }
        Ok(_) => format!(
            "The receipt at {shown} cannot be read: it must be at most {} KiB of JSON, an object \
             or a list.",
            MAX_DOCUMENT / 1024
        ),
    }
}
