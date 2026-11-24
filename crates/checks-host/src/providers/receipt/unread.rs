//! Reading a receipt, and why the card could not, with what mends it.

use std::fs::Metadata;
use std::io;
use std::path::Path;
use std::time::Instant;

use garrison_core::files::{answered_by, open_regular_file, read_json_with_metadata};
use serde_json::Value;

use super::{MAX_DOCUMENT, Receipt};
use crate::providers::hidden;
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
            Ok(_) => Err(self.unread(hidden::place(&self.path).as_deref(), until)),
            Err(error) => Err(self.unanswered(&error)),
        }
    }

    /// Why there is no receipt to read, with what mends it, as the looks at
    /// it answer by `until`: a place that the collector's sandbox hides,
    /// `hidden` where it hides one of the path; none at its path, which a
    /// job of the operator's writes; a folder on the way that the
    /// collector's user may not search; a file it may not open, as one a job
    /// writes under umask 027 or 077; a link or no plain file; or a file too
    /// large or no JSON object or list.
    pub(super) fn unread(&self, hidden: Option<&Path>, until: Instant) -> String {
        let (path, hidden) = (self.path.clone(), hidden.map(Path::to_path_buf));
        answered_by(until, move || why(&path, hidden.as_deref()))
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

/// [`Receipt::unread`] for the receipt at `path`, as the file system answers.
fn why(path: &Path, hidden: Option<&Path>) -> String {
    let shown = path.display();
    let denied = |error: &io::Error| error.kind() == io::ErrorKind::PermissionDenied;
    let looked = std::fs::symlink_metadata(path);
    // The deepest folder that can be looked at is the one that cannot be
    // searched, where one cannot be.
    let folder = looked.as_ref().is_err_and(denied).then(|| {
        path.ancestors()
            .skip(1)
            .find(|folder| std::fs::symlink_metadata(folder).is_ok())
            .unwrap_or(path)
    });
    // Neither a mode nor the job mends what the sandbox hides, and a home
    // folder, which the collector's unit hides, is opened to nobody.
    let home = folder.filter(|folder| hidden::HOMES.iter().any(|home| *folder == Path::new(home)));
    if let Some(place) = hidden.or(home)
        && looked
            .as_ref()
            .is_err_and(|error| denied(error) || error.kind() == io::ErrorKind::NotFound)
    {
        return format!(
            "The receipt at {shown} lies under {}, which the collector's unit hides from it: \
             let the job write it where the collector sees it, as under /var/lib \
             (docs/operator/checks.md, \"Paths the collector cannot see\").",
            place.display()
        );
    }
    match looked {
        Err(error) if denied(&error) => {
            let folder = folder.unwrap_or(path).display();
            format!(
                "The receipt at {shown} cannot be looked for: the collector's user may not \
                 search the folder {folder}; let every user search it (chmod o+x {folder})."
            )
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            format!("The receipt at {shown} cannot be looked for: {error}.")
        }
        Err(_) => {
            format!("No receipt at {shown}: the job that writes it has written none there.")
        }
        Ok(metadata) if metadata.is_symlink() => format!(
            "The receipt at {shown} is a link, which is not followed: let the job write the file \
             there itself."
        ),
        Ok(metadata) if !metadata.is_file() => {
            format!("The receipt at {shown} is no plain file: let the job write it there as one.")
        }
        // Opened as the read was, so that a FIFO put here since the look
        // above is not waited for.
        Ok(_) if open_regular_file(path).is_err_and(|error| denied(&error)) => format!(
            "The receipt at {shown} is there, but the collector's user may not open it: let the \
             job write it with mode 0644 (chmod 0644 {shown})."
        ),
        Ok(_) => format!(
            "The receipt at {shown} cannot be read: it must be at most {} KiB of JSON, an object \
             or a list.",
            MAX_DOCUMENT / 1024
        ),
    }
}
