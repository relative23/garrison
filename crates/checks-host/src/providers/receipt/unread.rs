//! Why the card could not read a receipt, and what mends it.

use std::path::Path;

use garrison_core::files::open_regular_file;

use super::{MAX_DOCUMENT, Receipt};
use crate::providers::hidden;

impl Receipt {
    /// Why there is no receipt to read, with what mends it: a place that the
    /// collector's sandbox hides, `hidden` where it hides one of the path;
    /// none at its path, which a job of the operator's writes; a folder on
    /// the way that the collector's user may not search; a file it may not
    /// open, as one a job writes under umask 027 or 077; a link or no plain
    /// file; or a file too large or no JSON object or list.
    pub(super) fn unread(&self, hidden: Option<&Path>) -> String {
        let path = self.path.display();
        let denied = |error: &std::io::Error| error.kind() == std::io::ErrorKind::PermissionDenied;
        let looked = std::fs::symlink_metadata(&self.path);
        // The deepest folder that can be looked at is the one that cannot be
        // searched, where one cannot be.
        let folder = looked.as_ref().is_err_and(denied).then(|| {
            self.path
                .ancestors()
                .skip(1)
                .find(|folder| std::fs::symlink_metadata(folder).is_ok())
                .unwrap_or(&self.path)
        });
        // Neither a mode nor the job mends what the sandbox hides, and a home
        // folder, which the collector's unit hides, is opened to nobody.
        let home =
            folder.filter(|folder| hidden::HOMES.iter().any(|home| *folder == Path::new(home)));
        if let Some(place) = hidden.or(home)
            && looked
                .as_ref()
                .is_err_and(|error| denied(error) || error.kind() == std::io::ErrorKind::NotFound)
        {
            return format!(
                "The receipt at {path} lies under {}, which the collector's unit hides from it: \
                 let the job write it where the collector sees it, as under /var/lib \
                 (docs/operator/checks.md, \"Paths the collector cannot see\").",
                place.display()
            );
        }
        match looked {
            Err(error) if denied(&error) => {
                let folder = folder.unwrap_or(&self.path).display();
                format!(
                    "The receipt at {path} cannot be looked for: the collector's user may not \
                     search the folder {folder}; let every user search it (chmod o+x {folder})."
                )
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                format!("The receipt at {path} cannot be looked for: {error}.")
            }
            Err(_) => {
                format!("No receipt at {path}: the job that writes it has written none there.")
            }
            Ok(metadata) if metadata.is_symlink() => format!(
                "The receipt at {path} is a link, which is not followed: let the job write the \
                 file there itself."
            ),
            Ok(metadata) if !metadata.is_file() => format!(
                "The receipt at {path} is no plain file: let the job write it there as one."
            ),
            // Opened as the read was, so that a FIFO put here since the
            // look above is not waited for.
            Ok(_) if open_regular_file(&self.path).is_err_and(|error| denied(&error)) => format!(
                "The receipt at {path} is there, but the collector's user may not open it: let \
                 the job write it with mode 0644 (chmod 0644 {path})."
            ),
            Ok(_) => format!(
                "The receipt at {path} cannot be read: it must be at most {} KiB of JSON, an \
                 object or a list.",
                MAX_DOCUMENT / 1024
            ),
        }
    }
}
