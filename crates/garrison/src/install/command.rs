//! The `garrison` command in the search path: a link in `/usr/bin` to the
//! running release, so that `sudo garrison doctor` works as the messages and
//! the guides write it.
//!
//! `/usr/local/bin` would be the place for software a host's administrator
//! installs, but sudo on the RHEL family searches neither it nor
//! `/usr/local/sbin`. The link is the only thing Garrison puts into `/usr`.
//! Something else of that name is left alone, and so is a `/usr` that cannot
//! be written: the installation does not depend on the link.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::BASE;

pub(super) const LINK: &str = "/usr/bin/garrison";

/// Where the link points: through `current`, so it follows every upgrade
/// and rollback.
fn target() -> String {
    format!("{BASE}/current/bin/garrison")
}

/// Whether `link` is the link an installer made.
pub(super) fn ours(link: &Path) -> bool {
    fs::read_link(link).is_ok_and(|found| found == Path::new(&target()))
}

/// Make the link at `link`. `Err` says why there is none, for the operator
/// to read; it never ends an installation.
pub(super) fn link(link: &Path) -> Result<(), String> {
    if ours(link) {
        return Ok(());
    }
    let full = target();
    match fs::symlink_metadata(link) {
        Ok(_) => Err(format!(
            "{} is something else and was left alone; Garrison's command is {full}.",
            link.display()
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            symlink(&full, link).map_err(|error| {
                format!(
                    "{} could not be made ({error}); Garrison's command is {full}.",
                    link.display()
                )
            })
        }
        Err(error) => Err(format!(
            "{}: {error}; Garrison's command is {full}.",
            link.display()
        )),
    }
}

/// How to call the command on this host: by its name where the link is
/// there, otherwise by its path.
pub(super) fn name() -> String {
    if ours(Path::new(LINK)) {
        "garrison".to_owned()
    } else {
        target()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_link_is_made_once_and_points_through_current() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("garrison");
        assert!(!ours(&path));
        assert_eq!(link(&path), Ok(()));
        assert_eq!(
            fs::read_link(&path).unwrap(),
            Path::new("/opt/garrison/current/bin/garrison")
        );
        assert!(ours(&path));
        // A second installation finds it and changes nothing.
        assert_eq!(link(&path), Ok(()));
    }

    #[test]
    fn something_else_of_that_name_is_left_alone() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("garrison");
        fs::write(&file, "another program").unwrap();
        let refused = link(&file).unwrap_err();
        assert!(refused.contains("is something else"), "{refused}");
        assert!(refused.ends_with("Garrison's command is /opt/garrison/current/bin/garrison."));
        assert_eq!(fs::read_to_string(&file).unwrap(), "another program");
        assert!(!ours(&file));

        // A link of someone else's, even a broken one, is not ours either.
        let other = directory.path().join("other");
        symlink("/nowhere/garrison", &other).unwrap();
        assert!(link(&other).is_err());
        assert_eq!(
            fs::read_link(&other).unwrap(),
            Path::new("/nowhere/garrison")
        );
    }

    #[test]
    fn a_directory_that_cannot_be_written_is_said_not_fatal() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("no-such-directory/garrison");
        let refused = link(&missing).unwrap_err();
        assert!(refused.contains("could not be made"), "{refused}");
    }
}
