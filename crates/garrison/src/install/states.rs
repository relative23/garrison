//! Every state the installer, the rollback, the restore and the
//! uninstallation report: their one constructor each.

use std::fmt::Display;

use crate::state::State;

/// What the system said of `what`, a file, a folder, a link or a command:
/// a failure the installer does not tell apart from others.
pub(super) fn io(what: impl Display, error: impl Display) -> State {
    State::new("install-io", format!("{what}: {error}"))
}

pub(super) fn sums_missing() -> State {
    State::new(
        "install-sums-missing",
        "SHA256SUMS is missing; this is not a complete release.",
    )
}

pub(super) fn sums_malformed() -> State {
    State::new("install-sums-malformed", "SHA256SUMS is malformed.")
}

pub(super) fn sums_outside(name: &str) -> State {
    State::new(
        "install-sums-outside",
        format!("SHA256SUMS lists {name:?}, which is no file of a release; nothing was installed."),
    )
}

pub(super) fn sums_twice(name: &str) -> State {
    State::new(
        "install-sums-twice",
        format!("SHA256SUMS lists {name} twice; nothing was installed."),
    )
}

pub(super) fn not_a_file(name: impl Display) -> State {
    State::new(
        "install-not-a-file",
        format!("{name} is not a regular file; nothing was installed."),
    )
}

pub(super) fn checksum_mismatch(name: &str) -> State {
    State::new(
        "install-checksum-mismatch",
        format!("Checksum mismatch for {name}; nothing was installed."),
    )
}

pub(super) fn unlisted(name: &str) -> State {
    State::new(
        "install-unlisted",
        format!("{name} is not listed in SHA256SUMS; nothing was installed."),
    )
}

pub(super) fn bad_version(version: &str) -> State {
    State::new(
        "install-bad-version",
        format!("VERSION {version:?} is not a release version; nothing was installed."),
    )
}

/// The run's last line where it changed something; `rollback`, the command
/// that returns to the release before, where there is one.
pub(super) fn running(version: &str, rollback: Option<&str>) -> State {
    back(
        State::new("install-running", format!("Garrison {version} is running.")),
        rollback,
    )
}

/// The run's last line where it changed nothing.
pub(super) fn as_installed(version: &str, rollback: Option<&str>) -> State {
    back(
        State::new(
            "install-as-installed",
            format!("Garrison {version} is running as installed; nothing was changed."),
        ),
        rollback,
    )
}

fn back(state: State, rollback: Option<&str>) -> State {
    match rollback {
        Some(command) => state.with_fix(format!("Roll back with: {command}")),
        None => state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_state_of_the_installer_says_its_line() {
        let back = Some("garrison install --rollback");
        crate::state::table(
            &[include_str!("states.rs")],
            &[
                (
                    io("/opt/garrison", "Permission denied (os error 13)"),
                    "/opt/garrison: Permission denied (os error 13) [install-io]",
                ),
                (
                    sums_missing(),
                    "SHA256SUMS is missing; this is not a complete release. [install-sums-missing]",
                ),
                (
                    sums_malformed(),
                    "SHA256SUMS is malformed. [install-sums-malformed]",
                ),
                (
                    sums_outside("../VERSION"),
                    "SHA256SUMS lists \"../VERSION\", which is no file of a release; nothing was \
                     installed. [install-sums-outside]",
                ),
                (
                    sums_twice("VERSION"),
                    "SHA256SUMS lists VERSION twice; nothing was installed. [install-sums-twice]",
                ),
                (
                    not_a_file("static/etc"),
                    "static/etc is not a regular file; nothing was installed. [install-not-a-file]",
                ),
                (
                    checksum_mismatch("static/index.html"),
                    "Checksum mismatch for static/index.html; nothing was installed. \
                     [install-checksum-mismatch]",
                ),
                (
                    unlisted("static/extra.js"),
                    "static/extra.js is not listed in SHA256SUMS; nothing was installed. \
                     [install-unlisted]",
                ),
                (
                    bad_version("../../etc"),
                    "VERSION \"../../etc\" is not a release version; nothing was installed. \
                     [install-bad-version]",
                ),
                (
                    running("0.2.0", back),
                    "Garrison 0.2.0 is running. [install-running]\n      Roll back with: \
                     garrison install --rollback",
                ),
                (
                    as_installed("0.2.0", None),
                    "Garrison 0.2.0 is running as installed; nothing was changed. \
                     [install-as-installed]",
                ),
            ],
        );
    }
}
