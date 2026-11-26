//! Every state the installer reports: its one constructor each. Those of
//! the rollback, the restore and the uninstallation are in `states/back.rs`.

use std::fmt::Display;
use std::path::Path;
use std::process::ExitStatus;

use super::CONFIG;
use crate::state::State;

mod back;
mod start;
pub(super) use back::*;
pub(super) use start::*;

/// What the system said of `what`, a file, a folder, a link or a command:
/// a failure the installer does not tell apart from others.
pub(super) fn io(what: impl Display, error: impl Display) -> State {
    State::new("install-io", format!("{what}: {error}"))
}

/// A command that ran and failed, in its own words.
pub(super) fn failed(program: &str, arguments: &[&str], said: &str) -> State {
    io(
        format_args!("{program} {} failed", arguments.join(" ")),
        said,
    )
}

/// A refusal before the running release stopped, whose sentence has no
/// full stop yet, with that said: the same state.
pub(super) fn untouched(state: State) -> State {
    State {
        text: format!("{}; the running release was not touched", state.text),
        ..state
    }
}

/// A refusal before anything changed, whose sentence has no full stop yet,
/// with that said: the same state.
pub(super) fn unchanged(state: State) -> State {
    State {
        text: format!("{}. Nothing was changed.", state.text),
        ..state
    }
}

pub(super) fn busy() -> State {
    State::new(
        "install-busy",
        "Another garrison install is already running; try again when it has finished.",
    )
}

pub(super) fn not_root() -> State {
    State::new("install-not-root", "Run as root.")
}

pub(super) fn tool_missing(program: &str) -> State {
    State::new("install-tool-missing", format!("{program} is required."))
}

pub(super) fn old_systemd(version: u32, needed: u32) -> State {
    State::new(
        "install-old-systemd",
        format!("systemd {version} is too old: Garrison's units need systemd {needed} or newer."),
    )
}

pub(super) fn systemd_unknown() -> State {
    State::new(
        "install-systemd-unknown",
        "`systemctl --version` names no systemd version.",
    )
}

pub(super) fn old_polkit(version: &str) -> State {
    State::new(
        "install-old-polkit",
        format!("polkit {version} has no JavaScript rules: Garrison needs polkit 0.106 or newer."),
    )
}

pub(super) fn no_polkit() -> State {
    State::new(
        "install-no-polkit",
        "polkit is required for service actions, with JavaScript rules (polkit 0.106 or newer, \
         /etc/polkit-1/rules.d).",
    )
}

/// `why`: the units' account of the place they hide.
pub(super) fn base_hidden(why: &str) -> State {
    State::new(
        "install-base-hidden",
        format!("{why}; nothing was changed."),
    )
}

/// Bytes `free` in `directory` and `wanted` there, for `what`, such as "the
/// installation".
pub(super) fn no_room(directory: &Path, free: u64, what: &str, wanted: u64) -> State {
    State::new(
        "install-no-room",
        format!(
            "{} has {} MiB free and {what} needs {} MiB; nothing was changed.",
            directory.display(),
            free >> 20,
            wanted >> 20
        ),
    )
}

/// The copies from before an upgrade that a switch back would put back.
pub(super) fn copies_no_room(directory: &Path, free: u64, wanted: u64) -> State {
    State::new(
        "install-copies-no-room",
        format!(
            "{} has {} MiB free and the copies from before the upgrade need {} MiB there; free \
             space there",
            directory.display(),
            free >> 20,
            wanted.div_ceil(1 << 20)
        ),
    )
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

/// A file of the release, or one met while copying it, that is a link or
/// anything else but a regular file.
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

/// The first installation's last words: what to do before the next run.
pub(super) fn not_configured(target: &Path, command: &str) -> State {
    State::new(
        "install-not-configured",
        format!(
            "The release is installed, but Garrison is not configured yet.

  1. Edit {target} (origins, providers, actions).
     `garrison detect` shows what this host runs, and
     `garrison modules` chooses the modules this installation offers.
  2. Create the Stalwart objects (webhook, API keys, metrics):
       garrison stalwart setup        (asks for a Stalwart administrator)
  3. Create the access policy:   garrison access init
  4. Check everything:           garrison check-config
  5. Run the installer again to start the services.
  6. Give Garrison a host name of its own (never Stalwart's):
     `garrison nginx` prints its server block and the lines for Stalwart's.
     Add
       include /etc/nginx/snippets/garrison-stalwart-server*.conf;
     to every server block that proxies to Stalwart: it keeps the metrics
     exporter that step 2 turns on off the internet.

The command is available as {command}.",
            target = target.display(),
        ),
    )
}

pub(super) fn config_refused() -> State {
    State::new("install-config-refused", "check-config failed")
}

/// `why`: the running release's own words.
pub(super) fn backup_failed(why: impl Display) -> State {
    State::new("install-backup-failed", format!("backup failed: {why}"))
}

/// The running release makes the backup, and a setting only the new one
/// knows keeps it from loading the configuration.
pub(super) fn backup_unloadable(said: &str, running: &str) -> State {
    State::new(
        "install-backup-unloadable",
        format!(
            "backup failed: {said}; {running}, the release that runs, makes the backup before the \
             upgrade and cannot load {CONFIG}/garrison.toml: take out the settings it does not \
             know, upgrade, then put them back"
        ),
    )
}

/// `said`: what `nginx -t` said.
pub(super) fn nginx_not_reloaded(said: &str) -> State {
    State::new(
        "install-nginx-not-reloaded",
        format!("nginx -t failed; snippets updated but nginx was not reloaded:\n{said}"),
    )
}

/// `reason`: what the command said.
pub(super) fn unwritten(target: &Path, command: &[&str], reason: &str) -> State {
    State::new(
        "install-unwritten",
        format!(
            "{} was not written, since `garrison {}` failed: {reason}",
            target.display(),
            command.join(" ")
        ),
    )
}

pub(super) fn policy_foreign(policy: &Path, owner: u32) -> State {
    let policy = policy.display();
    State::new(
        "install-policy-foreign",
        format!(
            "{policy}, the access policy that broker.policy names, belongs to the user with ID \
             {owner}, not to root: the installer makes no other user's file the policy, and the \
             broker takes none. Where it is the policy you mean, `chown root {policy}` and run \
             this again"
        ),
    )
}

/// `command`: where Garrison's command is without the link.
pub(super) fn link_taken(link: &Path, command: &str) -> State {
    State::new(
        "install-link-taken",
        format!(
            "{} is something else and was left alone; Garrison's command is {command}.",
            link.display()
        ),
    )
}

pub(super) fn link_failed(link: &Path, error: impl Display, command: &str) -> State {
    State::new(
        "install-link-failed",
        format!(
            "{} could not be made ({error}); Garrison's command is {command}.",
            link.display()
        ),
    )
}

/// `said`: what semodule said, where it said anything.
pub(super) fn selinux_failed(said: Option<&str>, status: ExitStatus) -> State {
    let said = said.map_or_else(
        || format!("`semodule -i` said nothing and ended with {status}"),
        ToOwned::to_owned,
    );
    State::new(
        "install-selinux-failed",
        format!(
            "The SELinux module did not load, so nginx may not reach Garrison: {said}. `setsebool \
             -P httpd_can_network_connect 1` allows it more broadly."
        ),
    )
}

/// `unit`: the macro filter's unit of a release up to 0.2, which runs.
pub(super) fn filter_runs(unit: &str) -> State {
    State::new(
        "install-macro-filter-runs",
        format!(
            "{unit} runs: Stalwart asks the macro filter of the release installed about every \
             message, and this release has no macro filter, so Stalwart would defer mail; nothing \
             was changed. With the release installed, remove the [milter] section from \
             garrison.toml and run `garrison stalwart setup`, which takes the filter out of \
             Stalwart and stops it; then install this release."
        ),
    )
}

#[cfg(test)]
mod tests;
