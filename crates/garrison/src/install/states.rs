//! Every state the installer reports: its one constructor each. Those of
//! the rollback, the restore and the uninstallation are in `states/back.rs`.

use std::fmt::Display;
use std::path::Path;
use std::process::ExitStatus;

use super::CONFIG;
use crate::state::{State, states};

mod back;
mod start;
pub(super) use back::*;
pub(super) use start::*;

states! {
    /// What the system said of `what`, a file, a folder, a link or a command:
    /// a failure the installer does not tell apart from others.
    pub(super) fn io(what: impl Display, error: impl Display) = "install-io":
        "{what}: {error}";
    pub(super) fn busy() = "install-busy":
        "Another garrison install is already running; try again when it has finished.";
    pub(super) fn not_root() = "install-not-root":
        "Run as root.";
    pub(super) fn tool_missing(program: &str) = "install-tool-missing":
        "{program} is required.";
    pub(super) fn old_systemd(version: u32, needed: u32) = "install-old-systemd":
        "systemd {version} is too old: Garrison's units need systemd {needed} or newer.";
    pub(super) fn systemd_unknown() = "install-systemd-unknown":
        "`systemctl --version` names no systemd version.";
    pub(super) fn old_polkit(version: &str) = "install-old-polkit":
        "polkit {version} has no JavaScript rules: Garrison needs polkit 0.106 or newer.";
    pub(super) fn no_polkit() = "install-no-polkit":
        "polkit is required for service actions, with JavaScript rules (polkit 0.106 or newer, \
         /etc/polkit-1/rules.d).";
    /// `why`: the units' account of the place they hide.
    pub(super) fn base_hidden(why: &str) = "install-base-hidden":
        "{why}; nothing was changed.";
    /// Bytes `free` in `directory` and `wanted` there, for `what`, such as "the
    /// installation".
    pub(super) fn no_room(directory: &Path, free: u64, what: &str, wanted: u64) = "install-no-room":
        "{} has {} MiB free and {what} needs {} MiB; nothing was changed.", directory.display(),
        free >> 20, wanted >> 20;
    /// The copies from before an upgrade that a switch back would put back.
    pub(super) fn copies_no_room(directory: &Path, free: u64, wanted: u64)
        = "install-copies-no-room":
        "{} has {} MiB free and the copies from before the upgrade need {} MiB there; free \
         space there", directory.display(), free >> 20, wanted.div_ceil(1 << 20);
    pub(super) fn sums_missing() = "install-sums-missing":
        "SHA256SUMS is missing; this is not a complete release.";
    pub(super) fn sums_malformed() = "install-sums-malformed":
        "SHA256SUMS is malformed.";
    pub(super) fn sums_outside(name: &str) = "install-sums-outside":
        "SHA256SUMS lists {name:?}, which is no file of a release; nothing was installed.";
    pub(super) fn sums_twice(name: &str) = "install-sums-twice":
        "SHA256SUMS lists {name} twice; nothing was installed.";
    /// A file of the release, or one met while copying it, that is a link or
    /// anything else but a regular file.
    pub(super) fn not_a_file(name: impl Display) = "install-not-a-file":
        "{name} is not a regular file; nothing was installed.";
    pub(super) fn checksum_mismatch(name: &str) = "install-checksum-mismatch":
        "Checksum mismatch for {name}; nothing was installed.";
    pub(super) fn unlisted(name: &str) = "install-unlisted":
        "{name} is not listed in SHA256SUMS; nothing was installed.";
    pub(super) fn bad_version(version: &str) = "install-bad-version":
        "VERSION {version:?} is not a release version; nothing was installed.";
    pub(super) fn config_refused() = "install-config-refused":
        "check-config failed";
    /// `why`: the running release's own words.
    pub(super) fn backup_failed(why: impl Display) = "install-backup-failed":
        "backup failed: {why}";
    /// The running release makes the backup, and a setting only the new one
    /// knows keeps it from loading the configuration.
    pub(super) fn backup_unloadable(said: &str, running: &str) = "install-backup-unloadable":
        "backup failed: {said}; {running}, the release that runs, makes the backup before the \
         upgrade and cannot load {CONFIG}/garrison.toml: take out the settings it does not \
         know, upgrade, then put them back";
    /// `said`: what `nginx -t` said.
    pub(super) fn nginx_not_reloaded(said: &str) = "install-nginx-not-reloaded":
        "nginx -t failed; snippets updated but nginx was not reloaded:\n{said}";
    /// `reason`: what the command said.
    pub(super) fn unwritten(target: &Path, command: &[&str], reason: &str) = "install-unwritten":
        "{} was not written, since `garrison {}` failed: {reason}", target.display(),
        command.join(" ");
    /// `command`: where Garrison's command is without the link.
    pub(super) fn link_taken(link: &Path, command: &str) = "install-link-taken":
        "{} is something else and was left alone; Garrison's command is {command}.", link.display();
    pub(super) fn link_failed(link: &Path, error: impl Display, command: &str)
        = "install-link-failed":
        "{} could not be made ({error}); Garrison's command is {command}.", link.display();
    /// `unit`: the macro filter's unit of a release up to 0.2, which runs.
    pub(super) fn filter_runs(unit: &str) = "install-macro-filter-runs":
        "{unit} runs: Stalwart asks the macro filter of the release installed about every \
         message, and this release has no macro filter, so Stalwart would defer mail; nothing \
         was changed. With the release installed, remove the [milter] section from \
         garrison.toml and run `garrison stalwart setup`, which takes the filter out of \
         Stalwart and stops it; then install this release.";
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

#[cfg(test)]
mod tests;
