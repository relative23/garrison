//! The states of `backup`, `self-check`, `notify-test`, `modules` and
//! `setup`, the guided setup at a terminal.

use std::fmt::Display;
use std::path::Path;

use crate::state::State;

/// What the system said of `what`, a file or a database, as `backup` copied it.
pub(crate) fn backup_io(what: impl Display, error: impl Display) -> State {
    State::new("backup-io", format!("{what}: {error}"))
}

pub(crate) fn receipt_unwritten(receipt: &Path, error: impl Display) -> State {
    State::new(
        "self-check-receipt-unwritten",
        format!("Cannot write {}: {error}", receipt.display()),
    )
}

/// `line`: a channel's secret its unit would not hand over, as `loaded`
/// words it.
pub(crate) fn notify_unloaded(line: &str) -> State {
    State::new("notify-test-unloaded", format!("Not tested: {line}"))
}

pub(crate) fn notify_not_root() -> State {
    State::new(
        "notify-test-not-root",
        "Run as root: the channels' secrets are files only root may read.",
    )
}

pub(crate) fn no_channel() -> State {
    State::new(
        "notify-test-no-channel",
        "No channel is configured: set ntfy_url, webhook_url or the mail settings under \
         [notifications] in garrison.toml.",
    )
}

pub(crate) fn notify_sent(channel: impl Display) -> State {
    State::new(
        "notify-test-sent",
        format!("{channel}: the test message is out."),
    )
}

pub(crate) fn notify_failed(channel: impl Display, error: impl Display) -> State {
    State::new(
        "notify-test-failed",
        format!(
            "{channel}: the test message did not go out: {error}. Check its address and its \
             secret in /etc/garrison/credentials."
        ),
    )
}

pub(crate) fn unknown_module(word: &str, known: &[&str]) -> State {
    State::new(
        "modules-unknown",
        format!("{word} is not a module ID; known: {}", known.join(", ")),
    )
}

/// What the system or the configuration said of `what`, the file or the
/// terminal.
pub(crate) fn modules_io(what: impl Display, error: impl Display) -> State {
    State::new("modules-io", format!("{what}: {error}"))
}

pub(crate) fn not_offered(path: &Path) -> State {
    State::new(
        "modules-not-offered",
        format!(
            "{}: the edited file does not offer the chosen modules",
            path.display()
        ),
    )
}

pub(crate) fn modules_unasked() -> State {
    State::new(
        "modules-unasked",
        "garrison modules asks before it writes, and no terminal is here to answer: add --yes to \
         write it.",
    )
}

pub(crate) fn modules_unchanged() -> State {
    State::new("modules-unchanged", "Nothing was changed.")
}

pub(crate) fn modules_held() -> State {
    State::new(
        "modules-held",
        "The configuration offers these modules already; nothing was changed.",
    )
}

pub(crate) fn modules_written(previous: &Path) -> State {
    State::new(
        "modules-written",
        format!("Written; the previous file is {}.", previous.display()),
    )
}

/// `units`: the services that read the modules when they start.
pub(crate) fn modules_unapplied(units: &[&str]) -> State {
    State::new(
        "modules-unapplied",
        format!("Restart {} to apply it.", units.join(" and ")),
    )
}

pub(crate) fn wizard_io(what: impl Display, error: impl Display) -> State {
    State::new("wizard-io", format!("{what}: {error}"))
}

pub(crate) fn wizard_ended() -> State {
    State::new(
        "wizard-ended",
        "The setup was ended; run `garrison setup` again to continue.",
    )
}

/// The addresses asked for, which the file's `[deployment]` table cannot take.
pub(crate) fn addresses_unwritable(path: &Path, answers: &[String; 4]) -> State {
    let [own, issuer, local, webui] = answers;
    State::new(
        "wizard-addresses-unwritable",
        format!(
            "The addresses cannot be written into {}: its deployment table is not one \
             [deployment] section with a line for each, as dotted keys write it. Write \
             public_origin = \"{own}\", issuer = \"{issuer}\", stalwart_url = \"{local}\" and \
             admin_url = \"{webui}\" under [deployment] there, then run `garrison setup` again.",
            path.display()
        ),
    )
}

/// `what`: the step that failed, which said why above.
pub(crate) fn step_failed(what: &str) -> State {
    State::new(
        "wizard-step-failed",
        format!("{what} did not succeed; fix the cause above and run `garrison setup` again."),
    )
}

pub(crate) fn stalwart_unconnected() -> State {
    State::new(
        "wizard-stalwart-unconnected",
        "Connecting Stalwart did not succeed.",
    )
}

pub(crate) fn start_failed(cause: &State) -> State {
    State::new(
        "wizard-start-failed",
        format!("Starting Garrison failed: {cause}; run `garrison setup` again."),
    )
}

pub(crate) fn wizard_not_root() -> State {
    State::new("wizard-not-root", "Run as root.")
}

pub(crate) fn no_terminal() -> State {
    State::new(
        "wizard-no-terminal",
        "garrison setup asks questions at a terminal; without one, follow \"Unattended \
         installation\" in docs/operator/installation.md.",
    )
}

pub(crate) fn wizard_not_installed() -> State {
    State::new(
        "wizard-not-installed",
        "Install the release first: ./bin/garrison install in the unpacked archive.",
    )
}
