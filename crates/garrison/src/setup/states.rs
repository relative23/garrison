//! Every state `garrison stalwart setup` reports: its one constructor each.
//! Those of the API keys are in `states/keys.rs`. A failure that reaches
//! the end of a run is said
//! with the run that mends it (`again`), and keeps its name; so does one
//! with what else it leaves, but a new secret Stalwart may not have taken,
//! which is a state of its own inside it (`until`).

use std::fmt::Display;
use std::path::Path;

use garrison_stalwart::SUPPORTED;

use crate::state::State;

mod keys;
pub(super) use keys::*;

/// A failure, with the run that mends it said after it: the same state.
pub(super) fn again(state: State, command: &str) -> State {
    State {
        text: format!(
            "{}. Run `{command}` again once this is mended.",
            state.text.trim_end_matches('.')
        ),
        ..state
    }
}

/// A failure after a new signature key (`signature`) or scrape credential
/// (`scrape`) is in its file and before Stalwart has surely reloaded its
/// settings, which is when it takes them, with what may go without them
/// until setup runs again: the same state.
pub(super) fn until(state: State, signature: bool, scrape: bool) -> State {
    let pending = [
        signature.then(signature_pending),
        scrape.then(scrape_pending),
    ];
    let text =
        (pending.into_iter().flatten()).fold(state.text, |text, left| format!("{text}; {left}"));
    State { text, ..state }
}

/// Stalwart signs with a new key once it reloads its settings, which it
/// may have done already or do later, as at its own restart.
pub(super) fn signature_pending() -> State {
    State::new(
        "setup-signature-pending",
        "the receiver may refuse Stalwart's batches until setup runs again, and Stalwart sends \
         them again for an hour",
    )
}

pub(super) fn scrape_pending() -> State {
    State::new(
        "setup-scrape-pending",
        "the exporter may refuse the collector's scrape until setup runs again",
    )
}

pub(super) fn no_administrator() -> State {
    State::new(
        "setup-no-administrator",
        "Name the Stalwart administrator: run this at a terminal to be asked, or pass \
         --admin-credential - with the JSON on standard input, or --admin-credential FILE.",
    )
}

/// A file setup reads a secret from, in the words of its reader, which
/// name the file and never what it holds.
pub(super) fn file_unread(error: impl Display) -> State {
    State::new("setup-file-unread", error.to_string())
}

pub(super) fn input_unread(error: impl Display) -> State {
    State::new("setup-input-unread", format!("standard input: {error}"))
}

pub(super) fn administrator_too_long() -> State {
    State::new(
        "setup-administrator-too-long",
        "The administrator on standard input is too long.",
    )
}

/// The parser's words, which quote nothing of what it read.
pub(super) fn administrator_not_json(error: impl Display) -> State {
    State::new("setup-administrator-not-json", error.to_string())
}

pub(super) fn administrator_unusable() -> State {
    State::new(
        "setup-administrator-unusable",
        r#"The administrator needs {"username","secret"} or {"apiKey"}"#,
    )
}

/// `program`, which asks for the secret at the terminal, did not start.
pub(super) fn ask_failed(program: &str, error: impl Display) -> State {
    State::new("setup-ask-failed", format!("{program}: {error}"))
}

pub(super) fn no_secret() -> State {
    State::new(
        "setup-no-secret",
        "No secret was entered; nothing was changed.",
    )
}

fn folder_unwritten(folder: &Path, error: impl Display) -> String {
    format!(
        "Setup cannot write the credentials folder {}: {error}.",
        folder.display()
    )
}

/// The credentials folder refused a user who is not root.
pub(super) fn not_root(folder: &Path, error: impl Display) -> State {
    State::new(
        "setup-not-root",
        format!(
            "{} Run it as root, as `sudo garrison stalwart setup`; nothing was changed.",
            folder_unwritten(folder, error)
        ),
    )
}

/// The credentials folder refused root; `again`, the run that mends it.
pub(super) fn folder_unwritable(folder: &Path, error: impl Display, again: &str) -> State {
    State::new(
        "setup-folder-unwritable",
        format!(
            "{} Nothing was changed; run `{again}` again once this is mended.",
            folder_unwritten(folder, error)
        ),
    )
}

/// A file of a secret setup writes, or the secret it could not make for one.
pub(super) fn unwritten(path: &Path, error: impl Display) -> State {
    State::new(
        "setup-unwritten",
        format!("Could not write {}: {error}", path.display()),
    )
}

/// The system gave no random bytes for a new secret.
pub(super) fn no_random(error: impl Display) -> State {
    State::new("setup-no-random", error.to_string())
}

/// A call to `method` that got no answer setup reads, in the words of
/// Stalwart's client, or one Stalwart answered with a status setup does not
/// take, such as `HTTP 404`.
pub(super) fn call_failed(method: &str, why: impl Display) -> State {
    State::new("setup-call-failed", format!("{method}: {why}"))
}

/// Why Stalwart refuses a request for its limit of requests (HTTP 429), as
/// where it sees setup at another address than 127.0.0.1: a run after the
/// limit's window goes through.
pub(super) const LIMITED: &str = "Stalwart refused the request for its limit of requests (HTTP \
                                  429), whose window is a minute unless it was set otherwise";

pub(super) fn limited(method: &str) -> State {
    State::new("setup-limited", format!("{method}: {LIMITED}"))
}

/// A wrong password, an unknown user and an API key Stalwart does not know
/// (measured on Stalwart 1.1.0 and 1.2.0).
pub(super) fn administrator_refused() -> State {
    State::new(
        "setup-administrator-refused",
        "Stalwart refused the administrator (HTTP 401): check the user name and the password, \
         or the API key.",
    )
}

/// A credential Stalwart knows, from an address it does not take it from:
/// an API key's networks. An address it blocked gets its connections
/// closed (measured on 1.1.0 only), so not this answer.
pub(super) fn administrator_refused_here() -> State {
    State::new(
        "setup-administrator-refused-here",
        "Stalwart refused the administrator from this host's address (HTTP 403): its API key may \
         not allow that address.",
    )
}

/// An answer of Stalwart's to `method` that this release does not read,
/// what was wrong with it, and where the supported Stalwart releases are
/// named, since no run of setup mends it.
pub(super) fn unreadable(method: &str, what: impl Display) -> State {
    State::new(
        "setup-unreadable",
        format!("{method}: {what}, which this release of Garrison does not read; {SUPPORTED}"),
    )
}

/// JMAP's error `kind` for `method`, with Stalwart's description.
pub(super) fn stalwart_error(method: &str, kind: &str, description: &str) -> State {
    State::new(
        "setup-stalwart-error",
        format!("{method}: {kind} {description}"),
    )
}

/// What `method` was to create, change or remove and Stalwart refused, in
/// Stalwart's words, shortened (`refusal`).
pub(super) fn stalwart_refused(method: &str, refusal: &str) -> State {
    State::new("setup-stalwart-refused", format!("{method}: {refusal}"))
}

/// The webhook would ask for `kind`, which Garrison must never record: a
/// broken build.
pub(super) fn event_forbidden(kind: &str) -> State {
    State::new(
        "setup-event-forbidden",
        format!(
            "This build of Garrison would ask Stalwart for the event {kind}, which Garrison must \
             never record, so the webhook was not changed. Install Garrison again from its \
             release archive."
        ),
    )
}

/// A run's last line where Stalwart and the files were as asked: the
/// Ansible role reads it as a play that changed nothing.
pub(super) fn as_asked() -> State {
    State::new(
        "setup-as-asked",
        "Stalwart is set up as asked; nothing was changed.",
    )
}

/// A run's outcome where it changed something, once Stalwart reloaded its
/// settings; `restart`, what the services that hold the new secrets do.
pub(super) fn reloaded(restart: Option<&State>) -> State {
    let text = match restart {
        Some(restart) => format!("Settings reloaded. {restart}"),
        None => "Settings reloaded.".to_owned(),
    };
    State::new("setup-reloaded", text)
}

/// Start the services `named` again so that they read their new secrets,
/// or it its (`one`): asked where setup runs without root, or where root's
/// restart failed.
pub(super) fn restart_asked(named: &str, one: bool) -> State {
    let text = if one {
        format!("Restart {named} so it reads the new secret.")
    } else {
        format!("Restart {named} so they read the new secrets.")
    };
    State::new("setup-restart-asked", text)
}

/// The services `named` do not run, and read their new secrets when they
/// start.
pub(super) fn read_at_start(named: &str, one: bool) -> State {
    let text = if one {
        format!("{named} reads the new secret when it starts.")
    } else {
        "The services read the new secrets when they start.".to_owned()
    };
    State::new("setup-read-at-start", text)
}

pub(super) fn restarted(named: &str, one: bool) -> State {
    let secrets = if one { "secret" } else { "secrets" };
    State::new(
        "setup-restarted",
        format!("{named} restarted with the new {secrets}."),
    )
}

#[cfg(test)]
mod tests;
