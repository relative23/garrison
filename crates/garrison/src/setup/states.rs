//! Every state `garrison stalwart setup` reports: its one constructor each.
//! Those of the API keys are in `states/keys.rs`. A failure that reaches
//! the end of a run is said with the run that mends it (`again`), and keeps
//! its name.

use std::fmt::Display;
use std::path::Path;

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

#[cfg(test)]
mod tests;
