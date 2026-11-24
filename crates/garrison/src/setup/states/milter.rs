//! The states of the macro filter's entry (`setup/milter.rs`).

use std::fmt::Display;

use crate::state::State;
use crate::units;

/// The filter runs, and setup, which sees its sockets only as root, cannot
/// tell which of Stalwart's entries ask it.
pub(in crate::setup) fn milter_unseen() -> State {
    State::new(
        "setup-milter-unseen",
        format!(
            "{} runs, but setup cannot see where it listens, so it cannot tell which of \
             Stalwart's entries ask it",
            units::MILTER
        ),
    )
}

/// Another program holds `port`, where the filter is to move.
pub(in crate::setup) fn milter_port_taken(port: u16, error: impl Display) -> State {
    State::new(
        "setup-milter-port-taken",
        format!(
            "The macro milter cannot move to 127.0.0.1:{port} ({error}). Nothing was changed: \
             free that port, or give the filter another"
        ),
    )
}

/// The filter does not answer on `port` for `problem`, where Stalwart is to
/// ask it.
pub(in crate::setup) fn milter_silent(port: u16, problem: &str) -> State {
    State::new(
        "setup-milter-silent",
        format!(
            "The macro milter does not answer on 127.0.0.1:{port} ({problem}): while Stalwart \
             asks it there, it defers all incoming mail. `journalctl -u {} -n 20` shows why it \
             does not run.",
            units::MILTER
        ),
    )
}

/// Stalwart asks entries in vain that are not the filter's, each said as
/// doctor says it (`stranded`): setup leaves them to their owner.
pub(in crate::setup) fn milter_stranded(stranded: &[State]) -> State {
    let lines: Vec<String> = stranded.iter().map(ToString::to_string).collect();
    State::new(
        "setup-milter-stranded",
        format!("{}\nSetup changed nothing", lines.join("\n")),
    )
}

/// Stalwart does not let the administrator read its milter entries
/// (`error`, JMAP's forbidden), as a user without its administrator role:
/// setup could not tell whether Stalwart asks one in vain.
pub(in crate::setup) fn milters_unreadable(error: &State) -> State {
    State::new(
        "setup-milters-unreadable",
        format!(
            "Stalwart does not let the administrator read its milter entries: run setup as an \
             administrator who holds the keys' permissions, as one with Stalwart's administrator \
             role ({error})"
        ),
    )
}
