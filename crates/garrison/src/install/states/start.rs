//! The states of a start: a service that does not stay up, and what the run
//! does then, back to the release that ran or stopped.

use crate::state::State;

pub(crate) fn restarting(unit: &str, restarts: &str, seconds: u64) -> State {
    State::new(
        "install-restarting",
        format!("{unit} restarted {restarts} times within {seconds} s of starting"),
    )
}

/// `state`: systemd's `ActiveState`, empty where it named none.
pub(crate) fn not_active(unit: &str, state: &str, seconds: u64) -> State {
    let state = if state.is_empty() { "unknown" } else { state };
    State::new(
        "install-not-active",
        format!("{unit} is {state} within {seconds} s of starting"),
    )
}

pub(crate) fn switching_back() -> State {
    State::new(
        "install-switching-back",
        "Start failed; switching back to the previous release.",
    )
}

/// What the switch back put back, `went`, before the release that ran starts.
pub(crate) fn migrated_back(went: &State) -> State {
    State::new(
        "install-migrated-back",
        format!(
            "The new release had changed what the release that ran cannot read. {went} The other \
             databases keep their data."
        ),
    )
}

/// The release that ran reads no state the switch back leaves it.
pub(crate) fn unreadable_state(old: &str, unreadable: &str) -> State {
    State::new(
        "install-unreadable-state",
        format!("{old} cannot read the current state, as its self-check says of {unreadable}"),
    )
}

/// `release` did not start for `cause`, and the release that ran runs again.
pub(crate) fn switched_back(release: &str, cause: &State) -> State {
    State::new(
        "install-switched-back",
        format!(
            "Garrison {release} did not start ({cause}); the previous release is running. See the \
             journal."
        ),
    )
}

/// The way back to `old` failed for `error` before it started; `links`,
/// where they could not be set back; `went`, what went back meanwhile.
pub(crate) fn switch_back_failed(
    release: &str,
    cause: &State,
    old: &str,
    error: &State,
    links: Option<&State>,
    went: Option<&State>,
    command: &str,
) -> State {
    let what = format!("switching back to {old} failed ({error})");
    State::new(
        "install-switch-back-failed",
        fallen(release, cause, &what, links, went, command),
    )
}

/// The release that ran was started again and did not start either.
pub(crate) fn previous_failed(
    release: &str,
    cause: &State,
    error: &State,
    links: Option<&State>,
    went: Option<&State>,
    command: &str,
) -> State {
    let what = format!("the previous release did not start either ({error})");
    State::new(
        "install-previous-failed",
        fallen(release, cause, &what, links, went, command),
    )
}

fn fallen(
    release: &str,
    cause: &State,
    what: &str,
    links: Option<&State>,
    went: Option<&State>,
    command: &str,
) -> String {
    let went = went.map_or_else(String::new, |went| format!(" {went}"));
    match links {
        None => format!(
            "Garrison {release} did not start ({cause}); {what}.{went} `{command} install \
             --rollback --restore-state` returns to it with the state from before the upgrade. \
             See the journal."
        ),
        Some(links) => format!(
            "Garrison {release} did not start ({cause}); {what}, and the links could not be set \
             back ({links}).{went} See the journal."
        ),
    }
}

/// `old` ran no service when the run began, so it was not started again.
pub(crate) fn not_restarted(release: &str, cause: &State, old: &str, command: &str) -> State {
    State::new(
        "install-not-restarted",
        format!(
            "Garrison {release} did not start ({cause}); {old} did not run when this run began, \
             so it was not started again; `{command} install --rollback` returns to it. See the \
             journal."
        ),
    )
}

/// `release` was stopped; `earlier`, the release a rollback returns to.
pub(crate) fn stopped(release: &str, cause: &State, earlier: Option<&str>, command: &str) -> State {
    let outcome = match earlier {
        Some(earlier) => {
            format!("it was stopped; `{command} install --rollback` returns to {earlier}")
        }
        None => "it was stopped, and there is no other release to return to".to_owned(),
    };
    State::new(
        "install-stopped",
        format!("Garrison {release} did not start ({cause}); {outcome}. See the journal."),
    )
}
