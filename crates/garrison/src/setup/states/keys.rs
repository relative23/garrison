//! The states of Garrison's API keys in Stalwart (`setup/keys.rs`).

use std::fmt::Display;
use std::path::Path;

use crate::state::{State, states};

states! {
    /// `text`, a network `--allow-network` named, is none.
    pub(in crate::setup) fn network_invalid(text: &str) = "setup-network-invalid":
        "invalid network {text}";
    pub(in crate::setup) fn network_host_bits(text: &str) = "setup-network-host-bits":
        "{text} has host bits set";
    /// Asking Stalwart whose the key in `file` is failed for `why`, so its
    /// account is not known: the run stops before it changes anything.
    pub(in crate::setup) fn owner_unknown(file: &Path, why: impl Display)
        = "setup-key-owner-unknown":
        "Asking Stalwart whose API key {} holds: {why}", file.display();
    /// Stalwart does not show the administrator the account that the key in
    /// `file` belongs to (`error`, JMAP's accountNotFound), as it answers a
    /// user without its administrator rights (measured on Stalwart 1.2.0).
    pub(in crate::setup) fn account_unseen(file: &Path, error: &State) = "setup-account-unseen":
        "Stalwart does not show the administrator the account that the API key in {} \
         belongs to: run setup as an administrator who holds the keys' permissions, as one \
         with Stalwart's administrator role ({error})", file.display();
    /// Stalwart does not let the administrator read its webhooks (`error`,
    /// JMAP's forbidden), as it answers a user without its administrator
    /// rights, who may read its own API keys and nothing else of what setup
    /// reads (measured on Stalwart 1.2.0).
    pub(in crate::setup) fn webhooks_unreadable(error: &State) = "setup-webhooks-unreadable":
        "Stalwart does not let the administrator read its webhooks: run setup as an \
         administrator who holds the keys' permissions, as one with Stalwart's administrator \
         role ({error})";
    /// Stalwart's quota leaves the administrator's account, which holds the
    /// keys `held` names, no room for a new key of `description`, which
    /// setup makes before it removes the one it replaces: nothing of that key
    /// changed.
    pub(in crate::setup) fn account_full(held: &str, description: &str) = "setup-account-full":
        "Stalwart takes no more API keys in the administrator's account, which holds {held}: \
         setup makes a new key before it removes the one it replaces. Remove a key the \
         account no longer needs in the Stalwart WebUI; setup made no new key \
         '{description}' and removed none";
    /// The administrator may not grant the key of `description` its
    /// permissions (`error`, JMAP's forbidden), as Stalwart answers a user
    /// without its administrator rights (measured on Stalwart 1.1.0 only).
    pub(in crate::setup) fn key_not_granted(description: &str, error: &State)
        = "setup-key-not-granted":
        "Stalwart refused the administrator the API key '{description}', since it may not \
         grant the key's permissions: run setup as an administrator who holds them, as one \
         with Stalwart's administrator role ({error})";
    pub(in crate::setup) fn secret_missing() = "setup-key-secret-missing":
        "Stalwart did not return the new API key secret";
    /// A try of the key in `file` that got no answer, or `why` Stalwart
    /// answered instead of a session.
    pub(in crate::setup) fn key_untried(file: &str, why: impl Display) = "setup-key-untried":
        "Trying {file}: {why}";
    pub(in crate::setup) fn key_untaken(file: &str) = "setup-key-untaken":
        "Stalwart does not take the API key in {file} (HTTP 401)";
    /// Stalwart knows the key but not from the address it sees this host at,
    /// as in a container's bridge network, where it sees the bridge's gateway.
    pub(in crate::setup) fn key_refused_here(file: &str) = "setup-key-refused-here":
        "Stalwart refuses the API key in {file} from this host (HTTP 403): it sees this host \
         at an address the key does not allow. That happens when Stalwart runs in a Docker \
         or Podman bridge network; run it in the host network instead (docker run --network \
         host, or network_mode: host with Compose)";
    /// The broker could not be started again with its new key (`asked`): it
    /// holds the key the new one replaces, which stays in Stalwart.
    pub(in crate::setup) fn old_key_kept(asked: &State) = "setup-old-key-kept":
        "{asked} Until then it holds the API key the new one replaces, which stays in \
         Stalwart";
}

/// A failure of the call that was to make a new key: the same state.
pub(in crate::setup) fn unreturned(state: State) -> State {
    State {
        text: format!(
            "{} (Stalwart did not return the new API key secret)",
            state.text
        ),
        ..state
    }
}

/// The new key's file could not be written (`state`), and the key was taken
/// out of Stalwart again: the same state.
pub(in crate::setup) fn taken_out(state: State) -> State {
    State {
        text: format!(
            "{}; the new API key was taken out of Stalwart again",
            state.text
        ),
        ..state
    }
}

/// The new key's file could not be written (`state`), nor the key taken out
/// again: the same state.
pub(in crate::setup) fn left_in(state: State) -> State {
    State {
        text: format!(
            "{}; the new API key stays in Stalwart without its secret, and the next run replaces it",
            state.text
        ),
        ..state
    }
}

/// The key of `description` that a new one replaced could not be removed
/// (`state`): the same state.
pub(in crate::setup) fn replaced_stays(state: State, description: &str) -> State {
    State {
        text: format!(
            "{}; the API key '{description}' that the new one replaced stays",
            state.text
        ),
        ..state
    }
}
