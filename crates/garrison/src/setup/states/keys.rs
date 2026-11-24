//! The states of Garrison's API keys in Stalwart (`setup/keys.rs`).

use crate::state::State;

/// `text`, a network `--allow-network` named, is none.
pub(in crate::setup) fn network_invalid(text: &str) -> State {
    State::new("setup-network-invalid", format!("invalid network {text}"))
}

pub(in crate::setup) fn network_host_bits(text: &str) -> State {
    State::new(
        "setup-network-host-bits",
        format!("{text} has host bits set"),
    )
}
