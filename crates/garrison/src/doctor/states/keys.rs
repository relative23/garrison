//! The states of the tries of the API keys (`doctor/keys.rs`).

use std::fmt::Display;

use crate::state::State;

/// Whose API key it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::doctor) enum Service {
    Broker,
    Collector,
}

impl Service {
    fn name(self) -> &'static str {
        match self {
            Self::Broker => "broker",
            Self::Collector => "collector",
        }
    }

    /// What follows where Stalwart does not take the key.
    fn refused(self) -> &'static str {
        match self {
            Self::Broker => "nobody can sign in",
            Self::Collector => "every card that reads Stalwart stays unknown",
        }
    }

    /// What follows where Stalwart refuses what the service reads with it.
    fn narrowed(self) -> &'static str {
        match self {
            Self::Broker => "nobody can sign in",
            Self::Collector => "the cards that read Stalwart's domains and accounts stay unknown",
        }
    }
}

/// Why the key's file could not be read.
pub(in crate::doctor) fn unread(error: impl Display) -> String {
    format!("it could not be read ({error})")
}

/// Why the session Stalwart answered with `status` tells nothing of the key.
pub(in crate::doctor) fn answered(status: u16) -> String {
    format!("it answered HTTP {status} for the key's JMAP session")
}

/// Why Stalwart at `url` was not asked.
pub(in crate::doctor) fn silent(url: &str, error: impl Display) -> String {
    super::no_answer(url, error)
}

pub(in crate::doctor) fn taken(service: Service, file: &str) -> State {
    let service = service.name();
    let text = format!("Stalwart takes the {service}'s API key ({file}) from this host");
    State::new("doctor-key-taken", text)
}

pub(in crate::doctor) fn not_known(service: Service, file: &str) -> State {
    let (refused, service) = (service.refused(), service.name());
    let text = format!("Stalwart does not know the {service}'s API key in {file}, so {refused}");
    State::new("doctor-key-not-known", text)
        .with_fix("Run `garrison stalwart setup`, which makes a new one.")
}

pub(in crate::doctor) fn other_address(service: Service, file: &str) -> State {
    let (refused, service) = (service.refused(), service.name());
    let text = format!(
        "Stalwart refuses the {service}'s API key in {file} from this host's address \
         (HTTP 403), so {refused}"
    );
    State::new("doctor-key-other-address", text)
        .with_fix("The key may be used only from this host: run Stalwart in the host network.")
}

pub(in crate::doctor) fn untried(service: Service, file: &str, why: &str) -> State {
    let service = service.name();
    let text = format!("whether Stalwart takes the {service}'s API key in {file}: {why}");
    State::new("doctor-key-untried", text)
}

/// Stalwart opens the key's session but refuses `why` what its service
/// reads with it.
pub(in crate::doctor) fn narrowed(service: Service, file: &str, why: &str) -> State {
    let (follows, service) = (service.narrowed(), service.name());
    let text = format!(
        "Stalwart takes the {service}'s API key ({file}) but refuses what the {service} \
         reads with it ({why}), so {follows}"
    );
    State::new("doctor-key-narrowed", text)
        .with_fix("Run `garrison stalwart setup`, which gives the key the permissions it needs.")
}

pub(in crate::doctor) fn reads_unknown(service: Service, file: &str, why: &str) -> State {
    let service = service.name();
    let text = format!(
        "whether Stalwart lets the {service}'s API key ({file}) read what the {service} \
         reads: {why}"
    );
    State::new("doctor-key-reads-unknown", text)
}

#[cfg(test)]
pub(super) fn rows() -> Vec<State> {
    use Service::{Broker, Collector};
    vec![
        taken(Broker, "broker-native-key"),
        not_known(Collector, "collector-native-key"),
        other_address(Broker, "broker-native-key"),
        untried(Broker, "broker-native-key", &answered(500)),
        narrowed(Collector, "collector-native-key", "forbidden"),
        reads_unknown(
            Broker,
            "broker-native-key",
            &silent("http://127.0.0.1:8080/jmap/", "timed out"),
        ),
    ]
}
