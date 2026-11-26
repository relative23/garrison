//! The states of doctor's look at Stalwart's milters (`doctor/milter.rs`).

use std::fmt::Display;

use garrison_stalwart::{Error, SUPPORTED};

use crate::doctor::milter::Entry;
use crate::state::State;

/// What mends an entry Stalwart asks in vain.
const MEND: &str = "Start the milter that is to answer there. If nothing is to answer there, \
                    remove that entry in the Stalwart WebUI (Settings ▸ MTA ▸ Milters) and reload \
                    its settings.";

/// Why Stalwart's milters could not be asked: the collector's key could
/// not be read.
pub(in crate::doctor) fn key_unread(error: impl Display) -> String {
    format!("the collector's API key: {error}")
}

/// Why Stalwart at `url` did not tell its milters.
pub(in crate::doctor) fn unasked(url: &str, error: Error) -> String {
    match error {
        Error::Unavailable(why) => super::no_answer(url, why),
        Error::Limited(why) => {
            format!(
                "Stalwart refused the question for its rate limit ({why}); ask again in a minute"
            )
        }
        // A key it does not know and one without the permission alike:
        // the line on the key says which.
        Error::Denied(_) | Error::InvalidToken(_) | Error::Misconfigured(_) => {
            "Stalwart refused the collector's API key".to_owned()
        }
        Error::Unreadable(why) => format!(
            "Stalwart answered in a form this release of Garrison does not read ({why}); \
             {SUPPORTED}"
        ),
    }
}

/// An entry Stalwart asks in vain.
fn stray(entry: &Entry) -> String {
    format!(
        "Stalwart asks a milter at {} (entry {}), where nothing answers: Stalwart {}",
        entry.address(),
        entry.id,
        entry.meanwhile("all incoming mail")
    )
}

/// Such an entry, where Stalwart defers mail meanwhile or decides by
/// conditions of its own.
pub(in crate::doctor) fn stranded(entry: &Entry) -> State {
    State::new("doctor-milter-stranded", stray(entry)).with_fix(MEND)
}

/// Such an entry, where Stalwart takes mail unscanned meanwhile.
pub(in crate::doctor) fn stranded_unscanned(entry: &Entry) -> State {
    State::new("doctor-milter-stranded-unscanned", stray(entry)).with_fix(MEND)
}

pub(in crate::doctor) fn stranded_unknown(why: &str) -> State {
    let text = format!("whether Stalwart asks a milter where nothing answers: {why}");
    State::new("doctor-milter-stranded-unknown", text)
}

#[cfg(test)]
pub(super) fn rows() -> Vec<State> {
    let entry = |id: &str, port: u16, defer: Option<bool>| -> Entry {
        serde_json::from_value(
            serde_json::json!({"id": id, "host": "127.0.0.1", "port": port,
            "tempFailOnError": defer}),
        )
        .unwrap()
    };
    let denied = Error::Denied(String::new());
    vec![
        stranded(&entry("o", 11332, None)),
        stranded_unscanned(&entry("x", 9000, Some(false))),
        stranded_unknown(&unasked("http://127.0.0.1:8080", denied)),
    ]
}
