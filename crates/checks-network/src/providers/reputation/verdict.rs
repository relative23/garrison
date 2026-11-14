//! What a blocklist's answer says of an address.

use serde::{Deserialize, Serialize};

use crate::dns::Answer;

/// What a list said of an address.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(super) enum Said {
    /// Listed, with the list's answer, such as `127.0.0.2`.
    Listed(String),
    Clear,
    /// No verdict, and why.
    Unanswered(String),
}

/// A list's answer for an address it was asked about.
pub(super) fn said(zone: &str, answer: Result<Answer, String>) -> Said {
    match answer {
        Ok(Answer::NoSuchName) => Said::Clear,
        Ok(Answer::Records(records)) => match records.first() {
            None => Said::Clear,
            // Spamhaus answers in 127.255.255.0/24 where it gives no verdict:
            // to a public resolver, or after too many questions.
            Some(code) if zone.ends_with("spamhaus.org") && code.starts_with("127.255.255.") => {
                Said::Unanswered(
                    "the list gives this resolver no verdict; it refuses public resolvers"
                        .to_owned(),
                )
            }
            Some(code) => Said::Listed(code.clone()),
        },
        Err(error) => Said::Unanswered(error),
    }
}
