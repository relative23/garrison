//! What a blocklist's answer says of an address.
//!
//! A list answers a listing within 127.0.0.0/8 (RFC 5782, 2.3): 127.0.0.2,
//! and Spamhaus and Mailspike further codes there. Another address is no
//! list's answer but that of a resolver which answers names that do not
//! exist with an address of its own: through it, the list cannot be read.

use std::net::Ipv4Addr;

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
    let records = match answer {
        Ok(Answer::NoSuchName) => return Said::Clear,
        Ok(Answer::Records(records)) => records,
        Err(error) => return Said::Unanswered(error),
    };
    let codes: Vec<Ipv4Addr> = records
        .iter()
        .filter_map(|record| record.parse().ok())
        .collect();
    if let Some(other) = codes.iter().find(|code| !code.is_loopback()) {
        return Said::Unanswered(format!(
            "the resolver answered {other}, which no list answers: it rewrites what it is \
             told, so the list cannot be read through it"
        ));
    }
    // Spamhaus answers in 127.255.255.0/24 where it gives no verdict; its
    // documentation calls these codes errors that imply no listing.
    let error =
        |code: &Ipv4Addr| zone.ends_with("spamhaus.org") && code.octets()[..3] == [127, 255, 255];
    match (codes.iter().find(|code| !error(code)), codes.first()) {
        (Some(code), _) => Said::Listed(code.to_string()),
        (None, None) => Said::Clear,
        (None, Some(code)) => Said::Unanswered(
            match code.octets()[3] {
                252 => "the list says that its name is mistyped",
                255 => "the list gives this resolver no verdict; it was asked too often",
                _ => "the list gives this resolver no verdict; it refuses public resolvers",
            }
            .to_owned(),
        ),
    }
}
