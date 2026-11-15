//! What a blocklist's answer says of an address.
//!
//! A list answers a listing within 127.0.0.0/8 (RFC 5782, 2.3): 127.0.0.2,
//! and Spamhaus and Mailspike further codes there. Another address is no
//! list's answer but that of a resolver which answers names that do not
//! exist with an address of its own: through it, the list cannot be read.
//! Spamhaus gives its errors within 127.255.255.0/24, its public lists
//! under `spamhaus.org` and its Data Query Service under `dq.spamhaus.net`
//! alike (docs.spamhaus.com, read 2026-11-15).

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
    let error = |code: &Ipv4Addr| spamhaus(zone) && code.octets()[..3] == [127, 255, 255];
    match (codes.iter().find(|code| !error(code)), codes.first()) {
        (Some(code), _) => Said::Listed(code.to_string()),
        (None, None) => Said::Clear,
        (None, Some(code)) => Said::Unanswered(error_named(*code)),
    }
}

/// Whether `zone` is Spamhaus': a public list under `spamhaus.org`, or one
/// of its Data Query Service, whose names under `dq.spamhaus.net` hold the
/// subscriber's key.
fn spamhaus(zone: &str) -> bool {
    zone == "spamhaus.org" || zone.ends_with(".spamhaus.org") || zone.ends_with(".dq.spamhaus.net")
}

/// One of Spamhaus' errors in the words of its documentation: the Data
/// Query Service names 250 to 252, the public lists 252, 254 and 255.
fn error_named(code: Ipv4Addr) -> String {
    match code.octets()[3] {
        250 => "the list gives no verdict; it says that the key in its name is disabled".to_owned(),
        251 => "the list gives no verdict; it says that the key in its name is used against its \
                terms"
            .to_owned(),
        252 => "the list says that its name is mistyped".to_owned(),
        254 => "the list gives this resolver no verdict; it refuses public resolvers".to_owned(),
        255 => "the list gives this resolver no verdict; it was asked too often".to_owned(),
        _ => format!("the list gives no verdict; it answers {code}, one of its errors"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answered(zone: &str, code: &str) -> Said {
        said(zone, Ok(Answer::Records(vec![code.to_owned()])))
    }

    /// Spamhaus' Data Query Service answers under `dq.spamhaus.net`, with the
    /// subscriber's key in the name, and gives its errors in
    /// 127.255.255.0/24 as the public lists do: none of them is a listing.
    #[test]
    fn the_errors_of_spamhaus_data_query_service_are_no_listing() {
        let zone = "abcdefghijklmnopqrstuvwxyz.zen.dq.spamhaus.net";
        for (code, reason) in [
            (
                "127.255.255.250",
                "the list gives no verdict; it says that the key in its name is disabled",
            ),
            (
                "127.255.255.251",
                "the list gives no verdict; it says that the key in its name is used against its terms",
            ),
            ("127.255.255.252", "the list says that its name is mistyped"),
            (
                "127.255.255.253",
                "the list gives no verdict; it answers 127.255.255.253, one of its errors",
            ),
        ] {
            assert_eq!(
                answered(zone, code),
                Said::Unanswered(reason.to_owned()),
                "{code}"
            );
        }
        // Its listings are listings, as the public lists'.
        assert_eq!(
            answered(zone, "127.0.0.2"),
            Said::Listed("127.0.0.2".to_owned())
        );
        // A list of another's whose name only ends in Spamhaus' letters is no
        // list of Spamhaus'.
        assert_eq!(
            answered("notspamhaus.org", "127.255.255.252"),
            Said::Listed("127.255.255.252".to_owned())
        );
        assert_eq!(
            answered("bl.example.net", "127.255.255.250"),
            Said::Listed("127.255.255.250".to_owned())
        );
    }
}
