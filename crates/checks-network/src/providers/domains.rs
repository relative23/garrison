//! Stalwart's domains, as the network checks read them with the collector's
//! API key: how many of them a check takes, and why they could not be read.

use std::time::Duration;

use garrison_stalwart::jmap::JmapClient;
use serde::Deserialize;

use crate::context::Context;
use crate::options::{Checked, Options};

const MOST_DOMAINS: usize = 20;

/// The `max_domains` option of a check that reads Stalwart's domains: how
/// many of them it takes, 20 unless it says otherwise.
pub(super) fn max_domains(options: &Options<'_>) -> Checked<usize> {
    let most = options.integer("max_domains", 20, 1, 100)?;
    Ok(usize::try_from(most).unwrap_or(MOST_DOMAINS))
}

/// What a check says that takes only the first `most` of Stalwart's
/// `domains`.
pub(super) fn left_out(domains: usize, most: usize) -> String {
    format!("Stalwart has {domains} domains; only the first {most} are checked (`max_domains`).")
}

/// What to do where Stalwart refused the collector's key: the setup gives
/// the key the permissions the checks need.
const SETUP: &str = "run `garrison stalwart setup` again to let it read them";

/// Why Stalwart did not give the collector's key its `what`, by what went
/// wrong: it did not answer, or refused the key for its rate limit, which
/// both pass by themselves; it refused the key, which the setup mends; or
/// it answered in a form this release does not read, which no setup mends,
/// so the words name the answer and where the supported releases are
/// named. `besides` is what else mends the last two, after a comma, such as
/// naming the endpoints for the certificate check.
pub(super) fn not_given(error: &garrison_stalwart::Error, what: &str, besides: &str) -> String {
    use garrison_stalwart::{Error, SUPPORTED};
    match error {
        Error::Unavailable(_) => {
            format!("Stalwart did not answer the collector's request for its {what}")
        }
        Error::Limited(_) => format!(
            "Stalwart refused the collector's key for its rate limit (HTTP 429), so its {what} \
             could not be read"
        ),
        Error::Denied(_) | Error::InvalidToken(_) | Error::Misconfigured(_) => {
            format!("Stalwart did not give its {what} to the collector's API key; {SETUP}{besides}")
        }
        Error::Unreadable(why) => format!(
            "Stalwart answered the collector's request for its {what} in a form this release of \
             Garrison does not read ({why}); {SUPPORTED}{besides}"
        ),
    }
}

/// Stalwart's domains, as the collector's `key` reads them.
pub(super) fn domains(
    context: &Context<'_>,
    key: &str,
) -> Result<Vec<Domain>, garrison_stalwart::Error> {
    JmapClient::new(&context.deployment.stalwart_url, key)
        .with_timeout(Duration::from_secs(8))
        .get::<Domain>("Domain", None, &["name", "dnsZoneFile"])
}

/// A domain as far as it is read.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Domain {
    pub(super) name: String,
    #[serde(default)]
    pub(super) dns_zone_file: Option<String>,
}
