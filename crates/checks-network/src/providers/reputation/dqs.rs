//! Spamhaus' Data Query Service. Its zones hold the subscriber's key as
//! their first label, `KEY.zen.dq.spamhaus.net`. A zone written without it,
//! `zen.dq.spamhaus.net`, is asked with the key the collector reads from
//! `collector.dqs_key`, so that garrison.toml, which every user of the host
//! may read, need not hold it; the key goes into the question and nowhere
//! else.

use std::net::IpAddr;

use super::asker::Asker;
use super::verdict::Said;
use super::{Reputation, shown};
use crate::context::{Context, DqsKey};

/// What a list's zone is of the Data Query Service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Dqs {
    /// `LIST.dq.spamhaus.net`, asked with the key before it.
    Keyless,
    /// `KEY.LIST.dq.spamhaus.net`, with the key written in it.
    Keyed,
    /// No zone of the service.
    Other,
}

pub(super) fn dqs(zone: &str) -> Dqs {
    match zone.strip_suffix(".dq.spamhaus.net") {
        Some(before) if before.contains('.') => Dqs::Keyed,
        Some(before) if !before.is_empty() => Dqs::Keyless,
        _ => Dqs::Other,
    }
}

/// Why a zone written without its key cannot be asked in a run with `key`;
/// `None` where the run has a key.
pub(super) fn missing(key: &DqsKey) -> Option<String> {
    match key {
        DqsKey::Key(_) => None,
        DqsKey::Missing(why) => Some(why.clone()),
        DqsKey::Unset => Some("collector.dqs_key is not set".to_owned()),
    }
}

/// The zone to ask for `zone`: itself, or for one written without its key,
/// with `key` before it; why it cannot be asked where this run has no key.
pub(super) fn asked(zone: &str, key: &DqsKey) -> Result<String, String> {
    match (dqs(zone), key) {
        (Dqs::Keyless, DqsKey::Key(key)) => Ok(format!("{key}.{zone}")),
        (Dqs::Keyless, _) => Err(missing(key).unwrap_or_default()),
        _ => Ok(zone.to_owned()),
    }
}

/// What each of `lists` says of `address`, named as the cards name it. A
/// zone written without its key is asked with the run's, and where the run
/// has none it is not asked and `keyless` says why.
pub(super) fn said(
    lists: &[String],
    address: IpAddr,
    asker: &mut Asker,
    context: &Context<'_>,
    keyless: &mut Option<String>,
) -> Vec<(String, Said)> {
    lists
        .iter()
        .map(|zone| {
            let said = match asked(zone, &context.dqs_key) {
                Ok(name) => asker.list(&name, address),
                Err(why) => {
                    let said = Said::Unanswered(format!("not asked: {why}"));
                    *keyless = Some(why);
                    said
                }
            };
            (shown(zone), said)
        })
        .collect()
}

impl Reputation {
    /// The zones of the Data Query Service among the lists, as the options
    /// name them (`lists` or `lists_ipv6`), each as the cards show it and
    /// with whether it holds its key: `garrison check-config` says what
    /// such a zone needs.
    #[must_use]
    pub fn dqs_zones(&self) -> Vec<(&'static str, String, bool)> {
        [("lists", &self.lists), ("lists_ipv6", &self.lists_ipv6)]
            .into_iter()
            .flat_map(|(option, zones)| {
                zones.iter().filter_map(move |zone| match dqs(zone) {
                    Dqs::Other => None,
                    kind => Some((option, shown(zone), kind == Dqs::Keyed)),
                })
            })
            .collect()
    }
}
