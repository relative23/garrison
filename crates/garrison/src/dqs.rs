//! Spamhaus' Data Query Service in garrison.toml. A list written without
//! its key, `zen.dq.spamhaus.net`, is asked with the key the collector
//! reads from `collector.dqs_key`, so that setting must be there. A list
//! that holds its key, as earlier releases had it, works as before, but
//! garrison.toml is readable by every user of the host. check-config and
//! doctor say both, and never the key itself.

use garrison_collector::providers::Reputation;
use garrison_core::config::Config;

use crate::units;

/// Where the key belongs.
fn file() -> String {
    format!("{}/spamhaus-dqs-key", units::CREDENTIALS)
}

/// The lists of the service in the reputation checks: the option of
/// `providers[N]` that names each, as the cards name it, and whether it
/// holds its key there.
fn zones(config: &Config) -> Vec<(String, String, bool)> {
    let mut found = Vec::new();
    for (index, raw) in config.collector.providers.iter().enumerate() {
        if raw.get("type").and_then(toml::Value::as_str) != Some("reputation") {
            continue;
        }
        // A check whose options do not read is refused as such.
        let Ok(reputation) = Reputation::new(raw) else {
            continue;
        };
        for (option, shown, keyed) in reputation.dqs_zones() {
            found.push((format!("providers[{index}].{option}"), shown, keyed));
        }
    }
    found
}

/// The lists written without their key where `collector.dqs_key` is not
/// set: none of them could be asked. Each with what to do.
pub(crate) fn refused(config: &Config) -> Vec<(String, String)> {
    if config.collector.dqs_key.is_some() {
        return Vec::new();
    }
    zones(config)
        .into_iter()
        .filter(|(_, _, keyed)| !keyed)
        .map(|(named, shown, _)| {
            (
                format!(
                    "{named} names {shown}, a list of Spamhaus' Data Query Service written \
                     without its key, but collector.dqs_key is not set, so it could not be asked"
                ),
                format!(
                    "Keep the key in {} (root, mode 0600) and set collector.dqs_key = \
                     \"credential:spamhaus-dqs-key\".",
                    file()
                ),
            )
        })
        .collect()
}

/// The lists that hold their key in garrison.toml, each with what to do.
pub(crate) fn warned(config: &Config) -> Vec<(String, String)> {
    zones(config)
        .into_iter()
        .filter(|(_, _, keyed)| *keyed)
        .map(|(named, shown, _)| {
            let plain = shown.trim_start_matches("….");
            (
                format!(
                    "{named} names {shown} with the key of Spamhaus' Data Query Service in it, in \
                     garrison.toml, which every user of this host may read"
                ),
                format!(
                    "Write the zone without the key, {plain}, keep the key in {} (root, mode \
                     0600) and set collector.dqs_key = \"credential:spamhaus-dqs-key\".",
                    file()
                ),
            )
        })
        .collect()
}

/// The first list that the collector asks with the key of
/// `collector.dqs_key`, where that is set, as the cards name it.
pub(crate) fn asked_with_key(config: &Config) -> Option<String> {
    config.collector.dqs_key.as_ref()?;
    zones(config)
        .into_iter()
        .find(|(_, _, keyed)| !keyed)
        .map(|(_, shown, _)| shown)
}
