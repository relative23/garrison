//! `garrison check-config`: whether the configuration, its providers and
//! the access policy are usable, as the services that read them meet them.

use std::path::Path;

use garrison_core::config::{self, Config};

use crate::doctor::policy::{self, Met, Unread};
use crate::{complain, dqs, loaded, placeholder, say, unfollowed, units};

pub(crate) fn run(config: &Config, path: &Path) -> u8 {
    let providers = match garrison_collector::build(&config.collector.providers) {
        Ok(providers) => providers,
        Err(error) => {
            complain(&format!("Configuration not usable: {error}"));
            return 2;
        }
    };
    let unloaded = loaded::unloaded(config);
    let unaskable = dqs::refused(config);
    // Root reads the checks' paths here; the collector, in its unit's sandbox, may not.
    let places = units::collector_places(&providers, path);
    if !unloaded.is_empty() || !unaskable.is_empty() || places.is_err() {
        for secret in &unloaded {
            complain(&format!("Configuration not usable: {}", secret.line()));
        }
        for (what, fix) in &unaskable {
            complain(&format!("Configuration not usable: {what}. {fix}"));
        }
        for refusal in places.err().unwrap_or_default() {
            complain(&format!("Configuration not usable: {refusal}"));
        }
        return 2;
    }
    say(&format!(
        "Configuration valid: {} providers, {} actions.",
        config.collector.providers.len(),
        config.broker.actions.len()
    ));
    let deployment = &config.deployment;
    for (setting, origin) in [
        ("public_origin", &deployment.public_origin),
        ("issuer", &deployment.issuer),
    ] {
        if placeholder(origin) {
            complain(&format!(
                "Warning: deployment.{setting} {origin} is a placeholder; set the real name."
            ));
        }
    }
    let include = unfollowed::installed_include();
    for setting in unfollowed::settings(config, include.as_deref()) {
        complain(&format!("Warning: {}. {}", setting.what, setting.fix));
    }
    for (what, fix) in dqs::warned(config) {
        complain(&format!("Warning: {what}. {fix}"));
    }
    for warning in places.unwrap_or_default() {
        complain(&format!("Warning: {warning}"));
    }
    // Root reads the policy here; the broker, in its unit's sandbox, may not.
    match units::policy_place(&config.broker.policy, path) {
        Err(refusal) => {
            complain(&format!("Access policy not usable: {refusal}"));
            return 1;
        }
        Ok(Some(warning)) => complain(&format!("Warning: {warning}")),
        Ok(None) => {}
    }
    // Nor may it read what root reads, which is judged for the broker: a
    // refusal for the configuration the units read, as above, a warning for
    // any other, such as the copy a restore's check names.
    let units_read = path == Path::new(config::DEFAULT_PATH);
    match refused(policy::as_the_broker(&config.broker.policy), units_read) {
        Err(said) => {
            complain(&format!("Access policy not usable: {said}"));
            return 1;
        }
        Ok(Some(said)) => complain(&format!("Warning: {said}")),
        Ok(None) => {}
    }
    match policy::granted(config) {
        Ok(_) => {
            say(&format!(
                "Access policy valid: {}",
                config.broker.policy.display()
            ));
            0
        }
        Err(Unread::TooLarge) => {
            let said = crate::access::too_large(&config.broker.policy);
            complain(&format!("Access policy not usable: {said}"));
            1
        }
        Err(Unread::Other(error)) => {
            complain(&format!("Access policy not usable: {error}"));
            1
        }
    }
}

/// Whether check-config refuses what the broker meets (`Err`), or warns of
/// it (`Some`): a policy that is missing always, one the broker does not
/// take where `units_read`, the configuration the units read.
fn refused(met: Met, units_read: bool) -> Result<Option<String>, String> {
    match met {
        Met::Missing(said) => Err(said),
        Met::Refused(said) if units_read => Err(said),
        Met::Refused(said) | Met::Taken(Some(said)) => Ok(Some(said)),
        Met::Taken(None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_the_broker_does_not_take_is_refused_where_the_units_read_it() {
        let said = || "garrison-broker may not read the access policy".to_owned();
        assert_eq!(refused(Met::Refused(said()), true), Err(said()));
        assert_eq!(refused(Met::Refused(said()), false), Ok(Some(said())));
        for units_read in [true, false] {
            assert_eq!(refused(Met::Missing(said()), units_read), Err(said()));
            assert_eq!(
                refused(Met::Taken(Some(said())), units_read),
                Ok(Some(said()))
            );
            assert_eq!(refused(Met::Taken(None), units_read), Ok(None));
        }
    }
}
