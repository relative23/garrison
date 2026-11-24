//! `garrison check-config`: whether the configuration, its providers and
//! the access policy are usable, as the services that read them meet them.

use std::path::Path;

use garrison_authz::Authority;
use garrison_core::config::Config;

use crate::{complain, credentials, dqs, loaded, placeholder, say, unfollowed, units};

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
    match Authority::new(config, credentials(config)).policy() {
        Ok(_) => {
            say(&format!(
                "Access policy valid: {}",
                config.broker.policy.display()
            ));
            0
        }
        Err(error) => {
            complain(&format!("Access policy not usable: {error}"));
            1
        }
    }
}
