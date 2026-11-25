//! The configuration a command loads, and what `garrison check-config` says
//! of it.

use std::fmt::Display;
use std::path::Path;

use crate::state::{State, states};

states! {
    pub(crate) fn unloadable(path: &Path, error: impl Display) = "config-unloadable":
        "Cannot load {}: {error}", path.display();
    /// The switch row's script, which `stalwart-switch` prints the include for.
    pub(crate) fn switch_missing(script: &Path) = "switch-script-missing":
        "{} is missing; build the interface first.", script.display();
    /// `error`: why the providers do not build, in the collector's words.
    pub(crate) fn providers_refused(error: impl Display) = "check-config-providers":
        "Configuration not usable: {error}";
    /// `line`: a secret's setting that its unit would not hand over, as
    /// `loaded` words it.
    pub(crate) fn unloaded(line: &str) = "check-config-unloaded":
        "Configuration not usable: {line}";
    /// A list of Spamhaus' Data Query Service nothing could ask, as `dqs`
    /// words it.
    pub(crate) fn dqs_refused(what: &str, fix: &str) = "check-config-dqs-refused":
        "Configuration not usable: {what}. {fix}";
    /// A check's path that the collector's unit hides, as the units word it.
    pub(crate) fn hidden_check(refusal: &str) = "check-config-hidden-check":
        "Configuration not usable: {refusal}";
    pub(crate) fn valid(providers: usize, actions: usize) = "check-config-valid":
        "Configuration valid: {providers} providers, {actions} actions.";
    pub(crate) fn placeholder(setting: &str, origin: &str) = "check-config-placeholder":
        "Warning: deployment.{setting} {origin} is a placeholder; set the real name.";
    /// A setting the units or nginx's include do not follow, as `unfollowed`
    /// words it.
    pub(crate) fn unfollowed(what: &str, fix: &str) = "check-config-unfollowed":
        "Warning: {what}. {fix}";
    /// A list of Spamhaus' Data Query Service with its key in garrison.toml.
    pub(crate) fn dqs_warned(what: &str, fix: &str) = "check-config-dqs-warned":
        "Warning: {what}. {fix}";
    /// A hidden path of a configuration that no unit reads, such as a draft's.
    pub(crate) fn hidden_check_warned(warning: &str) = "check-config-hidden-check-warned":
        "Warning: {warning}";
    /// `reason`: why the broker does not take the access policy.
    pub(crate) fn policy_refused(reason: impl Display) = "check-config-policy-refused":
        "Access policy not usable: {reason}";
    /// What the broker would meet in the policy, or a hidden place of the
    /// policy of a configuration no unit reads.
    pub(crate) fn policy_warned(warning: &str) = "check-config-policy-warned":
        "Warning: {warning}";
    pub(crate) fn policy_valid(path: &Path) = "check-config-policy-valid":
        "Access policy valid: {}", path.display();
}

/// `command` uses the units' configuration where `units`, else none.
pub(crate) fn not_followed(command: &str, units: bool, named: &Path) -> State {
    let why = if units {
        "uses /etc/garrison/garrison.toml, the units' configuration"
    } else {
        "reads no configuration"
    };
    State::new(
        "config-not-followed",
        format!(
            "garrison {command} {why}, so it takes no --config ({}).",
            named.display()
        ),
    )
}
