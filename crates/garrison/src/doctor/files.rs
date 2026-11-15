//! Files that must stay private: the access policy, root's and readable by
//! the broker's group alone, and the credentials, root's alone.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use garrison_core::config::Config;

use super::Finding;
use crate::units;

const CREDENTIALS: [&str; 4] = [
    "webhook-signature-key",
    "collector-native-key",
    "broker-native-key",
    "metrics-credential",
];

/// Root-owned and readable by nobody else (`group` may read the policy).
fn private(path: &Path, what: &str, group_read: bool) -> Finding {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Finding::fail(
            format!("{what} is missing: {}", path.display()),
            "Run `garrison stalwart setup` or the installer again.",
        );
    };
    let allowed = if group_read { 0o640 } else { 0o600 };
    let mode = metadata.mode() & 0o777;
    if metadata.is_file() && metadata.uid() == 0 && mode & !allowed == 0 {
        Finding::ok(format!("{what} is private ({mode:o})"))
    } else {
        Finding::fail(
            format!(
                "{} is not root-owned with mode {allowed:o} or less (mode {mode:o})",
                path.display()
            ),
            "Run the installer again; it sets owner and mode.",
        )
    }
}

pub(super) fn files(config: &Config) -> Vec<Finding> {
    // Where the broker reads it.
    let mut findings = vec![private(&config.broker.policy, "the access policy", true)];
    // Root reads it; the broker, in its unit's sandbox, may not.
    if let Some((what, fix)) = units::hidden_policy(&config.broker.policy) {
        findings.push(Finding::fail(what, format!("{fix}.")));
    }
    for name in CREDENTIALS {
        findings.push(private(
            &config.credentials_directory.join(name),
            name,
            false,
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::super::Level;
    use super::*;

    /// The access policy is looked at where the configuration names it,
    /// which is where the broker reads it.
    #[test]
    fn the_policy_is_judged_where_the_configuration_names_it() {
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let policy = &files(&config)[0];
        assert_eq!(
            policy.what,
            format!(
                "the access policy is missing: {}",
                config.broker.policy.display()
            )
        );
        // Root may read a policy that the broker's unit hides from it.
        let mut hidden = config.clone();
        hidden.broker.policy = "/home/doctor-test/policy.json".into();
        let found = files(&hidden);
        let named = found
            .iter()
            .find(|finding| finding.what.contains("(ProtectHome=true)"))
            .unwrap();
        assert_eq!(named.level, Level::Fail, "{}", named.line());
    }
}
