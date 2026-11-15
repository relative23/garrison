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

/// One of the files doctor checks: what it is, whether its group may read
/// it, the command that makes it, and what gives it owner and mode.
struct Private<'a> {
    what: &'a str,
    group_read: bool,
    made_by: &'a str,
    kept: String,
}

/// Root-owned and readable by nobody else (`group` may read the policy).
fn private(path: &Path, file: &Private<'_>) -> Finding {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Finding::fail(
            format!("{} is missing: {}", file.what, path.display()),
            format!("Run `{}`, which makes it.", file.made_by),
        );
    };
    // Neither the installer nor the services follow a link here or change
    // a folder: only the file itself does.
    if !metadata.is_file() {
        return Finding::fail(
            format!(
                "{} is a link or a folder, not a file: {}",
                file.what,
                path.display()
            ),
            format!(
                "Remove it; then `{}` makes the file itself there.",
                file.made_by
            ),
        );
    }
    let allowed = if file.group_read { 0o640 } else { 0o600 };
    let mode = metadata.mode() & 0o777;
    if metadata.uid() == 0 && mode & !allowed == 0 {
        Finding::ok(format!("{} is private ({mode:o})", file.what))
    } else {
        Finding::fail(
            format!(
                "{} is not root-owned with mode {allowed:o} or less (mode {mode:o})",
                path.display()
            ),
            file.kept.clone(),
        )
    }
}

pub(super) fn files(config: &Config) -> Vec<Finding> {
    // Where the broker reads it. The installer gives it owner and mode.
    let policy = Private {
        what: "the access policy",
        group_read: true,
        made_by: "garrison access init",
        kept: "Run the installer again; it sets owner and mode.".to_owned(),
    };
    let mut findings = vec![private(&config.broker.policy, &policy)];
    // Root reads it; the broker, in its unit's sandbox, may not.
    if let Some((what, fix)) = units::hidden_policy(&config.broker.policy) {
        findings.push(Finding::fail(what, format!("{fix}.")));
    }
    // Setup writes these root's with mode 600, and nothing changes them after.
    for name in CREDENTIALS {
        let path = config.credentials_directory.join(name);
        let credential = Private {
            what: name,
            group_read: false,
            made_by: "garrison stalwart setup",
            kept: format!(
                "Make it root's with mode 600: chown root {0} && chmod 600 {0}",
                path.display()
            ),
        };
        findings.push(private(&path, &credential));
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

    /// Each fix names what makes the file, or what gives it owner and mode.
    #[test]
    fn each_file_names_what_makes_it_and_what_keeps_it_private() {
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let fix = |found: &[Finding], what: &str| {
            let finding = found
                .iter()
                .find(|finding| finding.what.starts_with(what))
                .unwrap_or_else(|| panic!("{what}"));
            finding.fix.clone().unwrap()
        };
        let missing = files(&config);
        assert_eq!(
            fix(&missing, "the access policy is missing"),
            "Run `garrison access init`, which makes it."
        );
        for name in CREDENTIALS {
            assert_eq!(
                fix(&missing, &format!("{name} is missing")),
                "Run `garrison stalwart setup`, which makes it.",
                "{name}"
            );
        }
        // A folder in the policy's place, and files that are this user's.
        fs::create_dir_all(&config.broker.policy).unwrap();
        let key = config.credentials_directory.join("broker-native-key");
        fs::create_dir_all(&config.credentials_directory).unwrap();
        fs::write(&key, "key").unwrap();
        let present = files(&config);
        assert_eq!(
            fix(&present, "the access policy is a link or a folder"),
            "Remove it; then `garrison access init` makes the file itself there."
        );
        assert_eq!(
            fix(&present, &format!("{} is not root-owned", key.display())),
            format!(
                "Make it root's with mode 600: chown root {0} && chmod 600 {0}",
                key.display()
            )
        );
        fs::remove_dir(&config.broker.policy).unwrap();
        fs::write(&config.broker.policy, "{}").unwrap();
        let policy = files(&config);
        assert_eq!(
            fix(
                &policy,
                &format!("{} is not root-owned", config.broker.policy.display())
            ),
            "Run the installer again; it sets owner and mode."
        );
    }
}
