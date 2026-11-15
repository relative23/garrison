//! Files that must stay private: the access policy, root's and readable by
//! the broker's group alone, and the credentials, root's alone. The units
//! load every credential (`LoadCredential=`), and systemd starts none of
//! them without its file, so each must be there; a file that may be empty,
//! which means none, is in order empty unless the configuration reads it.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use garrison_core::config::Config;

use super::{Finding, Level};
use crate::units;

/// The keys setup writes, which every installation reads.
const KEYS: [&str; 3] = [
    "webhook-signature-key",
    "collector-native-key",
    "broker-native-key",
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

/// What of the configuration reads the file `name` and so needs it filled,
/// with how to fill it; `None` where an empty file serves. The notification
/// channels' files are judged with the channels.
fn reader(config: &Config, name: &str) -> Option<(&'static str, String)> {
    let scraped = config.collector.metrics_credential.is_some()
        && config.collector.providers.iter().any(|provider| {
            provider.get("type").and_then(toml::Value::as_str) == Some("prometheus")
        });
    if name == "spamhaus-dqs-key" {
        let zone = crate::dqs::asked_with_key(config)?;
        let path = config.credentials_directory.join(name);
        return Some((
            "the reputation check asks a list of Spamhaus' Data Query Service with it",
            format!(
                "Write the key into it ({zone} is asked with it): install -m 600 /dev/null {0} \
                 && sh -c 'cat > {0}', then paste the key and press Enter and Ctrl-D.",
                path.display()
            ),
        ));
    }
    (name == "metrics-credential" && scraped).then(|| {
        (
            "the prometheus check reads Stalwart's exporter with it",
            "Run `garrison stalwart setup`, which writes it while Stalwart's exporter is \
             Garrison's or off; for an exporter of another's, write its user name and password \
             into it as configuration.md says (collector.metrics_credential)."
                .to_owned(),
        )
    })
}

/// The units that load the file `name`, as a sentence names them.
fn loaders(name: &str) -> String {
    let loading: Vec<&str> = units::SECRETS
        .iter()
        .filter(|(_, _, loaded)| *loaded == name)
        .flat_map(|(_, units, _)| units.iter().copied())
        .collect();
    loading.join(" and ")
}

/// An empty file that may be empty: in order where nothing reads it, a
/// failure with the way to fill it where something does. A file that holds
/// something is judged by owner and mode alone (`kept`).
fn judged(
    name: &str,
    empty: bool,
    mode: u32,
    reader: Option<(&str, String)>,
    kept: Finding,
) -> Finding {
    match (empty, reader) {
        (true, Some((reads, fill))) => Finding::fail(format!("{name} is empty, but {reads}"), fill),
        (true, None) => Finding::ok(format!("{name} is empty, which means none ({mode:o})")),
        (false, _) => kept,
    }
}

/// A file the units load that may be empty, which means none.
fn optional(config: &Config, name: &str) -> Finding {
    let path = config.credentials_directory.join(name);
    let made = format!("install -m 600 /dev/null {}", path.display());
    let reads = reader(config, name);
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        let fix = reads.map_or_else(
            || format!("Make it, empty, which means none: {made}"),
            |(_, fill)| fill,
        );
        return Finding::fail(
            format!(
                "{name} is missing: {}; systemd starts {} only with it",
                path.display(),
                loaders(name)
            ),
            fix,
        );
    };
    let kept = private(
        &path,
        &Private {
            what: name,
            group_read: false,
            made_by: &made,
            kept: format!(
                "Make it root's with mode 600: chown root {0} && chmod 600 {0}",
                path.display()
            ),
        },
    );
    if kept.level != Level::Ok {
        return kept;
    }
    let empty = fs::read(&path).is_ok_and(|data| data.trim_ascii().is_empty());
    judged(name, empty, metadata.mode() & 0o777, reads, kept)
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
    // And the checks' paths, which the collector reads in its own.
    if let Ok(providers) = garrison_collector::build(&config.collector.providers) {
        for (what, fix) in units::hidden_paths(&providers) {
            findings.push(Finding::fail(what, format!("{fix}.")));
        }
    }
    // Setup writes these root's with mode 600, and nothing changes them after.
    for name in KEYS {
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
    // The installer keeps these, empty where nothing needs them.
    for name in units::COLLECTOR_FILES
        .into_iter()
        .chain(units::NOTIFICATION_FILES)
    {
        findings.push(optional(config, name));
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
        // And a check's path that the collector's unit hides from it.
        let mut check = config.clone();
        check.collector.providers.push(
            "type = \"bulwark\"\nadmin_directory = \"/root/bulwark\""
                .parse()
                .unwrap(),
        );
        let found = files(&check);
        let named = found
            .iter()
            .find(|finding| {
                finding
                    .what
                    .starts_with("providers[bulwark].admin_directory")
            })
            .unwrap();
        assert_eq!(named.level, Level::Fail, "{}", named.line());
        assert!(
            named.line().contains("Paths the collector cannot see"),
            "{}",
            named.line()
        );
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
        for name in KEYS {
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

    /// The finding that starts with `what`.
    fn starting<'a>(findings: &'a [Finding], what: &str) -> &'a Finding {
        findings
            .iter()
            .find(|finding| finding.what.starts_with(what))
            .unwrap_or_else(|| panic!("no finding {what}: {findings:?}"))
    }

    /// systemd starts no unit whose credential file is missing. A file that
    /// may be empty is named with the command that makes it, empty, which
    /// means none; where the configuration reads it, with how to fill it.
    #[test]
    fn a_file_the_units_load_is_named_where_it_is_missing() {
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let found = files(&config);
        for name in ["metrics-credential", "ntfy-token", "notify-webhook-url"] {
            let path = config.credentials_directory.join(name);
            let missing = starting(&found, &format!("{name} is missing"));
            assert_eq!(missing.level, Level::Fail, "{name}");
            assert!(
                missing.what.contains("garrison-collect.service"),
                "{}",
                missing.what
            );
            assert_eq!(
                missing.fix.as_deref(),
                Some(
                    format!(
                        "Make it, empty, which means none: install -m 600 /dev/null {}",
                        path.display()
                    )
                    .as_str()
                ),
                "{name}"
            );
        }
        assert!(
            starting(&found, "ntfy-token is missing")
                .what
                .contains("garrison-watch.service")
        );
    }

    /// A file that may be empty is in order empty where nothing reads it;
    /// where the configuration reads it, empty is a failure with the way to
    /// fill it. (Owner and mode come first, which a test cannot give a
    /// file unless it runs as root.)
    #[test]
    fn an_empty_file_is_in_order_unless_the_configuration_reads_it() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let kept = || Finding::ok("metrics-credential is private (600)");
        let unread = judged(
            "metrics-credential",
            true,
            0o600,
            reader(&config, "metrics-credential"),
            kept(),
        );
        assert_eq!(
            (unread.level, unread.what.as_str()),
            (
                Level::Ok,
                "metrics-credential is empty, which means none (600)"
            )
        );
        let mut prometheus = toml::Table::new();
        prometheus.insert("type".into(), "prometheus".into());
        config.collector.providers.push(prometheus);
        let read = judged(
            "metrics-credential",
            true,
            0o600,
            reader(&config, "metrics-credential"),
            kept(),
        );
        assert_eq!(read.level, Level::Fail, "{}", read.line());
        assert_eq!(
            read.what,
            "metrics-credential is empty, but the prometheus check reads Stalwart's exporter with it"
        );
        assert!(
            read.fix
                .as_deref()
                .unwrap()
                .starts_with("Run `garrison stalwart setup`, which writes it"),
            "{}",
            read.line()
        );
        // Filled, it is judged by owner and mode alone.
        let filled = judged(
            "metrics-credential",
            false,
            0o600,
            reader(&config, "metrics-credential"),
            kept(),
        );
        assert_eq!(filled.what, "metrics-credential is private (600)");
        // Missing where it is read, it is named with how to fill it.
        let found = files(&config);
        let missing = starting(&found, "metrics-credential is missing");
        assert!(
            missing
                .fix
                .as_deref()
                .unwrap()
                .starts_with("Run `garrison stalwart setup`, which writes it"),
            "{}",
            missing.line()
        );
        // The notification channels' files are judged with the channels.
        assert_eq!(reader(&config, "ntfy-token"), None);
    }

    /// The key of Spamhaus' Data Query Service is read where a list written
    /// without it is configured and `collector.dqs_key` names its file.
    #[test]
    fn the_dqs_key_is_read_where_a_list_written_without_it_is_asked() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        assert_eq!(reader(&config, "spamhaus-dqs-key"), None);
        let reputation: toml::Table = "type = \"reputation\"\nhosts = [\"mail.example.test\"]\n\
             lists = [\"zen.dq.spamhaus.net\"]\nlists_ipv6 = []"
            .parse()
            .unwrap();
        config.collector.providers.push(reputation);
        assert_eq!(reader(&config, "spamhaus-dqs-key"), None);
        config.collector.dqs_key = Some(garrison_core::credentials::SecretSource::Credential(
            "spamhaus-dqs-key".into(),
        ));
        let path = config.credentials_directory.join("spamhaus-dqs-key");
        let found = files(&config);
        let missing = starting(&found, "spamhaus-dqs-key is missing");
        assert_eq!(missing.level, Level::Fail);
        assert_eq!(
            missing.fix.as_deref(),
            Some(
                format!(
                    "Write the key into it (zen.dq.spamhaus.net is asked with it): install -m 600 \
                     /dev/null {0} && sh -c 'cat > {0}', then paste the key and press Enter and \
                     Ctrl-D.",
                    path.display()
                )
                .as_str()
            )
        );
        let empty = judged(
            "spamhaus-dqs-key",
            true,
            0o600,
            reader(&config, "spamhaus-dqs-key"),
            Finding::ok("spamhaus-dqs-key is private (600)"),
        );
        assert_eq!(
            (empty.level, empty.what.as_str()),
            (
                Level::Fail,
                "spamhaus-dqs-key is empty, but the reputation check asks a list of Spamhaus' \
                 Data Query Service with it"
            )
        );
    }
}
