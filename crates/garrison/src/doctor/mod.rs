//! `garrison doctor`: check an installation as a whole, from the services on
//! this host to what visitors see from outside, and say for every problem what
//! to do. It changes nothing. A finding is in order, a warning, a failure or
//! unknown, and unknown never counts as in order.

mod files;
mod host;
pub(crate) mod milter;
mod notify;
mod policy;
mod public;

use garrison_core::config::Config;

use crate::{complain, placeholder, say};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Ok,
    Warn,
    Fail,
    Unknown,
}

#[derive(Debug)]
struct Finding {
    level: Level,
    what: String,
    fix: Option<String>,
}

impl Finding {
    fn ok(what: impl Into<String>) -> Self {
        Self {
            level: Level::Ok,
            what: what.into(),
            fix: None,
        }
    }

    fn warn(what: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            level: Level::Warn,
            what: what.into(),
            fix: Some(fix.into()),
        }
    }

    fn fail(what: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            level: Level::Fail,
            what: what.into(),
            fix: Some(fix.into()),
        }
    }

    fn unknown(what: impl Into<String>) -> Self {
        Self {
            level: Level::Unknown,
            what: what.into(),
            fix: None,
        }
    }

    fn line(&self) -> String {
        let mark = match self.level {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
            Level::Unknown => "?   ",
        };
        match &self.fix {
            Some(fix) => format!("{mark}  {}\n      {fix}", self.what),
            None => format!("{mark}  {}", self.what),
        }
    }
}

fn origins(config: &Config) -> Vec<Finding> {
    [
        ("public_origin", &config.deployment.public_origin),
        ("issuer", &config.deployment.issuer),
    ]
    .into_iter()
    .filter(|(_, origin)| placeholder(origin))
    .map(|(key, origin)| {
        Finding::fail(
            format!("{key} is still the placeholder {origin}"),
            "Set the real address in /etc/garrison/garrison.toml.",
        )
    })
    .collect()
}

fn summary(findings: &[Finding]) -> String {
    let count = |level| {
        findings
            .iter()
            .filter(|finding| finding.level == level)
            .count()
    };
    let (failed, warned, unknown) = (
        count(Level::Fail),
        count(Level::Warn),
        count(Level::Unknown),
    );
    let checks = counted(findings.len(), "check", "checks");
    if failed + warned + unknown == 0 {
        if findings.len() == 1 {
            "The 1 check is in order.".into()
        } else {
            format!("All {checks} are in order.")
        }
    } else {
        format!(
            "{}, {}, {unknown} unknown, of {checks}.",
            counted(failed, "problem", "problems"),
            counted(warned, "warning", "warnings"),
        )
    }
}

/// The settings that the units or nginx's include do not follow, as
/// check-config warns of them.
fn unfollowed(config: &Config) -> Vec<Finding> {
    let include = crate::unfollowed::installed_include();
    crate::unfollowed::settings(config, include.as_deref())
        .into_iter()
        .map(|setting| Finding::warn(setting.what, setting.fix))
        .collect()
}

/// The secrets the units would not hand to their services, and whether the
/// notification channels' are all handed to the collector.
fn secrets(config: &Config) -> (Vec<Finding>, bool) {
    let unloaded = crate::loaded::unloaded(config);
    let channels = !unloaded
        .iter()
        .any(|secret| secret.setting.starts_with("notifications."));
    let findings = unloaded
        .into_iter()
        .map(|secret| Finding::fail(secret.what, secret.fix))
        .collect();
    (findings, channels)
}

/// The lists of Spamhaus' Data Query Service, as check-config judges them:
/// one written without its key that nothing could ask fails, one that holds
/// its key in garrison.toml is a warning.
fn lists(config: &Config) -> Vec<Finding> {
    let refused = crate::dqs::refused(config)
        .into_iter()
        .map(|(what, fix)| Finding::fail(what, fix));
    let warned = crate::dqs::warned(config)
        .into_iter()
        .map(|(what, fix)| Finding::warn(what, fix));
    refused.chain(warned).collect()
}

/// `1 problem`, `2 problems`.
fn counted(number: usize, one: &str, more: &str) -> String {
    format!("{number} {}", if number == 1 { one } else { more })
}

pub(crate) fn run(config: &Config) -> u8 {
    if !rustix::process::geteuid().is_root() {
        complain("Run as root: the checks read files only root may read.");
        return 2;
    }
    let mut findings = origins(config);
    findings.extend(host::checks(config));
    findings.extend(milter::checks(config, &crate::credentials(config)));
    findings.extend(unfollowed(config));
    let (unloaded, channels) = secrets(config);
    findings.extend(unloaded);
    findings.extend(lists(config));
    // A channel whose secret the collector would not have is not judged by
    // what root reads.
    if channels {
        findings.extend(notify::checks(config, &crate::credentials(config)));
    }
    findings.extend(public::checks(config));
    for finding in &findings {
        say(&finding.line());
    }
    say(&format!("\n{}", summary(&findings)));
    u8::from(findings.iter().any(|finding| finding.level == Level::Fail))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the units do not follow is a warning with what to do, as in
    /// check-config: the test configuration's own folders are not the units'.
    #[test]
    fn a_setting_the_units_do_not_follow_is_a_warning() {
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let found = unfollowed(&config);
        assert!(found.iter().all(|finding| finding.level == Level::Warn));
        let said: Vec<&str> = found.iter().map(|finding| finding.what.as_str()).collect();
        for start in [
            "web.state_directory is ",
            "collector.state_directory is ",
            "credentials_directory is ",
            "broker.socket is ",
        ] {
            assert!(said.iter().any(|what| what.starts_with(start)), "{said:?}");
        }
        assert!(
            found[0]
                .line()
                .contains("Remove the setting. To keep Garrison's data on another disk"),
            "{}",
            found[0].line()
        );
    }

    #[test]
    fn a_secret_the_units_do_not_hand_over_fails_and_no_channel_is_judged_by_it() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        assert!(matches!(secrets(&config), (found, true) if found.is_empty()));
        config.broker.native_key =
            garrison_core::credentials::SecretSource::Credential("key".into());
        let (found, channels) = secrets(&config);
        assert!(channels);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].line(),
            "FAIL  broker.native_key is credential:key, but garrison-broker.service loads this \
             secret only as credential:broker-native-key\n      Write broker.native_key = \
             \"credential:broker-native-key\" and keep the secret in \
             /etc/garrison/credentials/broker-native-key."
        );
        config.notifications.token =
            garrison_core::credentials::SecretSource::Credential("token".into());
        assert!(matches!(secrets(&config), (found, false) if found.len() == 2));
    }

    /// A list of Spamhaus' Data Query Service: one written without its key
    /// fails while nothing could ask it; one that holds its key is a warning
    /// that never repeats the key.
    #[test]
    fn the_lists_of_spamhaus_dqs_are_judged_as_check_config_judges_them() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let key = "abcdefghijklmnopqrstuvwxyz";
        let reputation: toml::Table = format!(
            "type = \"reputation\"\nhosts = [\"mail.example.test\"]\n\
             lists = [\"zen.dq.spamhaus.net\", \"{key}.sbl.dq.spamhaus.net\"]\nlists_ipv6 = []"
        )
        .parse()
        .unwrap();
        config.collector.providers.push(reputation);
        let found = lists(&config);
        let lines: Vec<(Level, String)> = found
            .iter()
            .map(|finding| (finding.level, finding.what.clone()))
            .collect();
        assert_eq!(
            lines,
            [
                (
                    Level::Fail,
                    "providers[1].lists names zen.dq.spamhaus.net, a list of Spamhaus' Data \
                     Query Service written without its key, but collector.dqs_key is not set, so \
                     it could not be asked"
                        .to_owned()
                ),
                (
                    Level::Warn,
                    "providers[1].lists names ….sbl.dq.spamhaus.net with the key of Spamhaus' \
                     Data Query Service in it, in garrison.toml, which every user of this host \
                     may read"
                        .to_owned()
                ),
            ]
        );
        assert!(found.iter().all(|finding| !finding.line().contains(key)));
        config.collector.dqs_key = Some(garrison_core::credentials::SecretSource::Credential(
            "spamhaus-dqs-key".into(),
        ));
        assert_eq!(lists(&config).len(), 1);
        assert_eq!(
            crate::dqs::asked_with_key(&config).as_deref(),
            Some("zen.dq.spamhaus.net")
        );
    }

    #[test]
    fn every_finding_says_how_it_stands_and_what_to_do() {
        assert_eq!(Finding::ok("fine").line(), "ok    fine");
        assert_eq!(
            Finding::fail("broken", "Fix it.").line(),
            "FAIL  broken\n      Fix it."
        );
        assert_eq!(Finding::unknown("unclear").line(), "?     unclear");
        let findings = [
            Finding::ok("a"),
            Finding::warn("b", "c"),
            Finding::unknown("d"),
        ];
        assert_eq!(
            summary(&findings),
            "0 problems, 1 warning, 1 unknown, of 3 checks."
        );
        assert_eq!(
            summary(&[Finding::fail("e", "f"), Finding::ok("a")]),
            "1 problem, 0 warnings, 0 unknown, of 2 checks."
        );
        assert_eq!(summary(&[Finding::ok("a")]), "The 1 check is in order.");
        assert_eq!(
            summary(&[Finding::ok("a"), Finding::ok("b")]),
            "All 2 checks are in order."
        );
    }
}

#[cfg(test)]
mod broken_tests;
