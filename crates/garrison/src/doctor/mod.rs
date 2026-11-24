//! `garrison doctor`: check an installation as a whole, from the services on
//! this host to what visitors see from outside, and say for every problem what
//! to do. It changes nothing. A finding is in order, a warning, a failure or
//! unknown, and unknown never counts as in order.

mod files;
mod host;
mod keys;
pub(crate) mod milter;
mod notify;
pub(crate) mod policy;
mod public;
mod states;

use garrison_core::config::Config;

use crate::state::State;
use crate::{complain, placeholder, say};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Ok,
    Warn,
    Fail,
    Unknown,
}

/// What a check found: how it stands, and the state that says it.
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    level: Level,
    state: State,
}

impl Finding {
    fn ok(state: State) -> Self {
        Self {
            level: Level::Ok,
            state,
        }
    }

    fn warn(state: State) -> Self {
        Self {
            level: Level::Warn,
            state,
        }
    }

    fn fail(state: State) -> Self {
        Self {
            level: Level::Fail,
            state,
        }
    }

    fn unknown(state: State) -> Self {
        Self {
            level: Level::Unknown,
            state,
        }
    }

    fn line(&self) -> String {
        let mark = match self.level {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
            Level::Unknown => "?   ",
        };
        format!("{mark}  {}", self.state)
    }
}

fn origins(config: &Config) -> Vec<Finding> {
    [
        ("public_origin", &config.deployment.public_origin),
        ("issuer", &config.deployment.issuer),
    ]
    .into_iter()
    .filter(|(_, origin)| placeholder(origin))
    .map(|(key, origin)| Finding::fail(states::placeholder(key, origin)))
    .collect()
}

fn summary(findings: &[Finding]) -> State {
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
    if failed > 0 {
        states::problems(failed, warned, unknown, findings.len())
    } else if warned + unknown > 0 {
        states::no_problem(warned, unknown, findings.len())
    } else {
        states::in_order(findings.len())
    }
}

/// The settings that the units or nginx's include do not follow, as
/// check-config warns of them.
fn unfollowed(config: &Config) -> Vec<Finding> {
    let include = crate::unfollowed::installed_include();
    crate::unfollowed::settings(config, include.as_deref())
        .into_iter()
        .map(|setting| Finding::warn(states::unfollowed(setting)))
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
        .map(|secret| Finding::fail(states::unloaded(secret)))
        .collect();
    (findings, channels)
}

/// The lists of Spamhaus' Data Query Service, as check-config judges them:
/// one written without its key that nothing could ask fails, one that holds
/// its key in garrison.toml is a warning.
fn lists(config: &Config) -> Vec<Finding> {
    let refused = crate::dqs::refused(config)
        .into_iter()
        .map(|said| Finding::fail(states::dqs_unasked(said)));
    let warned = crate::dqs::warned(config)
        .into_iter()
        .map(|said| Finding::warn(states::dqs_key_written(said)));
    refused.chain(warned).collect()
}

pub(crate) fn run(config: &Config) -> u8 {
    if !rustix::process::geteuid().is_root() {
        complain(&states::not_root().to_string());
        return 2;
    }
    let mut findings = origins(config);
    findings.extend(host::checks(config));
    findings.extend(keys::checks(config, &crate::credentials(config)));
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
        let said: Vec<&str> = found
            .iter()
            .map(|finding| finding.state.text.as_str())
            .collect();
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
             secret only as credential:broker-native-key [doctor-secret-unloaded]\n      Write \
             broker.native_key = \
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
            .map(|finding| (finding.level, finding.state.text.clone()))
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

    /// A line is its level's mark and its state; the last line, the state the
    /// levels' counts make.
    #[test]
    fn every_finding_says_how_it_stands_and_what_to_do() {
        let state = || states::host::unsynchronized();
        for (finding, mark) in [
            (Finding::ok(state()), "ok    "),
            (Finding::warn(state()), "warn  "),
            (Finding::fail(state()), "FAIL  "),
            (Finding::unknown(state()), "?     "),
        ] {
            assert_eq!(finding.line(), format!("{mark}{}", state()));
        }
        let findings = [
            Finding::ok(state()),
            Finding::warn(state()),
            Finding::unknown(state()),
        ];
        assert_eq!(summary(&findings), states::no_problem(1, 1, 3));
        assert_eq!(
            summary(&[Finding::fail(state()), Finding::ok(state())]),
            states::problems(1, 0, 0, 2)
        );
        assert_eq!(summary(&[Finding::ok(state())]), states::in_order(1));
        assert_eq!(
            summary(&[Finding::ok(state()), Finding::ok(state())]),
            states::in_order(2)
        );
    }
}

#[cfg(test)]
mod broken_tests;
