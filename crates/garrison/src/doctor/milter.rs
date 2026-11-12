//! The macro milter, where the configuration has it: the unit runs, the
//! filter answers as a milter, and setup told Stalwart of it. And the other
//! way round: a filter Stalwart still asks although the configuration
//! dropped it, which makes Stalwart defer mail.

use std::path::Path;
use std::time::Duration;

use garrison_core::config::Config;

use super::Finding;
use crate::units;

const SETUP: &str = "Run `garrison stalwart setup`.";

/// What `answered` says of the filter on `port`.
fn answering(port: u16, answered: Result<(), String>) -> Finding {
    match answered {
        Ok(()) => Finding::ok(format!("the macro milter answers on 127.0.0.1:{port}")),
        Err(error) => Finding::fail(
            format!("the macro milter does not answer on 127.0.0.1:{port}: {error}"),
            format!("journalctl -u {} -n 50 shows why.", units::MILTER),
        ),
    }
}

/// Whether Stalwart knows of the filter as the configuration has it.
/// `entered` is setup's note of the entry it made.
fn told(configured: bool, entered: bool) -> Option<Finding> {
    match (configured, entered) {
        (true, true) => Some(Finding::ok("setup told Stalwart of the macro milter")),
        (true, false) => Some(Finding::warn(
            "the macro milter runs, but Stalwart was not told of it and asks it nothing",
            SETUP,
        )),
        (false, true) => Some(Finding::fail(
            "Stalwart still asks the macro milter, which the configuration no longer has",
            format!(
                "{SETUP} It takes the filter out of Stalwart; until then mail may be deferred."
            ),
        )),
        (false, false) => None,
    }
}

pub(super) fn checks(config: &Config, credentials: &Path) -> Vec<Finding> {
    let entered = credentials.join(units::MILTER_ENTRY).exists();
    let mut findings = Vec::new();
    if let Some(milter) = &config.milter {
        findings.push(answering(
            milter.port,
            garrison_milter::answers(milter.port, Duration::from_secs(3)),
        ));
    }
    findings.extend(told(config.milter.is_some(), entered));
    findings
}

#[cfg(test)]
mod tests {
    use super::super::Level;
    use super::*;

    #[test]
    fn a_filter_that_stalwart_asks_must_be_configured_and_answer() {
        assert_eq!(answering(8096, Ok(())).level, Level::Ok);
        let silent = answering(8096, Err("Connection refused".to_owned()));
        assert_eq!(silent.level, Level::Fail);
        assert_eq!(
            silent.what,
            "the macro milter does not answer on 127.0.0.1:8096: Connection refused"
        );
        assert_eq!(told(true, true).unwrap().level, Level::Ok);
        assert_eq!(told(true, false).unwrap().level, Level::Warn);
        let left = told(false, true).unwrap();
        assert_eq!(left.level, Level::Fail);
        assert!(left.fix.unwrap().starts_with(SETUP));
        assert!(told(false, false).is_none());
    }
}
