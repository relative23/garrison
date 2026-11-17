//! What clamav-milter does with a message: the two directives of its file
//! that say so, judged as clamav-milter itself takes them.
//!
//! Measured with clamav-milter 1.4.3 (Debian 13) and 1.4.6 (EPEL 10), as
//! its manual page and sample file say: a directive the file does not set
//! has its default, Quarantine for an infected message and Defer for a
//! failure; the value is taken in any case; of two lines the first counts;
//! and a value outside the actions, anywhere in the file, keeps clamav-milter
//! from starting ("Incorrect argument format for option `OnInfected`").

use std::path::Path;

use crate::options::{Checked, Options, fail};

/// What clamav-milter can do with a message, as its manual page names them.
const ACTIONS: [&str; 5] = ["Accept", "Reject", "Defer", "Blackhole", "Quarantine"];
/// Of those, what it can do on a failure: not Blackhole or Quarantine.
const ON_FAILURE: [&str; 3] = ["Accept", "Reject", "Defer"];

/// One of the two directives, with clamav-milter's default.
#[derive(Debug)]
pub(super) struct Policy {
    pub(super) key: &'static str,
    /// The option of the check that names the action expected.
    option: &'static str,
    /// The subject and verb of a finding about it.
    handled: &'static str,
    actions: &'static [&'static str],
    default: &'static str,
}

pub(super) const ON_INFECTED: Policy = Policy {
    key: "OnInfected",
    option: "expect_on_infected",
    handled: "Detected malware is handled",
    actions: &ACTIONS,
    default: "Quarantine",
};

pub(super) const ON_FAIL: Policy = Policy {
    key: "OnFail",
    option: "expect_on_fail",
    handled: "Scanner failures are handled",
    actions: &ON_FAILURE,
    default: "Defer",
};

/// What a directive comes to: the action in force, if clamav-milter starts
/// with the file, and the findings, each with whether it needs a look.
pub(super) struct Judged {
    pub(super) action: Option<&'static str>,
    pub(super) findings: Vec<(bool, String)>,
}

impl Policy {
    /// The action `value` names, as the manual page writes it.
    fn named(&self, value: &str) -> Option<&'static str> {
        self.actions
            .iter()
            .copied()
            .find(|action| action.eq_ignore_ascii_case(value))
    }

    /// The action the check's option expects, `default` where it names none;
    /// one that clamav-milter does not take here can never be in force.
    pub(super) fn expected(&self, options: &Options<'_>, default: &str) -> Checked<&'static str> {
        let text = options.text(self.option, Some(default))?;
        self.named(&text).map_or_else(
            || {
                fail(format!(
                    "providers[clamav].{} must be one of {}",
                    self.option,
                    self.actions.join(", ")
                ))
            },
            Ok,
        )
    }

    /// The directive as `values`, its lines in `file` in their order,
    /// against the action `expected`.
    pub(super) fn judged(&self, values: &[String], expected: &str, file: &Path) -> Judged {
        let file = file.display();
        let Some(first) = values.first() else {
            let finding = (self.default != expected).then(|| {
                (
                    true,
                    format!(
                        "{} with {default}, not {expected}: {file} does not set {key}, and \
                         {default} is clamav-milter's default.",
                        self.handled,
                        default = self.default,
                        key = self.key,
                    ),
                )
            });
            return Judged {
                action: Some(self.default),
                findings: finding.into_iter().collect(),
            };
        };
        if let Some(refused) = values.iter().find(|value| self.named(value).is_none()) {
            return Judged {
                action: None,
                findings: vec![(
                    true,
                    format!(
                        "{} \"{refused}\" is none of the actions clamav-milter takes there ({}), \
                         so it does not start with {file}.",
                        self.key,
                        self.actions.join(", ")
                    ),
                )],
            };
        }
        let action = self.named(first);
        let mut findings = Vec::new();
        if let Some(taken) = action {
            if taken != expected {
                findings.push((
                    true,
                    format!("{} with {taken}, not {expected}.", self.handled),
                ));
            }
            if values.len() > 1 {
                findings.push((
                    false,
                    format!(
                        "{} is set {} times in {file}; clamav-milter takes the first, {taken}.",
                        self.key,
                        values.len()
                    ),
                ));
            }
        }
        Judged { action, findings }
    }
}
