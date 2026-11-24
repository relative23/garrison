//! Observations from the Stalwart management API and the recorded startup event.
//!
//! Uses a dedicated read-only API key (Replace permissions). Only selected
//! properties are requested; raw configuration objects are never stored.

use std::time::Duration;

use garrison_core::json;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, Required, State};
use garrison_stalwart::http::MAX_RESPONSE;
use garrison_stalwart::jmap::{JmapClient, Listed, Object};
use garrison_stalwart::{Error, SUPPORTED};

use self::answers::{Arguments, MailboxAccount, Milter, SpamClassifier, SpamSettings};
use super::mailboxes::mailboxes;
use crate::context::{Collected, Context, NO_KEY, Provider, ProviderError, Report};
use crate::options::{Checked, Options};
use crate::values::float;

pub mod answers;
mod milter;
mod version;

pub(super) use version::running_version;

/// The calls of one collection's first request, in the order in which
/// `Answers::read` takes their answers. The accounts come in pages of their
/// own ([`ACCOUNT_PROPERTIES`]), as many as `max_accounts`: Stalwart gives a
/// `/get` of all of them the first 500 alone.
pub fn calls() -> [(&'static str, Arguments); 6] {
    const SINGLETON: Arguments = Arguments::get(Some(&["singleton"]), None);
    [
        ("x:SpamSettings/get", SINGLETON),
        ("x:SpamClassifier/get", SINGLETON),
        ("x:SpamRule/query", Arguments::COUNT),
        ("x:SpamTrainingSample/query", Arguments::COUNT),
        ("x:QueuedMessage/query", Arguments::COUNT),
        (
            "x:MtaMilter/get",
            Arguments::get(
                None,
                Some(&["host", "port", "enable", "stages", "tempFailOnError"]),
            ),
        ),
    ]
}

/// What the mailbox storage reads of each account.
pub const ACCOUNT_PROPERTIES: [&str; 5] =
    ["id", "@type", "emailAddress", "quotas", "usedDiskQuota"];
/// The method the pages of the accounts begin with, as the Management API
/// card names it where they gave nothing.
const ACCOUNTS: &str = "x:Account/query";

/// What the calls answered, each as far as an observation shows it. A method
/// that did not answer leaves its part unknown.
#[derive(Debug, Default)]
struct Answers {
    spam: Option<SpamSettings>,
    classifier: SpamClassifier,
    rules: Option<u64>,
    training: Option<u64>,
    queue: Option<u64>,
    milters: Option<Vec<Milter>>,
}

impl Answers {
    /// `answers` in the order of [`calls`].
    fn read(answers: Vec<Option<Object>>) -> Answers {
        let mut answers = answers.into_iter();
        let mut next = || answers.next().flatten();
        Answers {
            spam: answers::only(next()),
            classifier: answers::only(next()).unwrap_or_default(),
            rules: answers::total(next()),
            training: answers::total(next()),
            queue: answers::total(next()),
            milters: answers::rows(next()),
        }
    }
}

/// Permissions the collector's API key needs (see `garrison stalwart setup`).
pub const REQUIRED_PERMISSIONS: [&str; 12] = [
    "authenticate",
    "sysSpamSettingsGet",
    "sysSpamClassifierGet",
    "sysSpamRuleQuery",
    "sysSpamTrainingSampleQuery",
    "sysQueuedMessageQuery",
    "sysMtaMilterGet",
    // The mailbox storage reads the accounts in pages a query finds.
    "sysAccountGet",
    "sysAccountQuery",
    // The `dns` provider reads each domain's expected records, those of
    // the first `max_domains` found by a query.
    "sysDomainGet",
    "sysDomainQuery",
    // The `tls` provider reads which listeners speak TLS.
    "sysNetworkListenerGet",
];

/// What mends a key Stalwart refused, as the other cards say it.
const SETUP: &str = "run `garrison stalwart setup` again, which gives the collector's API key \
                     the permissions it needs";

/// Why Stalwart's answer gave the Management API card nothing, by its kind.
fn unread(error: &Error) -> String {
    match error {
        Error::Unavailable(_) => "Stalwart unavailable".to_owned(),
        Error::Limited(_) => {
            "Stalwart refused the collector's key for its rate limit (HTTP 429)".to_owned()
        }
        Error::Unreadable(why) => format!(
            "Stalwart answered in a form this release of Garrison does not read ({why}); \
             {SUPPORTED}"
        ),
        Error::Denied(_) | Error::InvalidToken(_) | Error::Misconfigured(_) => {
            format!("access denied; {SETUP}")
        }
    }
}

/// What the Management API card says of the calls that gave nothing, each
/// with its method, in the order they were made: those Stalwart refused the
/// collector's key, as it refuses every call of a key made before they were
/// needed, with the setup's advice, those it answered in a form this release
/// does not read, and the accounts' pages where Stalwart did not complete
/// one; nothing where every call answered.
fn parts_unread(failed: &[(&str, &Error)]) -> Vec<String> {
    let (mut refused, mut unreadable, mut others) = (Vec::new(), Vec::new(), Vec::new());
    for (method, error) in failed {
        match error {
            Error::Denied(_) | Error::InvalidToken(_) | Error::Misconfigured(_) => {
                refused.push(*method);
            }
            Error::Unreadable(why) => unreadable.push(why.as_str()),
            // These end a whole request: the first one's never reach here.
            Error::Unavailable(_) | Error::Limited(_) => {
                others.push(format!("Not readable ({method}): {}.", unread(error)));
            }
        }
    }
    let mut findings = Vec::new();
    if !refused.is_empty() {
        findings.push(format!(
            "Not readable: access denied to {}; {SETUP}.",
            refused.join(", ")
        ));
    }
    if !unreadable.is_empty() {
        findings.push(format!(
            "Not readable: Stalwart answered in a form this release of Garrison does not read \
             ({}); {SUPPORTED}.",
            unreadable.join(", ")
        ));
    }
    findings.extend(others);
    findings
}

#[derive(Debug)]
pub struct Stalwart {
    milter_host: Option<String>,
    milter_port: i64,
    max_accounts: usize,
}

impl Stalwart {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["milter_host", "milter_port", "max_accounts"])?;
        Ok(Stalwart {
            milter_host: options.optional_text("milter_host")?,
            milter_port: options.integer("milter_port", 0, 0, 65535)?,
            max_accounts: usize::try_from(options.integer("max_accounts", 1000, 1, 20000)?)
                .unwrap_or(1000),
        })
    }

    fn observation(
        context: &Context<'_>,
        id: &str,
        title: &str,
        modules: &[ModuleId],
        evidence: Evidence,
        state: State,
        source: &str,
    ) -> Result<Observation, ProviderError> {
        Ok(Observation::new(Required {
            id,
            provider: "stalwart",
            title,
            modules: modules.iter().copied(),
            evidence,
            state,
            checked_at: &context.checked_at(),
            source,
        })?)
    }

    fn unknown(context: &Context<'_>, findings: Vec<String>) -> Result<Observation, ProviderError> {
        Ok(Self::observation(
            context,
            "stalwart.api",
            "Management API",
            &[ModuleId::Services],
            Evidence::Configuration,
            State::Unknown,
            "Stalwart management API",
        )?
        .with_findings(findings))
    }

    fn spam(context: &Context<'_>, answers: &Answers) -> Result<Observation, ProviderError> {
        let settings = answers.spam.clone().unwrap_or_default();
        let classifier = &answers.classifier;
        let model = classifier.model.0.kind.0.as_ref();
        let model = model.filter(|kind| json::is_set(kind));
        let interval = classifier.train_interval.float();
        let interval = interval
            .filter(|millis| *millis != 0.0)
            .map(|millis| float(millis / 1000.0));
        Ok(Self::observation(
            context,
            "stalwart.spam",
            "Native spam filter and classifier",
            &[ModuleId::Spam],
            Evidence::Configuration,
            if answers.spam.is_some() {
                State::Ok
            } else {
                State::Unknown
            },
            "x:SpamSettings, x:SpamClassifier, x:SpamRule, x:SpamTrainingSample",
        )?
        .with_scope("Configured values. A rule count or queued sample does not prove learning.")
        .with_fields(vec![
            Field::new("Filter enabled", settings.enable.0, Format::Boolean),
            Field::new(
                "Spam threshold",
                settings.score_spam.value(),
                Format::Number,
            ),
            Field::new(
                "Reject threshold",
                settings.score_reject.value(),
                Format::Number,
            ),
            Field::new(
                "Discard threshold",
                settings.score_discard.value(),
                Format::Number,
            ),
            Field::new("Native rules", answers.rules, Format::Number),
            Field::text(
                "Classifier model",
                model.map(|kind| {
                    crate::values::text(kind)
                        .chars()
                        .take(40)
                        .collect::<String>()
                }),
            ),
            Field::new(
                "Minimum ham samples",
                classifier.min_ham_samples.value(),
                Format::Number,
            ),
            Field::new(
                "Minimum spam samples",
                classifier.min_spam_samples.value(),
                Format::Number,
            ),
            Field::new("Training interval", interval, Format::Duration),
            Field::new("Queued training samples", answers.training, Format::Number),
        ]))
    }
}

impl Provider for Stalwart {
    fn name(&self) -> &'static str {
        "stalwart"
    }

    fn ids(&self) -> Vec<String> {
        [
            "version.stalwart",
            "stalwart.api",
            "stalwart.spam",
            "stalwart.milter",
            "stalwart.mailboxes",
            "stalwart.queue",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let mut report = Report::of(Self::version(context)?);
        let Some(key) = &context.native_key else {
            report.observations.push(Self::unknown(
                context,
                vec![format!("Not asked: {NO_KEY}.")],
            )?);
            return Ok(report);
        };
        // The check's one request, which has its own time; it is not made
        // once the run's time is up, after the history was read.
        if context.deadline.expired() {
            report.observations.push(Self::unknown(
                context,
                vec!["Not asked: the collection run's time was used up.".into()],
            )?);
            return Ok(report);
        }
        let client = JmapClient::new(&context.deployment.stalwart_url, key)
            .with_timeout(Duration::from_secs(8));
        let answers = match client.call_many(&calls(), MAX_RESPONSE) {
            Ok(answers) => answers,
            Err(error) => {
                let finding = format!("Not readable: {}.", unread(&error));
                report
                    .observations
                    .push(Self::unknown(context, vec![finding])?);
                return Ok(report);
            }
        };
        // The accounts, as many as `max_accounts`, in requests of their own,
        // each made while the run has time.
        let accounts = (!context.deadline.expired()).then(|| {
            client.listed::<MailboxAccount>(
                "Account",
                &ACCOUNT_PROPERTIES,
                self.max_accounts,
                || !context.deadline.expired(),
            )
        });
        // The calls that answered fill their cards; the others are named.
        let requests = calls();
        let mut failed: Vec<(&str, &Error)> = requests
            .iter()
            .zip(&answers)
            .filter_map(|((method, _), answer)| answer.as_ref().err().map(|error| (*method, error)))
            .collect();
        if let Some(Err(error)) = &accounts {
            failed.push((ACCOUNTS, error));
        }
        let unanswered = parts_unread(&failed);
        if !unanswered.is_empty() {
            report
                .observations
                .push(Self::unknown(context, unanswered)?);
        }
        let answers = Answers::read(answers.into_iter().map(Result::ok).collect());
        report.observations.push(Self::spam(context, &answers)?);
        report
            .observations
            .push(self.milter(context, answers.milters.as_deref())?);
        let listed: Option<&Listed<MailboxAccount>> =
            accounts.as_ref().and_then(|read| read.as_ref().ok());
        let mut storage = mailboxes(context, listed, self.max_accounts)?;
        if accounts.is_none() {
            storage
                .findings
                .push("Not asked: the collection run's time was used up.".to_owned());
        }
        report.observations.push(storage);
        let queue = answers.queue;
        let observation = Self::observation(
            context,
            "stalwart.queue",
            "Mail queue",
            &[ModuleId::Dashboard, ModuleId::Deliveries],
            if queue.is_some() {
                Evidence::Inventory
            } else {
                Evidence::Configuration
            },
            if queue.is_some() {
                State::Ok
            } else {
                State::Unknown
            },
            "x:QueuedMessage/query",
        )?
        .with_fields(vec![Field::new("Queued messages", queue, Format::Number)])
        .with_max_age(180);
        report.observations.push(observation);
        if let Some(queue) = queue {
            #[allow(clippy::cast_precision_loss)]
            report.gauges.insert("queue_count".into(), queue as f64);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod limit_tests;
#[cfg(test)]
mod many_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod time_tests;
#[cfg(test)]
mod unread_tests;
