//! Observations from the Stalwart management API and the recorded startup event.
//!
//! Uses a dedicated read-only API key (Replace permissions). Only selected
//! properties are requested; raw configuration objects are never stored.

use std::time::Duration;

use garrison_core::json;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Kind, Observation, Required, State};
use garrison_core::recording::{self, QUIET_AFTER};
use garrison_core::sqlite::reading;
use garrison_stalwart::http::MAX_RESPONSE;
use garrison_stalwart::jmap::{JmapClient, Object};
use garrison_stalwart::{Error, SUPPORTED};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{Map, json};

use self::answers::{Arguments, MailboxAccount, Milter, SpamClassifier, SpamSettings};
use super::mailboxes::mailboxes;
use crate::context::{Collected, Context, Provider, ProviderError, Report};
use crate::options::{Checked, Options};
use crate::values::float;

pub mod answers;
mod milter;

/// The calls of one collection, in the order in which `Answers::read` takes
/// their answers.
pub fn calls() -> [(&'static str, Arguments); 7] {
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
        (
            "x:Account/get",
            Arguments::get(
                None,
                Some(&["id", "@type", "emailAddress", "quotas", "usedDiskQuota"]),
            ),
        ),
    ]
}

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
    accounts: Option<Vec<MailboxAccount>>,
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
            accounts: answers::rows(next()),
        }
    }
}

/// Permissions the collector's API key needs (see `garrison stalwart setup`).
pub const REQUIRED_PERMISSIONS: [&str; 10] = [
    "authenticate",
    "sysSpamSettingsGet",
    "sysSpamClassifierGet",
    "sysSpamRuleQuery",
    "sysSpamTrainingSampleQuery",
    "sysQueuedMessageQuery",
    "sysMtaMilterGet",
    "sysAccountGet",
    // The `dns` provider reads each domain's expected records.
    "sysDomainGet",
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

/// The fields of a recorded `server.startup` event that are read.
#[derive(Deserialize)]
struct Startup {
    version: String,
}

/// The version the running server reported at its last recorded start, and
/// when that was.
pub(super) fn running_version(context: &Context<'_>) -> Option<(String, i64)> {
    let (started, fields): (i64, String) =
        reading(&context.events_database, Duration::from_secs(2))
            .ok()
            .flatten()
            .and_then(|db| {
                db.query_row(
                    "SELECT created_at, fields FROM events WHERE type='server.startup' \
                     ORDER BY created_at DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .ok()
                .flatten()
            })?;
    let Startup { version } = serde_json::from_str(&fields).ok()?;
    let valid = (1..=40).contains(&version.len())
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte));
    valid.then_some((version, started))
}

/// Why a start of Stalwart after `started` may be missing in the event
/// history, where it may: the receiver does not report, or it lost events
/// since. `None` says the recorded start is the last one.
fn later_start_unrecorded(context: &Context<'_>, started: i64) -> Option<String> {
    let db = reading(&context.events_database, Duration::from_secs(2))
        .ok()
        .flatten()?;
    match recording::uncovered(&db, started, context.now.as_second(), QUIET_AFTER) {
        Ok(reason) => reason.map(|reason| reason.to_string()),
        Err(error) => Some(format!(
            "what the event receiver recorded about itself cannot be read ({error})"
        )),
    }
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

    fn unknown(context: &Context<'_>, finding: String) -> Result<Observation, ProviderError> {
        Ok(Self::observation(
            context,
            "stalwart.api",
            "Management API",
            &[ModuleId::Services],
            Evidence::Configuration,
            State::Unknown,
            "Stalwart management API",
        )?
        .with_findings(vec![finding]))
    }

    /// The version from the last recorded `server.startup` event.
    fn version(context: &Context<'_>) -> Result<Observation, ProviderError> {
        let found = running_version(context);
        let scope = if found.is_some() {
            "Version reported by the running server at its last recorded start."
        } else {
            "No server start has been recorded since the event webhook was enabled."
        };
        let mut value = Map::new();
        value.insert("component".into(), json!("Stalwart"));
        value.insert(
            "version".into(),
            json!(found.as_ref().map(|(version, _)| version)),
        );
        value.insert(
            "startedAt".into(),
            json!(found.as_ref().map(|(_, started)| started)),
        );
        // The recorded start is the running server only while every later
        // start would have been recorded too.
        let unrecorded = found
            .as_ref()
            .and_then(|(_, started)| later_start_unrecorded(context, *started));
        Ok(Self::observation(
            context,
            "version.stalwart",
            "Stalwart",
            &[ModuleId::Dashboard, ModuleId::Services],
            Evidence::Process,
            if found.is_some() && unrecorded.is_none() {
                State::Ok
            } else {
                State::Unknown
            },
            "server.startup event",
        )?
        .with_kind(Kind::Version)
        .with_scope(scope)
        .with_value(value)
        .with_findings(
            unrecorded
                .map(|reason| format!("A later start of Stalwart may not be recorded: {reason}."))
                .into_iter()
                .collect(),
        )
        .with_max_age(3600))
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
            report
                .observations
                .push(Self::unknown(context, "No API key is configured.".into())?);
            return Ok(report);
        };
        // The check's one request, which has its own time; it is not made
        // once the run's time is up, after the history was read.
        if context.deadline.expired() {
            report.observations.push(Self::unknown(
                context,
                "Not asked: the collection run's time was used up.".into(),
            )?);
            return Ok(report);
        }
        let client = JmapClient::new(&context.deployment.stalwart_url, key)
            .with_timeout(Duration::from_secs(8));
        let answers = match client.call_many(&calls(), MAX_RESPONSE) {
            Ok(answers) => Answers::read(answers.into_iter().map(Result::ok).collect()),
            Err(error) => {
                let finding = format!("Not readable: {}.", unread(&error));
                report.observations.push(Self::unknown(context, finding)?);
                return Ok(report);
            }
        };
        report.observations.push(Self::spam(context, &answers)?);
        report
            .observations
            .push(self.milter(context, answers.milters.as_deref())?);
        let accounts = answers.accounts.as_deref();
        report
            .observations
            .push(mailboxes(context, accounts, self.max_accounts)?);
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
mod tests;
#[cfg(test)]
mod time_tests;
#[cfg(test)]
mod unread_tests;
