//! Observations from the Stalwart management API and the recorded startup event.
//!
//! Uses a dedicated read-only API key (Replace permissions). Only selected
//! properties are requested; raw configuration objects are never stored.

use std::time::Duration;

use garrison_core::json;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Kind, Observation, State};
use garrison_core::sqlite::reading;
use garrison_stalwart::Error;
use garrison_stalwart::http::MAX_RESPONSE;
use garrison_stalwart::jmap::{JmapClient, Object};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{Map, json};

use self::answers::{Arguments, MailboxAccount, Milter, SpamClassifier, SpamSettings};
use super::mailboxes::mailboxes;
use crate::context::{Collected, Context, Provider, ProviderError, Report};
use crate::options::{Checked, Options};
use crate::values::{float, loosely_equal};

pub mod answers;

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
        Ok(Observation::new(
            id,
            "stalwart",
            title,
            modules.iter().copied(),
            evidence,
            state,
            context.checked_at(),
            source,
        )?)
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
        Ok(Self::observation(
            context,
            "version.stalwart",
            "Stalwart",
            &[ModuleId::Dashboard, ModuleId::Services],
            Evidence::Process,
            if found.is_some() {
                State::Ok
            } else {
                State::Unknown
            },
            "server.startup event",
        )?
        .with_kind(Kind::Version)
        .with_scope(scope)
        .with_value(value)
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

    fn milter(
        &self,
        context: &Context<'_>,
        rows: Option<&[Milter]>,
    ) -> Result<Observation, ProviderError> {
        let matches: Vec<&Milter> = rows
            .into_iter()
            .flatten()
            .filter(|row| {
                let host = self
                    .milter_host
                    .as_ref()
                    .is_none_or(|host| row.host.0 == Some(json!(host)));
                let wanted = json!(self.milter_port);
                let port = self.milter_port == 0
                    || (row.port.0.as_ref()).is_some_and(|port| loosely_equal(port, &wanted));
                host && port
            })
            .collect();
        // With a host or a port named, the one milter that is meant. Without,
        // every milter Stalwart asks: a scanner's, and Garrison's own macro
        // filter beside it.
        let named = self.milter_host.is_some() || self.milter_port != 0;
        let endpoint = |row: &Milter| format!("{}:{}", row.host.text(), row.port.text());
        let mut findings = Vec::new();
        for row in &matches {
            if row.temp_fail_on_error.0 != Some(false) {
                continue;
            }
            findings.push(if matches.len() == 1 {
                "Milter errors do not cause a temporary rejection; mail may pass unscanned."
                    .to_owned()
            } else {
                format!(
                    "Errors of the milter {} do not cause a temporary rejection; mail may pass \
                     it unscanned.",
                    endpoint(row)
                )
            });
        }
        if rows.is_some() && (matches.is_empty() || (named && matches.len() != 1)) {
            findings.push(format!(
                "Expected one matching milter, found {}.",
                matches.len()
            ));
        }
        // What holds for every one of them; unknown where one does not say.
        let all = |value: fn(&Milter) -> Option<bool>| {
            let mut values = matches.iter().map(|row| value(row)).peekable();
            values.peek()?;
            values.try_fold(true, |all, value| value.map(|value| all && value))
        };
        let endpoints: Vec<String> = matches.iter().map(|row| endpoint(row)).collect();
        let endpoint = (!endpoints.is_empty()).then(|| endpoints.join(", "));
        let state = match (rows.is_some(), findings.is_empty()) {
            (false, _) => State::Unknown,
            (true, false) => State::Warning,
            (true, true) => State::Ok,
        };
        Ok(Self::observation(
            context,
            "stalwart.milter",
            "Stalwart milter connection",
            &[ModuleId::Antivirus],
            Evidence::Configuration,
            state,
            "x:MtaMilter/get",
        )?
        .with_fields(vec![
            Field::new(
                "Matching milters",
                rows.as_ref().map(|_| matches.len()),
                Format::Number,
            ),
            Field::text("Endpoint", endpoint),
            Field::new("Enabled", all(|row| row.enable.0), Format::Boolean),
            Field::new(
                "DATA stage",
                all(|row| row.stages.0.data.0),
                Format::Boolean,
            ),
            Field::new(
                "Temporary failure on error",
                all(|row| row.temp_fail_on_error.0),
                Format::Boolean,
            ),
        ])
        .with_findings(findings))
    }
}

impl Provider for Stalwart {
    fn name(&self) -> &'static str {
        "stalwart"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let mut report = Report::of(Self::version(context)?);
        let Some(key) = &context.native_key else {
            report
                .observations
                .push(Self::unknown(context, "No API key is configured.".into())?);
            return Ok(report);
        };
        let client = JmapClient::new(&context.deployment.stalwart_url, key)
            .with_timeout(Duration::from_secs(8));
        let answers = match client.call_many(&calls(), MAX_RESPONSE) {
            Ok(answers) => Answers::read(answers),
            Err(error) => {
                let kind = match error {
                    Error::Unavailable(_) => "Stalwart unavailable",
                    Error::Denied(_) | Error::InvalidToken(_) => "access denied",
                };
                report
                    .observations
                    .push(Self::unknown(context, format!("Not readable: {kind}."))?);
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
mod tests;
