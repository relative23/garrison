//! Mail flow: what the last week's events say of the spam filter, the
//! scanner behind the milter, the checks of incoming senders and TLS in
//! transit.
//!
//! The pages for deliveries and sessions show one message at a time. These
//! summaries count: spam and ham by day and by recipient domain, the
//! milter's verdicts, how many senders pass SPF, DKIM, DMARC and ARC and
//! which domains fail, and how much mail travels without TLS. They are read
//! from the event history every ten minutes (`read.rs`) and shown as cards
//! (`cards.rs`).

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Observation, State};
use garrison_core::sqlite::reading;
use garrison_stalwart::ids::decode_native_id;
use garrison_stalwart::jmap::JmapClient;
use serde::{Deserialize, Serialize};

mod cards;
mod read;

use read::{DAYS, Week};

use crate::context::{Collected, Context, Provider, ProviderError, Report};
use crate::options::{Checked, Options, fail};

const CHECKS: [&str; 4] = ["spam", "milter", "authentication", "tls"];
const EVERY: i64 = 600;
const MEMORY: &str = "flow.week";

/// What the status database keeps of the last reading.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
struct Read {
    at: i64,
    week: Week,
    problem: Option<String>,
}

#[derive(Debug)]
pub struct Flow {
    checks: BTreeSet<String>,
}

/// An account as far as its domain needs it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Account {
    id: String,
    #[serde(default)]
    email_address: Option<String>,
}

type Made = Result<Observation, ProviderError>;

impl Flow {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        Options::new(raw, &["checks"])?;
        let wrong = || {
            fail(format!(
                "providers[mail-flow].checks lists {}",
                CHECKS.join(", ")
            ))
        };
        let checks = match raw.get("checks") {
            None => CHECKS.iter().map(ToString::to_string).collect(),
            Some(toml::Value::Array(names)) if !names.is_empty() => {
                let mut checks = BTreeSet::new();
                for name in names {
                    match name.as_str().filter(|name| CHECKS.contains(name)) {
                        Some(name) if checks.insert(name.to_owned()) => {}
                        _ => return wrong(),
                    }
                }
                checks
            }
            Some(_) => return wrong(),
        };
        Ok(Flow { checks })
    }

    /// The domain of each account's address, by the account's number. Without
    /// an answer from Stalwart the domains stay unknown; the counts do not.
    fn accounts(context: &Context<'_>) -> HashMap<i64, String> {
        let Some(key) = context.native_key.as_deref() else {
            return HashMap::new();
        };
        let client = JmapClient::new(&context.deployment.stalwart_url, key)
            .with_timeout(Duration::from_secs(8));
        let accounts = client
            .get::<Account>("Account", None, &["id", "emailAddress"])
            .unwrap_or_default();
        accounts
            .iter()
            .filter_map(|account| {
                let number = i64::try_from(decode_native_id(&account.id)?).ok()?;
                let (_, domain) = account.email_address.as_deref()?.rsplit_once('@')?;
                Some((number, domain.to_lowercase()))
            })
            .collect()
    }

    /// The last reading, or a new one where that is due.
    fn known(context: &Context<'_>) -> Read {
        let now = context.now.as_second();
        let kept: Option<Read> = context
            .memory
            .recall(MEMORY)
            .and_then(|text| serde_json::from_str(&text).ok());
        if let Some(kept) = kept.filter(|kept| (0..EVERY).contains(&(now - kept.at))) {
            return kept;
        }
        let problem = |problem: String| Read {
            at: now,
            problem: Some(problem),
            ..Read::default()
        };
        let read = match reading(&context.events_database, Duration::from_secs(2)) {
            Ok(Some(db)) => match read::week(&db, now, &Self::accounts(context)) {
                Ok(week) => Read {
                    at: now,
                    week,
                    problem: None,
                },
                Err(error) => problem(format!("the event history could not be read: {error}")),
            },
            Ok(None) => problem("no events are recorded yet".to_owned()),
            Err(error) => problem(format!("the event history could not be opened: {error}")),
        };
        if let Ok(text) = serde_json::to_string(&read) {
            context.memory.keep(MEMORY, &text);
        }
        read
    }

    /// An observation of this provider; Unknown, with the reason, where the
    /// history could not be read.
    fn observation(
        &self,
        context: &Context<'_>,
        read: &Read,
        id: &str,
        title: &str,
        module: ModuleId,
        state: State,
    ) -> Made {
        let unknown = read.problem.as_ref();
        let observation = Observation::new(
            format!("flow.{id}"),
            self.name(),
            title,
            [module],
            Evidence::Probe,
            if unknown.is_some() {
                State::Unknown
            } else {
                state
            },
            context.checked_at(),
            "event history",
        )?
        .with_max_age(180);
        Ok(match unknown {
            Some(problem) => {
                observation.with_findings(vec![format!("Nothing could be counted: {problem}.")])
            }
            None => observation,
        })
    }
}

impl Provider for Flow {
    fn name(&self) -> &'static str {
        "mail-flow"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let read = Self::known(context);
        let mut report = Report::default();
        for check in &self.checks {
            match check.as_str() {
                "spam" => self.spam(context, &read, &mut report)?,
                "milter" => self.milter(context, &read, &mut report)?,
                "authentication" => self.authentication(context, &read, &mut report)?,
                _ => self.tls(context, &read, &mut report)?,
            }
        }
        if read.week.truncated
            && let Some(first) = report.observations.first_mut()
        {
            first.findings.push(format!(
                "More events were recorded in the last {DAYS} days than the lists by domain count."
            ));
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
