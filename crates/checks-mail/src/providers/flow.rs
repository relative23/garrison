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
//!
//! A count is in order only over a history that holds the week: while the
//! receiver does not report, or where it lost events within these days, a
//! summary that would be in order is Unknown and says why. Its numbers stay.

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Observation, Required, State};
use garrison_core::sqlite::reading;
use garrison_stalwart::ids::decode_native_id;
use garrison_stalwart::jmap::JmapClient;
use garrison_stalwart::{Error, SUPPORTED};
use serde::{Deserialize, Serialize};

mod cards;
mod read;

use read::{DAY, DAYS, Week};

use super::history;

use crate::context::{Collected, Context, Provider, ProviderError, Report};
use crate::kept::{Kept, cached};
use crate::options::{Checked, Options, fail};

const CHECKS: [&str; 4] = ["spam", "milter", "authentication", "tls"];
const EVERY: i64 = 600;
const MEMORY: &str = "flow.week";

/// What the status database keeps of the last reading.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
struct Read {
    week: Week,
    problem: Option<String>,
    /// Why the history does not hold the whole week, where it does not.
    #[serde(default)]
    uncovered: Option<String>,
    /// Why the domains of the mailboxes are not known, where Stalwart did not
    /// give the collector's key its accounts or the collector has no key:
    /// the mail is counted under "unknown" then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    domains_unread: Option<String>,
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

/// Why Stalwart did not give the collector's key its accounts, by what went
/// wrong: it did not answer, or refused the key for its rate limit, which
/// both pass by themselves; it refused the key, which the setup mends; or
/// it answered in a form this release does not read, which no setup mends.
fn unread(error: &Error) -> String {
    match error {
        Error::Unavailable(_) => {
            "Stalwart did not answer the collector's request for its accounts".to_owned()
        }
        Error::Limited(_) => "Stalwart refused the collector's key for its rate limit (HTTP 429), \
                              so its accounts could not be read"
            .to_owned(),
        Error::Denied(_) | Error::InvalidToken(_) | Error::Misconfigured(_) => {
            "Stalwart did not give its accounts to the collector's API key; run `garrison \
             stalwart setup` again to let it read them"
                .to_owned()
        }
        Error::Unreadable(why) => format!(
            "Stalwart answered the collector's request for its accounts in a form this release of \
             Garrison does not read ({why}); {SUPPORTED}"
        ),
    }
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
    /// an answer from Stalwart the domains stay unknown, and the error says
    /// why; the counts do not need them. Without a key none is asked for,
    /// and the error says what makes one.
    fn accounts(context: &Context<'_>) -> Result<HashMap<i64, String>, String> {
        let Some(key) = context.native_key.as_deref() else {
            return Err(
                "the collector has no API key for Stalwart; run `garrison stalwart \
                        setup`, which makes one"
                    .to_owned(),
            );
        };
        let client = JmapClient::new(&context.deployment.stalwart_url, key)
            .with_timeout(Duration::from_secs(8));
        let accounts = client
            .get::<Account>("Account", None, &["id", "emailAddress"])
            .map_err(|error| unread(&error))?;
        Ok(accounts
            .iter()
            .filter_map(|account| {
                let number = i64::try_from(decode_native_id(&account.id)?).ok()?;
                let (_, domain) = account.email_address.as_deref()?.rsplit_once('@')?;
                Some((number, domain.to_lowercase()))
            })
            .collect())
    }

    /// The last reading, or a new one where that is due: every ten minutes.
    fn known(context: &Context<'_>) -> Kept<Read> {
        cached(context, MEMORY, |_, _| EVERY, |_| Self::counted(context))
    }

    /// The week as the event history has it now.
    fn counted(context: &Context<'_>) -> Read {
        let now = context.now.as_second();
        let problem = |problem: String| Read {
            problem: Some(problem),
            ..Read::default()
        };
        match reading(&context.events_database, Duration::from_secs(2)) {
            Ok(Some(db)) => {
                let (accounts, domains_unread) = match Self::accounts(context) {
                    Ok(accounts) => (accounts, None),
                    Err(why) => (HashMap::new(), Some(why)),
                };
                match read::week(&db, now, &accounts) {
                    Ok(week) => Read {
                        uncovered: history::uncovered(
                            &db,
                            week.days.first().copied().unwrap_or(now - DAYS * DAY),
                            now,
                        ),
                        week,
                        problem: None,
                        domains_unread,
                    },
                    Err(error) => problem(format!("the event history could not be read: {error}")),
                }
            }
            Ok(None) => problem("no events are recorded yet".to_owned()),
            Err(error) => problem(format!("the event history could not be opened: {error}")),
        }
    }

    /// An observation of this provider; Unknown, with the reason, where the
    /// history could not be read, and where it would be in order over a
    /// history that does not hold the week.
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
        // What was seen stays what it is; only "in order" needs all of it.
        let incomplete = read.uncovered.as_ref().filter(|_| unknown.is_none());
        let observation = Observation::new(Required {
            id: &format!("flow.{id}"),
            provider: self.name(),
            title,
            modules: [module],
            evidence: Evidence::Probe,
            state: if unknown.is_some() || (incomplete.is_some() && state == State::Ok) {
                State::Unknown
            } else {
                state
            },
            checked_at: &context.checked_at(),
            source: "event history",
        })?;
        Ok(match (unknown, incomplete) {
            (Some(problem), _) => {
                observation.with_findings(vec![format!("Nothing could be counted: {problem}.")])
            }
            (None, Some(reason)) => observation.with_findings(vec![format!(
                "The event history is not current: {reason}. What is counted here may be too \
                 little."
            )]),
            (None, None) => observation,
        })
    }
}

impl Provider for Flow {
    fn name(&self) -> &'static str {
        "mail-flow"
    }

    /// The card of each configured check, and the list by domain that the
    /// spam and authentication checks show where the week had any: only
    /// there, but under an id their check alone decides.
    fn ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        for check in &self.checks {
            ids.push(format!("flow.{check}"));
            match check.as_str() {
                "spam" => ids.push("flow.spam-domains".to_owned()),
                "authentication" => ids.push("flow.failing-senders".to_owned()),
                _ => {}
            }
        }
        ids
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let kept = Self::known(context);
        let read = &kept.answer;
        let mut report = Report::default();
        for check in &self.checks {
            match check.as_str() {
                "spam" => self.spam(context, read, &mut report)?,
                "milter" => self.milter(context, read, &mut report)?,
                "authentication" => self.authentication(context, read, &mut report)?,
                _ => self.tls(context, read, &mut report)?,
            }
        }
        // Every card is as old as the reading it is made from.
        report.observations = report
            .observations
            .into_iter()
            .map(|observation| kept.dated(observation))
            .collect();
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
mod accounts_tests;
#[cfg(test)]
mod history_tests;
#[cfg(test)]
mod tests;
