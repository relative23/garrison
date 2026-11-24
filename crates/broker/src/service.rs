//! Maintenance requests: fresh authorization, idempotency, audit and execution.
//!
//! Every operation starts from the user's access token. The broker resolves the
//! identity and rights itself and re-checks them when a queued job starts, so a
//! demoted user's pending request is not executed.
//!
//! A job the audit shows as queued or running holds back every other. So a
//! job never stays that way for a reason of the broker's own: one it could
//! not start is failed at once, one whose start the audit does not take is
//! not run, and a record the audit did not take is owed to it and written
//! with the next request it does take.

use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;

use crate::protocol::{BrokerError, Catalog, Submitted, refuse};
use crate::runner::{Outcome, Runner};
use crate::store::{Change, Job, JobStatus, JobStore, JobView, MAX_JOBS, now};
use garrison_authz::{Authority, Error, Grant};
use garrison_core::config::Action;
use garrison_core::constant_time;

mod ids;
mod limited;
mod refusal;

pub use ids::is_job_id;
use ids::{is_request_id, job_id};
use limited::{Failing, Limited};

/// Seconds after any job before the next one may start.
const SETTLE_SECONDS: i64 = 30;
const RECENT_JOBS: i64 = 20;
const LISTED_JOBS: usize = 10;

/// A failing job audit is the broker's own problem: the cause goes to the
/// journal and the caller hears no more than that the broker failed.
impl From<rusqlite::Error> for BrokerError {
    fn from(error: rusqlite::Error) -> Self {
        log::error!("Broker request failed: {error}");
        refuse(500, "Internal broker error")
    }
}

/// What the broker needs to turn a token into a grant; tests use their own.
pub trait Authorize: Send + Sync {
    fn authorize(&self, token: &str) -> Result<Grant, Error>;
}

impl Authorize for Authority {
    fn authorize(&self, token: &str) -> Result<Grant, Error> {
        Authority::authorize(self, token)
    }
}

/// Runs an accepted job; the broker passes a thread spawner, tests their own.
/// An error says that the job could not be started: nothing of it ran.
pub(crate) type Worker = Box<dyn Fn(Box<dyn FnOnce() + Send>) -> io::Result<()> + Send + Sync>;

/// Each accepted job runs on its own thread.
pub(crate) fn threads() -> Worker {
    Box::new(|work| {
        thread::Builder::new()
            .name("maintenance-action".into())
            .spawn(work)
            .map(drop)
    })
}

/// Why a job ended before anything ran.
const NOT_STARTED: &str = "The broker could not start the job; nothing was run.";
const NOT_RECORDED: &str = "The job's start could not be recorded in the audit; nothing was run.";
const CHANGED: &str = "Authorization changed before execution; nothing was run.";
const SIGNED_OUT: &str = "The sign-in ended before execution; nothing was run.";
const UNCHECKED: &str = "Authorization could not be checked before execution: Stalwart did not \
                         complete the check, and the broker's journal says why. Nothing was run.";
const LIMITED: &str = "Authorization could not be checked before execution: Stalwart refused the \
                       check for its rate limit (HTTP 429). Nothing was run.";
const NOT_SET_UP: &str = "Access rights could not be checked before execution: Garrison is not \
                          set up to check them, and the broker's journal says why. Nothing was \
                          run.";
const UNREAD: &str = "Authorization could not be checked before execution: Stalwart answered in a \
                      form this release of Garrison does not read, and the broker's journal \
                      names the answer. Nothing was run.";

const BROKER_FAILED: &str = "The broker failed while it handled the job; whether anything was \
                             run is not known. Consult the host journal.";

/// A change to a job's record that the audit did not take.
type Owed = (String, Change<'static>);

pub struct Broker {
    authority: Box<dyn Authorize>,
    actions: Vec<Action>,
    store: Mutex<JobStore>,
    /// What the audit did not take, oldest first. Lock the store before it.
    owed: Mutex<Vec<Owed>>,
    /// When the journal last named Stalwart's rate limit.
    limited: Mutex<Limited>,
    /// When the journal last named a check Stalwart did not complete.
    failing: Mutex<Failing>,
    runner: Box<dyn Runner>,
    worker: Worker,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Broker")
            .field("actions", &self.actions)
            .finish_non_exhaustive()
    }
}

impl Broker {
    pub fn new(
        authority: Box<dyn Authorize>,
        actions: Vec<Action>,
        store: JobStore,
        runner: Box<dyn Runner>,
        worker: Worker,
    ) -> Arc<Self> {
        Arc::new(Broker {
            authority,
            actions,
            store: Mutex::new(store),
            owed: Mutex::new(Vec::new()),
            limited: Mutex::new(Limited::default()),
            failing: Mutex::new(Failing::default()),
            runner,
            worker,
        })
    }

    fn store(&self) -> MutexGuard<'_, JobStore> {
        // Every write is one statement, so a panic leaves the audit consistent.
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The audit, with what it is owed written first where it takes it. A
    /// request sees the jobs as they are, not as the last record that could
    /// be written left them.
    fn audit(&self) -> MutexGuard<'_, JobStore> {
        let store = self.store();
        self.settle(&store, None);
        store
    }

    /// Write what the audit is owed, oldest first, and `change` after it;
    /// what it does not take stays owed, in its order. Whether nothing is
    /// owed any more.
    fn settle(&self, store: &JobStore, change: Option<Owed>) -> bool {
        let mut owed = self.owed.lock().unwrap_or_else(PoisonError::into_inner);
        owed.extend(change);
        let mut written = 0;
        for (identifier, change) in owed.iter() {
            if let Err(error) = store.update(identifier, change) {
                log::error!("Could not record maintenance job {identifier}: {error}");
                break;
            }
            written += 1;
        }
        owed.drain(..written);
        owed.is_empty()
    }

    fn action(&self, id: &str) -> Option<&Action> {
        self.actions.iter().find(|action| action.id == id)
    }

    pub(crate) fn catalog(&self, token: &str) -> Result<Catalog, BrokerError> {
        let grant = self.authorize(token)?;
        let actions = self
            .actions
            .iter()
            .filter(|action| grant.allows_action(&action.id))
            .map(Action::public)
            .collect();
        let store = self.audit();
        store.prune()?;
        let jobs = store
            .recent(RECENT_JOBS)?
            .iter()
            .filter(|job| grant.allows_action(&job.action_id))
            .take(LISTED_JOBS)
            .map(Job::view)
            .collect();
        Ok(Catalog { actions, jobs })
    }

    pub(crate) fn job(&self, token: &str, identifier: &str) -> Result<JobView, BrokerError> {
        let grant = self.authorize(token)?;
        if !is_job_id(identifier) {
            return Err(refuse(400, "Invalid job ID"));
        }
        let job = self.audit().get(identifier)?;
        match job {
            Some(job) if grant.allows_action(&job.action_id) => Ok(job.view()),
            _ => Err(refuse(404, "Job not found")),
        }
    }

    pub(crate) fn submit(
        self: &Arc<Self>,
        token: &str,
        action_id: &str,
        request_id: &str,
        confirmation: &str,
    ) -> Result<Submitted, BrokerError> {
        let grant = self.authorize(token)?;
        let action = self
            .action(action_id)
            .filter(|_| grant.allows_action(action_id))
            .ok_or_else(|| refuse(403, "This maintenance action is not authorized"))?
            .clone();
        if !is_request_id(request_id) {
            return Err(refuse(400, "A lowercase UUID4 request ID is required"));
        }
        if !constant_time::eq(confirmation, &action.confirmation) {
            return Err(refuse(400, "The confirmation phrase does not match"));
        }
        let job = {
            let store = self.audit();
            store.prune()?;
            if let Some(previous) = store.by_request(request_id)? {
                if previous.actor != grant.subject || previous.action_id != action_id {
                    return Err(refuse(
                        409,
                        "The request ID belongs to a different operation",
                    ));
                }
                return Ok(Submitted {
                    job: previous.view(),
                    replayed: true,
                });
            }
            self.check_capacity(&store, &action)?;
            self.runner.preflight(&action)?;
            let job = Job {
                id: job_id()?,
                action_id: action_id.to_owned(),
                actor: grant.subject.clone(),
                actor_email: grant.email.clone(),
                request_id: request_id.to_owned(),
                status: JobStatus::Queued,
                created_at: now(),
                started_at: None,
                finished_at: None,
                message: "Accepted for execution.".into(),
                may_still_run: false,
            };
            store.insert(&job)?;
            job
        };
        log::info!("Maintenance action {action_id} accepted as job {}", job.id);
        let (broker, identifier, token) = (Arc::clone(self), job.id.clone(), token.to_owned());
        let started = (self.worker)(Box::new(move || {
            broker.attend(&identifier, &action, &token);
        }));
        let job = match started {
            Ok(()) => job,
            // Left queued, the job would hold back every action until the
            // broker is started anew.
            Err(error) => {
                log::error!("Could not start maintenance job {}: {error}", job.id);
                let finished_at = now();
                self.record(
                    &job.id,
                    Change {
                        status: Some(JobStatus::Failed),
                        finished_at: Some(finished_at),
                        message: Some(NOT_STARTED),
                        ..Change::default()
                    },
                );
                Job {
                    status: JobStatus::Failed,
                    finished_at: Some(finished_at),
                    message: NOT_STARTED.into(),
                    ..job
                }
            }
        };
        Ok(Submitted {
            job: job.view(),
            replayed: false,
        })
    }

    fn check_capacity(&self, store: &JobStore, action: &Action) -> Result<(), BrokerError> {
        for job in store.active()? {
            if job.status.is_pending() {
                return Err(refuse(409, "Another maintenance operation is in progress"));
            }
            if self
                .action(&job.action_id)
                .is_some_and(|other| self.runner.still_running(other))
            {
                return Err(refuse(409, "An earlier operation may still be running"));
            }
            let settled = Change {
                may_still_run: Some(false),
                ..Change::default()
            };
            store.update(&job.id, &settled)?;
        }
        let at = now();
        // A job dated ahead of the clock, as after the clock went back, was
        // not created seconds ago; when it was is not known: it waits for
        // nothing, where it held every action back until the clock was there.
        let within = |latest: i64, wait: i64| (0..wait).contains(&(at - latest));
        let latest = store.latest_created(None)?;
        if latest.is_some_and(|latest| within(latest, SETTLE_SECONDS)) {
            return Err(refuse(429, "Allow the previous operation to settle first"));
        }
        let latest = store.latest_created(Some(&action.id))?;
        if latest.is_some_and(|latest| within(latest, i64::from(action.cooldown_seconds))) {
            return Err(refuse(429, "This action is still in its cooldown period"));
        }
        if store.count()? >= MAX_JOBS {
            return Err(refuse(
                503,
                "Audit capacity reached; retained records are not evicted",
            ));
        }
        Ok(())
    }

    /// Write `change` to the job's record, after anything the audit is still
    /// owed. What the audit does not take, it is owed.
    fn record(&self, identifier: &str, change: Change<'static>) {
        let store = self.store();
        self.settle(&store, Some((identifier.to_owned(), change)));
    }

    /// Write `change` now or not at all: whether the audit holds it, with
    /// everything it was owed before.
    fn recorded(&self, identifier: &str, change: &Change<'static>) -> bool {
        let store = self.store();
        self.settle(&store, None)
            && store
                .update(identifier, change)
                .inspect_err(|error| {
                    log::error!("Could not record maintenance job {identifier}: {error}");
                })
                .is_ok()
    }

    /// Run an accepted job to its end, whatever that is. A job whose thread
    /// ended in a panic of the broker's own would stay queued or running,
    /// and hold back every other until the broker is started anew.
    fn attend(&self, identifier: &str, action: &Action, token: &str) {
        let attended = catch_unwind(AssertUnwindSafe(|| self.execute(identifier, action, token)));
        if attended.is_err() {
            log::error!("The broker failed while it handled maintenance job {identifier}");
            self.record(
                identifier,
                Change {
                    status: Some(JobStatus::Uncertain),
                    finished_at: Some(now()),
                    message: Some(BROKER_FAILED),
                    may_still_run: Some(true),
                    ..Change::default()
                },
            );
        }
    }

    /// End a job that did not run, and say why.
    fn fail(&self, identifier: &str, message: &'static str) {
        self.record(
            identifier,
            Change {
                status: Some(JobStatus::Failed),
                finished_at: Some(now()),
                message: Some(message),
                ..Change::default()
            },
        );
    }

    /// Run an accepted job. A queued request is not a durable permission, so
    /// the rights are checked again first.
    fn execute(&self, identifier: &str, action: &Action, token: &str) {
        // Rights that changed and rights nobody could confirm both run
        // nothing, and the record and the journal say which it was.
        let unconfirmed = match self.authority.authorize(token) {
            Ok(grant) if grant.allows_action(&action.id) => None,
            Ok(_) => {
                log::info!(
                    "Rights for job {identifier} changed before it started: {} is no longer \
                     granted",
                    action.id
                );
                Some(CHANGED)
            }
            Err(Error::Denied(reason)) => {
                log::info!("Rights for job {identifier} changed before it started: {reason}");
                Some(CHANGED)
            }
            Err(Error::InvalidToken(reason)) => {
                log::info!("The sign-in of job {identifier} ended before it started: {reason}");
                Some(SIGNED_OUT)
            }
            Err(Error::Unavailable(how)) => {
                log::warn!(
                    "Rights for job {identifier} could not be checked: Stalwart did not complete \
                     the check ({how})"
                );
                Some(UNCHECKED)
            }
            Err(Error::Limited(whose)) => {
                log::warn!(
                    "Rights for job {identifier} could not be checked: Stalwart refused {whose} \
                     for its rate limit (HTTP 429)"
                );
                Some(LIMITED)
            }
            Err(Error::Misconfigured(reason)) => {
                log::error!(
                    "Rights for job {identifier} could not be checked: Garrison is not set up to \
                     check them ({reason})"
                );
                Some(NOT_SET_UP)
            }
            Err(Error::Unreadable(reason)) => {
                log::error!(
                    "Rights for job {identifier} could not be checked: {}",
                    refusal::unread(&reason)
                );
                Some(UNREAD)
            }
        };
        if let Some(message) = unconfirmed {
            self.fail(identifier, message);
            return;
        }
        let running = Change {
            status: Some(JobStatus::Running),
            started_at: Some(now()),
            message: Some("Running."),
            ..Change::default()
        };
        // What the audit does not hold does not happen: a job whose start
        // it does not take is not run, and that start is not owed to it.
        if !self.recorded(identifier, &running) {
            self.fail(identifier, NOT_RECORDED);
            return;
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| self.runner.run(action)));
        let outcome = outcome.unwrap_or_else(|_| {
            log::error!("Maintenance runner failed for job {identifier}");
            Outcome {
                status: JobStatus::Uncertain,
                message: "The result could not be confirmed. Consult the host journal.",
                may_still_run: true,
            }
        });
        let (status, message, pending) = (outcome.status, outcome.message, outcome.may_still_run);
        self.record(
            identifier,
            Change {
                status: Some(status),
                finished_at: Some(now()),
                message: Some(message),
                may_still_run: Some(pending),
                ..Change::default()
            },
        );
        log::info!("Maintenance job {identifier} finished: {}", status.as_str());
    }
}

#[cfg(test)]
mod actions_tests;
#[cfg(test)]
mod concurrency_tests;
#[cfg(test)]
mod failure_tests;
#[cfg(test)]
pub(crate) mod limit_tests;
#[cfg(test)]
mod outage_tests;
#[cfg(test)]
mod record_tests;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod unread_tests;
