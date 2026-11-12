//! Maintenance requests: fresh authorization, idempotency, audit and execution.
//!
//! Every operation starts from the user's access token. The broker resolves the
//! identity and rights itself and re-checks them when a queued job starts, so a
//! demoted user's pending request is not executed.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;

use crate::protocol::{BrokerError, Catalog, Submitted, refuse};
use crate::runner::{Outcome, Runner};
use crate::store::{Change, Job, JobStatus, JobStore, JobView, MAX_JOBS, now};
use garrison_authz::{Authority, Error, Grant};
use garrison_core::config::Action;
use garrison_core::{constant_time, hex};

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
pub type Worker = Box<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync>;

/// Each accepted job runs on its own thread.
pub fn threads() -> Worker {
    Box::new(|work| {
        let started = thread::Builder::new()
            .name("maintenance-action".into())
            .spawn(work);
        if let Err(error) = started {
            log::error!("Could not start a maintenance job: {error}");
        }
    })
}

/// `xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx` in lowercase.
fn is_request_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            14 => *byte == b'4',
            19 => b"89ab".contains(byte),
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
}

/// A job ID: 32 lowercase hex digits.
pub fn is_job_id(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A random version-4 UUID as 32 lowercase hex digits without dashes.
fn job_id() -> Result<String, BrokerError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| refuse(500, "Internal broker error"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(hex::encode(&bytes))
}

pub struct Broker {
    authority: Box<dyn Authorize>,
    actions: Vec<Action>,
    store: Mutex<JobStore>,
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
            runner,
            worker,
        })
    }

    fn store(&self) -> MutexGuard<'_, JobStore> {
        // Every write is one statement, so a panic leaves the audit consistent.
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn action(&self, id: &str) -> Option<&Action> {
        self.actions.iter().find(|action| action.id == id)
    }

    pub fn authorize(&self, token: &str) -> Result<Grant, BrokerError> {
        self.authority
            .authorize(token)
            .map_err(|error| match error {
                Error::InvalidToken(_) => refuse(401, "Sign-in required again"),
                Error::Unavailable(_) => refuse(503, "Authorization is temporarily unavailable"),
                Error::Denied(reason) => {
                    log::info!("Garrison access denied: {reason}");
                    refuse(403, "Garrison access is not authorized")
                }
            })
    }

    pub fn catalog(&self, token: &str) -> Result<Catalog, BrokerError> {
        let grant = self.authorize(token)?;
        let actions = self
            .actions
            .iter()
            .filter(|action| grant.allows_action(&action.id))
            .map(Action::public)
            .collect();
        let store = self.store();
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

    pub fn job(&self, token: &str, identifier: &str) -> Result<JobView, BrokerError> {
        let grant = self.authorize(token)?;
        if !is_job_id(identifier) {
            return Err(refuse(400, "Invalid job ID"));
        }
        let job = self.store().get(identifier)?;
        match job {
            Some(job) if grant.allows_action(&job.action_id) => Ok(job.view()),
            _ => Err(refuse(404, "Job not found")),
        }
    }

    pub fn submit(
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
            let store = self.store();
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
        (self.worker)(Box::new(move || {
            broker.execute(&identifier, &action, &token);
        }));
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
        let latest = store.latest_created(None)?;
        if latest.is_some_and(|latest| at - latest < SETTLE_SECONDS) {
            return Err(refuse(429, "Allow the previous operation to settle first"));
        }
        let latest = store.latest_created(Some(&action.id))?;
        if latest.is_some_and(|latest| at - latest < i64::from(action.cooldown_seconds)) {
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

    fn record(&self, identifier: &str, change: &Change<'_>) {
        if let Err(error) = self.store().update(identifier, change) {
            log::error!("Could not record maintenance job {identifier}: {error}");
        }
    }

    /// Run an accepted job. A queued request is not a durable permission, so
    /// the rights are checked again first.
    fn execute(&self, identifier: &str, action: &Action, token: &str) {
        let allowed = self
            .authority
            .authorize(token)
            .is_ok_and(|grant| grant.allows_action(&action.id));
        if !allowed {
            self.record(
                identifier,
                &Change {
                    status: Some(JobStatus::Failed),
                    finished_at: Some(now()),
                    message: Some("Authorization changed before execution; nothing was run."),
                    ..Change::default()
                },
            );
            return;
        }
        self.record(
            identifier,
            &Change {
                status: Some(JobStatus::Running),
                started_at: Some(now()),
                message: Some("Running."),
                ..Change::default()
            },
        );
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
            &Change {
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
mod failure_tests;
#[cfg(test)]
mod record_tests;
#[cfg(test)]
pub(crate) mod tests;
