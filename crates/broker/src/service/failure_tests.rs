//! Refusals and failures: a denied grant, an operation that may still run, a
//! full audit, a runner that panics and an audit store that broke.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;

use super::tests::{REQUEST, Tokens, action, make, sent};
use super::*;

/// A runner whose unit may still be busy and whose run may panic.
#[derive(Default)]
struct Unruly {
    busy: AtomicBool,
    panics: AtomicBool,
}

impl Runner for Arc<Unruly> {
    fn preflight(&self, _: &Action) -> Result<(), BrokerError> {
        Ok(())
    }

    fn still_running(&self, _: &Action) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    fn run(&self, _: &Action) -> Outcome {
        assert!(
            !self.panics.load(Ordering::SeqCst),
            "the unit could not be reached"
        );
        Outcome {
            status: JobStatus::Uncertain,
            message: "systemd did not answer in time.",
            may_still_run: true,
        }
    }
}

fn unruly(runner: &Arc<Unruly>, directory: &Path) -> Arc<Broker> {
    Broker::new(
        Box::new(Arc::new(Tokens::standard())),
        vec![
            action("run_monitor", "RUN HEALTH CHECKS", "m.service", 0),
            action("run_backup", "RUN BACKUP", "b.service", 0),
        ],
        JobStore::open(&directory.join("jobs.sqlite")).unwrap(),
        Box::new(Arc::clone(runner)),
        Box::new(|work| work()),
    )
}

fn submit(
    broker: &Arc<Broker>,
    action: &str,
    request: &str,
    phrase: &str,
) -> Result<Value, BrokerError> {
    broker
        .submit("admin-token", action, request, phrase)
        .map(sent)
}

fn stored(broker: &Broker, answer: &Value) -> Job {
    let id = answer["job"]["id"].as_str().unwrap();
    broker.store().get(id).unwrap().unwrap()
}

#[test]
fn a_denied_grant_is_refused_before_anything_runs() {
    let setup = make(false);
    setup.tokens.set(
        "admin-token",
        Err(Error::Denied("no role grants Garrison".into())),
    );
    let refused = submit(&setup.broker, "run_monitor", REQUEST, "RUN HEALTH CHECKS").unwrap_err();
    assert_eq!(
        (refused.status, refused.message.as_str()),
        (403, "Garrison access is not authorized")
    );
    assert_eq!(setup.broker.catalog("admin-token").unwrap_err().status, 403);
    let job = "0b3f1a6e4f9d4c1e9a2b1c3d5e7f9a0b";
    assert_eq!(
        setup.broker.job("admin-token", job).unwrap_err().status,
        403
    );
    assert!(setup.systemd.runs.lock().unwrap().is_empty());
}

#[test]
fn an_operation_that_may_still_run_holds_back_the_next() {
    let directory = tempfile::tempdir().unwrap();
    let runner = Arc::new(Unruly::default());
    let broker = unruly(&runner, directory.path());
    let first = submit(&broker, "run_monitor", REQUEST, "RUN HEALTH CHECKS").unwrap();
    assert!(stored(&broker, &first).may_still_run);
    runner.busy.store(true, Ordering::SeqCst);
    let other = REQUEST.replace("0b3f", "4b3f");
    let refused = submit(&broker, "run_backup", &other, "RUN BACKUP").unwrap_err();
    assert_eq!(
        (refused.status, refused.message.as_str()),
        (409, "An earlier operation may still be running")
    );
    // The mark stays until the unit is idle, so the next request asks again.
    assert!(stored(&broker, &first).may_still_run);
}

#[test]
fn a_runner_that_panics_leaves_the_job_uncertain() {
    let directory = tempfile::tempdir().unwrap();
    let runner = Arc::new(Unruly::default());
    runner.panics.store(true, Ordering::SeqCst);
    let broker = unruly(&runner, directory.path());
    let answer = submit(&broker, "run_monitor", REQUEST, "RUN HEALTH CHECKS").unwrap();
    let job = stored(&broker, &answer);
    assert_eq!(
        (job.status, job.message.as_str(), job.may_still_run),
        (
            JobStatus::Uncertain,
            "The result could not be confirmed. Consult the host journal.",
            true
        )
    );
    assert!(job.finished_at.is_some());
}

#[test]
fn a_full_audit_refuses_new_jobs_and_evicts_nothing() {
    let setup = make(false);
    {
        let store = setup.broker.store();
        for index in 0..MAX_JOBS {
            let job = Job {
                id: format!("{index:0>32}"),
                action_id: "run_backup".into(),
                actor: "1".into(),
                actor_email: String::new(),
                request_id: format!("request-{index}"),
                status: JobStatus::Succeeded,
                created_at: now() - 3600,
                started_at: None,
                finished_at: None,
                message: String::new(),
                may_still_run: false,
            };
            store.insert(&job).unwrap();
        }
    }
    let refused = submit(&setup.broker, "run_monitor", REQUEST, "RUN HEALTH CHECKS").unwrap_err();
    assert_eq!(
        (refused.status, refused.message.as_str()),
        (
            503,
            "Audit capacity reached; retained records are not evicted"
        )
    );
    assert_eq!(setup.broker.store().count().unwrap(), MAX_JOBS);
    assert!(setup.systemd.runs.lock().unwrap().is_empty());
}

#[test]
fn a_broken_audit_store_is_an_internal_error() {
    let setup = make(false);
    let database = setup.directory.path().join("jobs.sqlite");
    rusqlite::Connection::open(database)
        .unwrap()
        .execute_batch("DROP TABLE jobs")
        .unwrap();
    let failed = setup.broker.catalog("admin-token").unwrap_err();
    assert_eq!(
        (failed.status, failed.message.as_str()),
        (500, "Internal broker error")
    );
    let refused = submit(&setup.broker, "run_monitor", REQUEST, "RUN HEALTH CHECKS").unwrap_err();
    assert_eq!(refused.status, 500);
    assert!(setup.systemd.runs.lock().unwrap().is_empty());
}
