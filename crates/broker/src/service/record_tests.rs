//! Identifiers, the job record and the capacity rules at their limits.

use std::collections::BTreeSet;
use std::path::PathBuf;

use garrison_authz::Error;
use serde_json::Value;

use super::tests::{REQUEST, Setup, Tokens, action, make, sent};
use super::*;

const MINUTE: i64 = 60;

fn submit_monitor(setup: &Setup, request: &str) -> Result<Value, BrokerError> {
    setup
        .broker
        .submit("admin-token", "run_monitor", request, "RUN HEALTH CHECKS")
        .map(sent)
}

fn old_job(id: &str, action: &str, age: i64) -> Job {
    Job {
        id: format!("{id:0>32}"),
        action_id: action.into(),
        actor: "1".into(),
        actor_email: "1@example.test".into(),
        request_id: format!("request-{id}"),
        status: JobStatus::Succeeded,
        created_at: now() - age,
        started_at: None,
        finished_at: None,
        message: "Done.".into(),
        may_still_run: false,
    }
}

#[test]
fn request_ids_are_lowercase_version_4_uuids() {
    assert!(is_request_id(REQUEST));
    for invalid in [
        "0b3f1a6e-4f9d-4c1e-0a2b-1c3d5e7f9a0b",
        "0b3f1a6e-4f9d-5c1e-9a2b-1c3d5e7f9a0b",
        "0B3F1A6E-4F9D-4C1E-9A2B-1C3D5E7F9A0B",
        "0b3f1a6e4f9d4c1e9a2b1c3d5e7f9a0b",
        "0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0",
    ] {
        assert!(!is_request_id(invalid), "{invalid}");
    }
}

#[test]
fn job_ids_are_random_version_4_uuids() {
    let ids: BTreeSet<String> = (0..20).map(|_| job_id().unwrap()).collect();
    assert_eq!(ids.len(), 20);
    for id in &ids {
        assert!(is_job_id(id), "{id}");
        assert_eq!(&id[12..13], "4", "{id}");
        assert!("89ab".contains(&id[16..17]), "{id}");
    }
    assert!(!is_job_id(&"a".repeat(31)));
    assert!(!is_job_id(&"a".repeat(33)));
    assert!(!is_job_id(&"A".repeat(32)));
}

#[test]
fn a_finished_job_records_every_result() {
    let setup = make(false);
    let answer = submit_monitor(&setup, REQUEST).unwrap();
    let job = setup
        .broker
        .store()
        .get(answer["job"]["id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        (job.status, job.message.as_str()),
        (JobStatus::Succeeded, "ok")
    );
    let (started, finished) = (job.started_at.unwrap(), job.finished_at.unwrap());
    assert!(job.created_at <= started && started <= finished);
    assert!(!job.may_still_run);
}

#[test]
fn a_job_whose_rights_vanished_is_finished_without_running() {
    let setup = make(true);
    let answer = submit_monitor(&setup, REQUEST).unwrap();
    setup
        .tokens
        .set("admin-token", Err(Error::Denied("demoted".into())));
    for work in setup.queue.as_ref().unwrap().lock().unwrap().drain(..) {
        work();
    }
    let job = setup
        .broker
        .store()
        .get(answer["job"]["id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(job.status, JobStatus::Failed);
    assert!(job.finished_at.is_some() && job.started_at.is_none());
    assert!(setup.systemd.runs.lock().unwrap().is_empty());
}

#[test]
fn the_cooldown_and_the_settle_time_end_on_time() {
    let setup = make(false);
    let store = setup.broker.store();
    store
        .insert(&old_job("1", "run_monitor", 5 * MINUTE - 10))
        .unwrap();
    drop(store);
    let refused = submit_monitor(&setup, REQUEST).unwrap_err();
    assert_eq!(
        refused.message,
        "This action is still in its cooldown period"
    );

    let setup = make(false);
    let store = setup.broker.store();
    store
        .insert(&old_job("1", "run_monitor", 5 * MINUTE + 10))
        .unwrap();
    store
        .insert(&old_job("2", "run_backup", MINUTE / 2 - 5))
        .unwrap();
    drop(store);
    let refused = submit_monitor(&setup, REQUEST).unwrap_err();
    assert_eq!(
        refused.message,
        "Allow the previous operation to settle first"
    );

    let setup = make(false);
    let store = setup.broker.store();
    store
        .insert(&old_job("1", "run_monitor", 5 * MINUTE + 10))
        .unwrap();
    store
        .insert(&old_job("2", "run_backup", MINUTE / 2 + 5))
        .unwrap();
    drop(store);
    assert!(submit_monitor(&setup, REQUEST).is_ok());

    // Both waits are over in the second they end, and not a second before.
    // (A clock that ticks during the test only moves a job further back.)
    let setup = make(false);
    let store = setup.broker.store();
    store
        .insert(&old_job("1", "run_monitor", 5 * MINUTE))
        .unwrap();
    store
        .insert(&old_job("2", "run_backup", MINUTE / 2))
        .unwrap();
    drop(store);
    assert!(submit_monitor(&setup, REQUEST).is_ok());
    for (first, second, reason) in [
        (
            5 * MINUTE - 2,
            MINUTE,
            "This action is still in its cooldown period",
        ),
        (
            6 * MINUTE,
            MINUTE / 2 - 2,
            "Allow the previous operation to settle first",
        ),
    ] {
        let setup = make(false);
        let store = setup.broker.store();
        store.insert(&old_job("1", "run_monitor", first)).unwrap();
        store.insert(&old_job("2", "run_backup", second)).unwrap();
        drop(store);
        assert_eq!(submit_monitor(&setup, REQUEST).unwrap_err().message, reason);
    }
}

#[test]
fn a_job_that_may_still_run_is_settled_once_its_unit_is_idle() {
    let setup = make(false);
    let earlier = Job {
        may_still_run: true,
        ..old_job("1", "run_backup", 10 * MINUTE)
    };
    setup.broker.store().insert(&earlier).unwrap();
    assert!(submit_monitor(&setup, REQUEST).is_ok());
    let settled = setup.broker.store().get(&earlier.id).unwrap().unwrap();
    assert!(!settled.may_still_run);
    assert_eq!(settled.status, JobStatus::Succeeded);
}

#[test]
fn debug_output_names_the_actions_only() {
    let setup = make(false);
    let text = format!("{:?}", setup.broker);
    assert!(text.starts_with("Broker"), "{text}");
    assert!(text.contains("run_monitor"), "{text}");
    assert!(!text.contains("admin-token"), "{text}");
}

/// Reads the job's record while it runs, then ends it with `outcome`.
struct Watching {
    database: PathBuf,
    outcome: fn() -> Outcome,
    seen: Mutex<Option<(String, String, bool)>>,
}

impl Runner for Arc<Watching> {
    fn preflight(&self, _: &Action) -> Result<(), BrokerError> {
        Ok(())
    }

    fn still_running(&self, _: &Action) -> bool {
        false
    }

    fn run(&self, _: &Action) -> Outcome {
        let db = rusqlite::Connection::open(&self.database).unwrap();
        let sql = "SELECT status, message, started_at IS NOT NULL FROM jobs";
        let seen = db.query_row(sql, [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)));
        *self.seen.lock().unwrap() = Some(seen.unwrap());
        (self.outcome)()
    }
}

#[test]
fn a_running_job_says_so_and_a_doubtful_end_is_kept() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("jobs.sqlite");
    let watching = Arc::new(Watching {
        database: database.clone(),
        outcome: || Outcome {
            status: JobStatus::Uncertain,
            message: "systemd did not answer in time.",
            may_still_run: true,
        },
        seen: Mutex::default(),
    });
    let broker = Broker::new(
        Box::new(Arc::new(Tokens::standard())),
        vec![action("run_monitor", "RUN HEALTH CHECKS", "m.service", 0)],
        JobStore::open(&database).unwrap(),
        Box::new(Arc::clone(&watching)),
        Box::new(|work| work()),
    );
    let answer = broker
        .submit("admin-token", "run_monitor", REQUEST, "RUN HEALTH CHECKS")
        .unwrap();
    let seen = watching.seen.lock().unwrap().clone();
    assert_eq!(seen, Some(("running".into(), "Running.".into(), true)));
    let job = broker.store().get(&answer.job.id).unwrap().unwrap();
    assert_eq!(
        (job.status, job.message.as_str(), job.may_still_run),
        (
            JobStatus::Uncertain,
            "systemd did not answer in time.",
            true
        )
    );
}
