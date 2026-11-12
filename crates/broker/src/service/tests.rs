use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use garrison_core::config::Operation;
use garrison_core::modules::ModuleId;
use serde_json::{Value, json};

use super::*;

pub(crate) const REQUEST: &str = "0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b";

pub(crate) fn action(id: &str, confirmation: &str, unit: &str, cooldown: u32) -> Action {
    Action {
        id: id.into(),
        title: id.into(),
        description: "d".into(),
        confirmation: confirmation.into(),
        unit: unit.into(),
        operation: Operation::Start,
        cooldown_seconds: cooldown,
        timeout_seconds: 60,
        operator: true,
    }
}

fn grant(subject: &str, actions: &[&str]) -> Grant {
    Grant {
        subject: subject.into(),
        email: format!("{subject}@example.test"),
        modules: BTreeSet::from([ModuleId::Actions, ModuleId::Dashboard]),
        actions: actions.iter().map(ToString::to_string).collect(),
        profiles: vec!["administrator".into()],
        checked_at: "2026-10-29T00:00:00+00:00".into(),
    }
}

/// Maps tokens to grants exactly as UserInfo and the policy would.
#[derive(Default)]
pub(crate) struct Tokens(pub(crate) Mutex<BTreeMap<String, Result<Grant, Error>>>);

impl Tokens {
    pub(crate) fn standard() -> Self {
        let tokens = Tokens::default();
        tokens.set(
            "admin-token",
            Ok(grant("1", &["run_monitor", "run_backup"])),
        );
        tokens.set("viewer-token", Ok(grant("2", &[])));
        tokens
    }

    pub(crate) fn set(&self, token: &str, value: Result<Grant, Error>) {
        self.0.lock().unwrap().insert(token.into(), value);
    }
}

impl Authorize for Arc<Tokens> {
    fn authorize(&self, token: &str) -> Result<Grant, Error> {
        let tokens = self.0.lock().unwrap();
        tokens
            .get(token)
            .cloned()
            .unwrap_or_else(|| Err(Error::InvalidToken("unknown token".into())))
    }
}

#[derive(Default)]
pub(crate) struct Systemd {
    pub(crate) runs: Mutex<Vec<String>>,
}

impl Runner for Arc<Systemd> {
    fn preflight(&self, _: &Action) -> Result<(), BrokerError> {
        Ok(())
    }

    fn still_running(&self, _: &Action) -> bool {
        false
    }

    fn run(&self, action: &Action) -> Outcome {
        self.runs.lock().unwrap().push(action.id.clone());
        Outcome {
            status: JobStatus::Succeeded,
            message: "ok",
            may_still_run: false,
        }
    }
}

pub(crate) type Queue = Arc<Mutex<Vec<Box<dyn FnOnce() + Send>>>>;

pub(crate) struct Setup {
    pub(crate) broker: Arc<Broker>,
    pub(crate) tokens: Arc<Tokens>,
    pub(crate) systemd: Arc<Systemd>,
    pub(crate) queue: Option<Queue>,
    pub(crate) directory: tempfile::TempDir,
}

/// A broker with two actions; jobs run at once unless `queued`.
pub(crate) fn make(queued: bool) -> Setup {
    let directory = tempfile::tempdir().unwrap();
    let store = JobStore::open(&directory.path().join("jobs.sqlite")).unwrap();
    let (tokens, systemd) = (Arc::new(Tokens::standard()), Arc::new(Systemd::default()));
    let queue: Option<Queue> = queued.then(Queue::default);
    let worker: Worker = match &queue {
        Some(queue) => {
            let queue = Arc::clone(queue);
            Box::new(move |work| queue.lock().unwrap().push(work))
        }
        None => Box::new(|work| work()),
    };
    let actions = vec![
        action("run_monitor", "RUN HEALTH CHECKS", "m.service", 300),
        action("run_backup", "RUN BACKUP", "b.service", 0),
    ];
    let broker = Broker::new(
        Box::new(Arc::clone(&tokens)),
        actions,
        store,
        Box::new(Arc::clone(&systemd)),
        worker,
    );
    Setup {
        broker,
        tokens,
        systemd,
        queue,
        directory,
    }
}

fn submit(
    broker: &Arc<Broker>,
    token: &str,
    action: &str,
    request: &str,
    phrase: &str,
) -> Result<Value, BrokerError> {
    broker.submit(token, action, request, phrase).map(sent)
}

/// An answer as it goes over the socket.
pub(crate) fn sent(answer: impl serde::Serialize) -> Value {
    serde_json::to_value(answer).unwrap()
}

fn status(result: Result<Value, BrokerError>) -> u16 {
    result.unwrap_err().status
}

#[test]
fn identity_comes_from_the_token_not_from_the_caller() {
    let setup = make(false);
    let result = submit(
        &setup.broker,
        "admin-token",
        "run_monitor",
        REQUEST,
        "RUN HEALTH CHECKS",
    )
    .unwrap();
    assert_eq!(result["job"]["actor"], "1");
    assert_eq!(result["job"]["actorEmail"], "1@example.test");
    assert_eq!(*setup.systemd.runs.lock().unwrap(), ["run_monitor"]);
    let other = REQUEST.replace("0b3f", "1b3f");
    assert_eq!(
        status(submit(
            &setup.broker,
            "viewer-token",
            "run_monitor",
            &other,
            "RUN HEALTH CHECKS"
        )),
        403
    );
    assert_eq!(
        status(submit(
            &setup.broker,
            "forged-token",
            "run_monitor",
            REQUEST,
            "RUN HEALTH CHECKS"
        )),
        401
    );
}

#[test]
fn a_replay_is_idempotent_and_bound_to_actor_and_action() {
    let setup = make(false);
    let first = submit(
        &setup.broker,
        "admin-token",
        "run_monitor",
        REQUEST,
        "RUN HEALTH CHECKS",
    )
    .unwrap();
    let again = submit(
        &setup.broker,
        "admin-token",
        "run_monitor",
        REQUEST,
        "RUN HEALTH CHECKS",
    )
    .unwrap();
    assert_eq!(again["replayed"], true);
    assert_eq!(again["job"]["id"], first["job"]["id"]);
    assert_eq!(setup.systemd.runs.lock().unwrap().len(), 1);
    assert_eq!(
        status(submit(
            &setup.broker,
            "admin-token",
            "run_backup",
            REQUEST,
            "RUN BACKUP"
        )),
        409
    );
}

#[test]
fn confirmation_settle_time_and_cooldown() {
    let setup = make(false);
    let broker = &setup.broker;
    assert_eq!(
        status(submit(
            broker,
            "admin-token",
            "run_monitor",
            REQUEST,
            "run health checks"
        )),
        400
    );
    submit(broker, "admin-token", "run_backup", REQUEST, "RUN BACKUP").unwrap();
    let other = REQUEST.replace("0b3f", "2b3f");
    let settle = submit(
        broker,
        "admin-token",
        "run_monitor",
        &other,
        "RUN HEALTH CHECKS",
    );
    assert_eq!(
        settle.unwrap_err().message,
        "Allow the previous operation to settle first"
    );
}

#[test]
fn requests_are_validated_before_anything_runs() {
    let setup = make(false);
    let broker = &setup.broker;
    assert_eq!(
        status(submit(broker, "admin-token", "format_disk", REQUEST, "x")),
        403
    );
    for request in [
        "0B3F1A6E-4F9D-4C1E-9A2B-1C3D5E7F9A0B",
        "0b3f1a6e-4f9d-1c1e-9a2b-1c3d5e7f9a0b",
        "x",
    ] {
        assert_eq!(
            status(submit(
                broker,
                "admin-token",
                "run_monitor",
                request,
                "RUN HEALTH CHECKS"
            )),
            400
        );
    }
    assert!(setup.systemd.runs.lock().unwrap().is_empty());
}

#[test]
fn a_demotion_before_execution_prevents_the_run() {
    let setup = make(true);
    let result = submit(
        &setup.broker,
        "admin-token",
        "run_monitor",
        REQUEST,
        "RUN HEALTH CHECKS",
    )
    .unwrap();
    setup
        .tokens
        .set("admin-token", Err(Error::Denied("role removed".into())));
    let work = setup.queue.as_ref().unwrap().lock().unwrap().pop().unwrap();
    work();
    assert!(setup.systemd.runs.lock().unwrap().is_empty());
    let job = setup
        .broker
        .store()
        .get(result["job"]["id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(job.status, JobStatus::Failed);
    assert!(job.message.contains("Authorization changed"));
}

#[test]
fn an_unavailable_authority_is_a_temporary_error() {
    let setup = make(false);
    setup.tokens.set(
        "admin-token",
        Err(Error::Unavailable("Stalwart restarting".into())),
    );
    assert_eq!(
        setup.broker.authorize("admin-token").unwrap_err().status,
        503
    );
}

#[test]
fn a_queued_job_blocks_others_until_it_finishes() {
    let setup = make(true);
    submit(
        &setup.broker,
        "admin-token",
        "run_monitor",
        REQUEST,
        "RUN HEALTH CHECKS",
    )
    .unwrap();
    let other = REQUEST.replace("0b3f", "3b3f");
    let busy = submit(
        &setup.broker,
        "admin-token",
        "run_backup",
        &other,
        "RUN BACKUP",
    );
    assert_eq!(
        busy.unwrap_err().message,
        "Another maintenance operation is in progress"
    );
}

#[test]
fn jobs_are_visible_only_with_their_action() {
    let setup = make(false);
    let job = submit(
        &setup.broker,
        "admin-token",
        "run_monitor",
        REQUEST,
        "RUN HEALTH CHECKS",
    )
    .unwrap();
    let id = job["job"]["id"].as_str().unwrap();
    let stored = setup.broker.job("admin-token", id).unwrap();
    assert_eq!(stored.status, JobStatus::Succeeded);
    assert!(stored.finished_at.is_some());
    assert_eq!(
        setup.broker.job("viewer-token", id).unwrap_err().status,
        404
    );
    assert_eq!(
        setup.broker.job("admin-token", "nope").unwrap_err().status,
        400
    );
    let catalog = sent(setup.broker.catalog("admin-token").unwrap());
    assert_eq!(catalog["actions"].as_array().unwrap().len(), 2);
    assert_eq!(
        catalog["actions"][0],
        json!({
            "id": "run_monitor", "title": "run_monitor", "description": "d",
            "confirmation": "RUN HEALTH CHECKS", "cooldownSeconds": 300,
        })
    );
    assert_eq!(catalog["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(
        sent(setup.broker.catalog("viewer-token").unwrap()),
        json!({"actions": [], "jobs": []})
    );
}

#[test]
fn job_ids_are_random_version_4_uuids() {
    let (one, two) = (job_id().unwrap(), job_id().unwrap());
    assert_ne!(one, two);
    assert!(is_job_id(&one));
    assert_eq!(&one[12..13], "4");
    assert!("89ab".contains(&one[16..17]));
    assert!(is_request_id(REQUEST));
}

#[test]
fn without_the_maintenance_module_no_action_runs() {
    let setup = make(false);
    // Actions listed in a grant whose modules lack maintenance count for nothing.
    let mut grant = grant("1", &["run_monitor", "run_backup"]);
    grant.modules.remove(&ModuleId::Actions);
    setup.tokens.set("no-maintenance-token", Ok(grant));
    let refused = submit(
        &setup.broker,
        "no-maintenance-token",
        "run_monitor",
        REQUEST,
        "RUN HEALTH CHECKS",
    );
    assert_eq!(status(refused), 403);
    assert!(setup.systemd.runs.lock().unwrap().is_empty());
    assert_eq!(
        sent(setup.broker.catalog("no-maintenance-token").unwrap()),
        json!({"actions": [], "jobs": []})
    );
}
