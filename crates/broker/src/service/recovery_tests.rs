//! What the broker does where it cannot go on as planned: no thread for a
//! job, an audit that takes no record, and rights that cannot be confirmed
//! when the job starts.

use std::io;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::Value;

use super::limit_tests::{kept, kept_lines};
use super::tests::{REQUEST, Systemd, Tokens, action, make, sent};
use super::*;

fn actions() -> Vec<Action> {
    vec![
        action("run_monitor", "RUN HEALTH CHECKS", "m.service", 0),
        action("run_backup", "RUN BACKUP", "b.service", 0),
    ]
}

fn submit(broker: &Arc<Broker>, action: &str, request: &str) -> Result<Value, BrokerError> {
    let phrase = if action == "run_backup" {
        "RUN BACKUP"
    } else {
        "RUN HEALTH CHECKS"
    };
    broker
        .submit("admin-token", action, request, phrase)
        .map(sent)
}

/// The audit takes no record, as on a disk that fails: its table is away.
fn break_audit(directory: &Path) {
    Connection::open(directory.join("jobs.sqlite"))
        .unwrap()
        .execute_batch("ALTER TABLE jobs RENAME TO away")
        .unwrap();
}

fn mend_audit(directory: &Path) {
    Connection::open(directory.join("jobs.sqlite"))
        .unwrap()
        .execute_batch("ALTER TABLE away RENAME TO jobs")
        .unwrap();
}

#[test]
fn a_job_no_thread_could_be_started_for_fails_and_holds_nothing_back() {
    let directory = tempfile::tempdir().unwrap();
    let systemd = Arc::new(Systemd::default());
    let broker = Broker::new(
        Box::new(Arc::new(Tokens::standard())),
        actions(),
        JobStore::open(&directory.path().join("jobs.sqlite")).unwrap(),
        Box::new(Arc::clone(&systemd)),
        // The system gives no thread.
        Box::new(|_work| Err(io::Error::from(io::ErrorKind::WouldBlock))),
    );
    let answer = submit(&broker, "run_monitor", REQUEST).unwrap();
    assert_eq!(
        (&answer["job"]["status"], &answer["job"]["message"]),
        (
            &Value::from("failed"),
            &Value::from("The broker could not start the job; nothing was run.")
        )
    );
    let id = answer["job"]["id"].as_str().unwrap();
    let job = broker.store().get(id).unwrap().unwrap();
    assert_eq!(job.status, JobStatus::Failed);
    assert!(job.finished_at.is_some() && !job.may_still_run);
    assert!(systemd.runs.lock().unwrap().is_empty());
    // No job is in progress: the next waits for the settle time and for
    // nothing else, where it used to be refused until the broker restarted.
    let next = submit(&broker, "run_backup", &REQUEST.replace("0b3f", "1b3f")).unwrap_err();
    assert_eq!(
        (next.status, next.message.as_str()),
        (429, "Allow the previous operation to settle first")
    );
}

#[test]
fn a_job_whose_start_the_audit_does_not_take_is_not_run() {
    let setup = make(true);
    let answer = submit(&setup.broker, "run_monitor", REQUEST).unwrap();
    let id = answer["job"]["id"].as_str().unwrap();
    break_audit(setup.directory.path());
    let work = setup.queue.as_ref().unwrap().lock().unwrap().pop().unwrap();
    work();
    // What the audit does not hold does not happen.
    assert!(setup.systemd.runs.lock().unwrap().is_empty());
    mend_audit(setup.directory.path());
    // The audit takes records again, and the next request brings it up to
    // date: the job is over, and says why nothing ran.
    let job = setup.broker.job("admin-token", id).unwrap();
    assert_eq!(
        (job.status, job.message.as_str()),
        (
            JobStatus::Failed,
            "The job's start could not be recorded in the audit; nothing was run."
        )
    );
    // It did not start, and no record says that it did.
    assert!(job.started_at.is_none() && job.finished_at.is_some());
}

/// Rights that are confirmed for the request and whose check fails, as a
/// fault of the broker's own would, when the job starts.
struct Failing(std::sync::atomic::AtomicUsize);

impl Authorize for Failing {
    fn authorize(&self, token: &str) -> Result<Grant, Error> {
        let asked = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert!(asked == 0, "the check of the job's rights failed");
        Arc::new(Tokens::standard()).authorize(token)
    }
}

#[test]
fn a_job_the_broker_failed_on_is_over_and_holds_nothing_back() {
    let directory = tempfile::tempdir().unwrap();
    let systemd = Arc::new(Systemd::default());
    let broker = Broker::new(
        Box::new(Failing(std::sync::atomic::AtomicUsize::new(0))),
        actions(),
        JobStore::open(&directory.path().join("jobs.sqlite")).unwrap(),
        Box::new(Arc::clone(&systemd)),
        Box::new(|work| {
            work();
            Ok(())
        }),
    );
    let answer = submit(&broker, "run_monitor", REQUEST).unwrap();
    let id = answer["job"]["id"].as_str().unwrap();
    let job = broker.store().get(id).unwrap().unwrap();
    assert_eq!(
        (job.status, job.message.as_str(), job.may_still_run),
        (
            JobStatus::Uncertain,
            "The broker failed while it handled the job; whether anything was run is not \
             known. Consult the host journal.",
            true
        )
    );
    assert!(job.finished_at.is_some());
    assert!(systemd.runs.lock().unwrap().is_empty());
}

/// A runner during whose run the audit breaks.
struct Breaking(PathBuf);

impl Runner for Breaking {
    fn preflight(&self, _: &Action) -> Result<(), BrokerError> {
        Ok(())
    }

    fn still_running(&self, _: &Action) -> bool {
        false
    }

    fn run(&self, _: &Action) -> Outcome {
        break_audit(&self.0);
        Outcome {
            status: JobStatus::Succeeded,
            message: "ok",
            may_still_run: false,
        }
    }
}

#[test]
fn a_result_the_audit_did_not_take_is_recorded_once_it_takes_records_again() {
    let directory = tempfile::tempdir().unwrap();
    let broker = Broker::new(
        Box::new(Arc::new(Tokens::standard())),
        actions(),
        JobStore::open(&directory.path().join("jobs.sqlite")).unwrap(),
        Box::new(Breaking(directory.path().to_owned())),
        Box::new(|work| {
            work();
            Ok(())
        }),
    );
    let answer = submit(&broker, "run_monitor", REQUEST).unwrap();
    let id = answer["job"]["id"].as_str().unwrap();
    // While the audit is broken the broker says so.
    assert_eq!(broker.job("admin-token", id).unwrap_err().status, 500);
    mend_audit(directory.path());
    let job = broker.job("admin-token", id).unwrap();
    assert_eq!(
        (job.status, job.message.as_str()),
        (JobStatus::Succeeded, "ok")
    );
    assert!(job.started_at.is_some() && job.finished_at.is_some());
    // And nothing is held to be in progress any more.
    assert_eq!(broker.store().active().unwrap(), Vec::<Job>::new());
}

/// A job whose rights are not confirmed when it starts runs nothing, and its
/// record and a line in the journal say why, each reason here the case's
/// own, so that the line found is this job's.
#[test]
fn a_job_that_does_not_start_says_which_check_of_its_rights_failed() {
    kept();
    let cases: [(Result<Grant, Error>, &str, &str); 6] = [
        (
            Err(Error::Unavailable("UserInfo: timeout (case 1)".into())),
            "Authorization could not be checked before execution: Stalwart did not complete the \
             check, and the broker's journal says why. Nothing was run.",
            "WARN Rights for job {} could not be checked: Stalwart did not complete the check \
             (UserInfo: timeout (case 1))",
        ),
        (
            Err(Error::Limited("the broker's key (case 2)".into())),
            "Authorization could not be checked before execution: Stalwart refused the check \
             for its rate limit (HTTP 429). Nothing was run.",
            "WARN Rights for job {} could not be checked: Stalwart refused the broker's key (case \
             2) for its rate limit (HTTP 429)",
        ),
        (
            Err(Error::InvalidToken("expired (case 3)".into())),
            "The sign-in ended before execution; nothing was run.",
            "INFO The sign-in of job {} ended before it started: expired (case 3)",
        ),
        (
            Err(Error::Misconfigured("no policy (case 4)".into())),
            "Access rights could not be checked before execution: Garrison is not set up to \
             check them, and the broker's journal says why. Nothing was run.",
            "ERROR Rights for job {} could not be checked: Garrison is not set up to check them \
             (no policy (case 4))",
        ),
        (
            Err(Error::Denied("no role (case 5)".into())),
            "Authorization changed before execution; nothing was run.",
            "INFO Rights for job {} changed before it started: no role (case 5)",
        ),
        (
            Err(Error::Unreadable("UserInfo: no subject (case 6)".into())),
            "Authorization could not be checked before execution: Stalwart answered in a form \
             this release of Garrison does not read, and the broker's journal names the answer. \
             Nothing was run.",
            "ERROR Rights for job {} could not be checked: Stalwart answered in a form this \
             release of Garrison does not read (UserInfo: no subject (case 6))",
        ),
    ];
    for (outcome, message, line) in cases {
        let setup = make(true);
        let answer = submit(&setup.broker, "run_monitor", REQUEST).unwrap();
        let id = answer["job"]["id"].as_str().unwrap();
        // Between the request and the job's start the answer changes.
        setup.tokens.set("admin-token", outcome);
        let work = setup.queue.as_ref().unwrap().lock().unwrap().pop().unwrap();
        work();
        let job = setup.broker.store().get(id).unwrap().unwrap();
        assert_eq!(
            (job.status, job.message.as_str()),
            (JobStatus::Failed, message)
        );
        assert!(setup.systemd.runs.lock().unwrap().is_empty());
        let line = line.replace("{}", id);
        assert_eq!(kept_lines(&line, "").len(), 1, "{line}");
    }
}
