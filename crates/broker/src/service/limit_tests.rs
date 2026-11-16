//! Stalwart's own rate limit: where it answers the broker 429, the check of
//! a user's rights fails with 503 as when Stalwart is away, and the broker's
//! journal says that Stalwart refused it for its limit and whose budget it
//! was, once a minute and not once per refusal. A job whose start meets the
//! limit runs nothing, and its record says that it was the limit.

use std::sync::{Mutex, Once};

use garrison_testing::http::{json, serve};
use garrison_testing::{config, credentials, policy_document, write_policy};
use serde_json::Value;

use super::tests::{REQUEST, Systemd};
use super::*;

pub(super) const TOKEN: &str = "token-0123456789abcdef";
/// Stalwart's answer to a request beyond its limit.
const LIMITED: &str =
    "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The lines the broker writes to its journal in this test binary.
struct Journal(Mutex<Vec<String>>);

impl log::Log for Journal {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        if record.target().starts_with("garrison_broker") {
            let line = format!("{} {}", record.level(), record.args());
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(line);
        }
    }

    fn flush(&self) {}
}

static JOURNAL: Journal = Journal(Mutex::new(Vec::new()));
static KEPT: Once = Once::new();

/// From now on the journal's lines are kept for the tests.
pub(super) fn kept() {
    KEPT.call_once(|| {
        log::set_logger(&JOURNAL).unwrap();
        log::set_max_level(log::LevelFilter::Info);
    });
}

/// The kept lines that begin with `start` and name `whose` budget.
pub(super) fn kept_lines(start: &str, whose: &str) -> Vec<String> {
    JOURNAL
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|line| line.starts_with(start) && line.contains(whose))
        .cloned()
        .collect()
}

/// The kept lines that say the limit refused checks of `whose` budget: the
/// line written at most once a minute, not that of a job, which tests of
/// other brokers may write in the meantime.
fn said(whose: &str) -> Vec<String> {
    kept_lines(
        "WARN Stalwart refused a check of a user's rights for its rate limit",
        whose,
    )
}

/// A broker with Garrison's own authority, against a stand-in for
/// Stalwart that answers `responses` in turn.
pub(super) fn broker(
    responses: Vec<String>,
) -> (
    Arc<Broker>,
    garrison_testing::http::Server,
    tempfile::TempDir,
) {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(responses);
    let config = config(directory.path(), &server.url);
    write_policy(&config, &policy_document());
    let authority = Authority::new(&config, credentials(&config));
    let store = JobStore::open(&directory.path().join("jobs.sqlite")).unwrap();
    let broker = Broker::new(
        Box::new(authority),
        config.broker.actions.clone(),
        store,
        Box::new(Arc::new(Systemd::default())),
        Box::new(|work| {
            work();
            Ok(())
        }),
    );
    (broker, server, directory)
}

/// Twenty checks in a row, each refused for Stalwart's limit.
fn refused(broker: &Broker) {
    for _ in 0..20 {
        let error = broker.authorize(TOKEN).unwrap_err();
        assert_eq!(
            (error.status, error.message.as_str()),
            (503, "Authorization is temporarily unavailable")
        );
    }
}

#[test]
fn a_user_token_beyond_stalwarts_limit_is_said_in_the_journal_once() {
    kept();
    let (broker, server, _directory) = broker(vec![LIMITED.to_owned(); 20]);
    refused(&broker);
    server.requests();
    let lines = said("the user's token");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].starts_with("WARN Stalwart refused"),
        "{}",
        lines[0]
    );
}

#[test]
fn the_brokers_key_beyond_stalwarts_limit_is_said_in_the_journal_once() {
    kept();
    // UserInfo takes the user's token; the management API refuses the key.
    let identity = json(&serde_json::json!({"sub": "1", "email": "ann@example.test"}));
    let mut answers = Vec::new();
    for _ in 0..20 {
        answers.push(identity.clone());
        answers.push(LIMITED.to_owned());
    }
    let (broker, server, _directory) = broker(answers);
    refused(&broker);
    server.requests();
    let lines = said("the broker's key");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].starts_with("WARN Stalwart refused"),
        "{}",
        lines[0]
    );
}

/// Stalwart's answers that grant subject 1, who holds the role `e` of the
/// test policy's administrator profile, both actions.
pub(super) fn granted() -> Vec<String> {
    let jmap = |method: &str, list: Value| {
        json(&serde_json::json!({
            "methodResponses": [[method, {"list": list, "notFound": []}, "0"]]
        }))
    };
    vec![
        json(&serde_json::json!({"sub": "1", "email": "ann@example.test"})),
        jmap(
            "x:Account/get",
            serde_json::json!([{"id": "b", "@type": "User",
                "roles": {"@type": "Custom", "roleIds": {"e": true}},
                "permissions": {"@type": "Inherit"}}]),
        ),
        jmap(
            "x:Authentication/get",
            serde_json::json!([{"id": "singleton", "defaultAdminRoleIds": {},
                "defaultUserRoleIds": {}}]),
        ),
        jmap(
            "x:Role/get",
            serde_json::json!([{"id": "e", "roleIds": {}, "disabledPermissions": {},
                "enabledPermissions": {"authenticate": true, "sysActionCreate": true,
                    "sysRoleUpdate": true}}]),
        ),
    ]
}

#[test]
fn a_job_whose_start_meets_stalwarts_limit_says_so() {
    kept();
    let identity = json(&serde_json::json!({"sub": "1", "email": "ann@example.test"}));
    // The request is granted; the check when the job starts meets the limit
    // at UserInfo, with the user's token, or at the management API, with the
    // broker's key.
    for (whose, at_start) in [
        ("the user's token", vec![LIMITED.to_owned()]),
        ("the broker's key", vec![identity, LIMITED.to_owned()]),
    ] {
        let mut answers = granted();
        answers.extend(at_start);
        let (broker, server, _directory) = broker(answers);
        let submitted = broker
            .submit(TOKEN, "run_monitor", REQUEST, "RUN HEALTH CHECKS")
            .unwrap();
        server.requests();
        let job = broker.store().get(&submitted.job.id).unwrap().unwrap();
        assert_eq!(
            (job.status, job.message.as_str(), job.started_at),
            (
                JobStatus::Failed,
                "Authorization could not be checked before execution: Stalwart refused the \
                 check for its rate limit (HTTP 429). Nothing was run.",
                None
            ),
            "{whose}"
        );
        let lines = kept_lines(&format!("WARN Rights for job {}", job.id), whose);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].ends_with("for its rate limit (HTTP 429)"),
            "{}",
            lines[0]
        );
    }
}
