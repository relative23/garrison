//! An answer of Stalwart's that this release does not read grants nothing
//! and refuses nobody: the check of a user's rights answers 503, as when
//! Stalwart is away, never 403, which would end the user's session, and the
//! broker's journal names the answer as an error. A job whose start meets
//! such an answer runs nothing, and its record says so.

use garrison_testing::http::{answer, json};
use serde_json::json as value;

use super::limit_tests::{TOKEN, broker, granted, kept, kept_lines};
use super::tests::REQUEST;
use super::*;

/// What the broker answers a check of a user's rights where Stalwart answers
/// the broker's requests with `answers`, one after another.
fn checked(answers: Vec<String>) -> BrokerError {
    let (broker, server, _directory) = broker(answers);
    let error = broker.authorize(TOKEN).unwrap_err();
    server.requests();
    error
}

/// The journal's errors that name an answer this release does not read and
/// hold `answer`.
fn named(answer: &str) -> Vec<String> {
    kept_lines(
        "ERROR Access rights cannot be checked: Stalwart answered in a form this release of \
         Garrison does not read",
        answer,
    )
}

#[test]
fn an_unreadable_userinfo_answer_is_no_refusal_of_the_user() {
    kept();
    let cases = [
        ("no JSON", answer(200, "<html>Welcome</html>")),
        ("no subject", json(&value!({"email": "ann@example.test"}))),
        ("over its limit", answer(200, &"x".repeat(70_000))),
    ];
    for (case, userinfo) in cases {
        let error = checked(vec![userinfo]);
        assert_eq!(
            (error.status, error.message.as_str()),
            (503, "Authorization is temporarily unavailable"),
            "{case}"
        );
    }
    let lines = named("UserInfo: The provider returned no stable subject");
    assert!(!lines.is_empty(), "{lines:?}");
}

/// UserInfo refuses a token that is no longer valid with 401, which ends
/// the user's session; another status says nothing of the token, such as
/// 404 where the endpoint moved, and ends nobody's.
#[test]
fn a_userinfo_answer_of_another_status_signs_nobody_out() {
    kept();
    for status in [400, 403, 404, 405] {
        let error = checked(vec![answer(status, "")]);
        assert_eq!(
            (error.status, error.message.as_str()),
            (503, "Authorization is temporarily unavailable"),
            "{status}"
        );
    }
    let lines = named("UserInfo: Stalwart answered HTTP 405");
    assert!(!lines.is_empty(), "{lines:?}");
    let ended = checked(vec![answer(401, "")]);
    assert_eq!(
        (ended.status, ended.message.as_str()),
        (401, "Sign-in required again")
    );
}

#[test]
fn an_unreadable_answer_of_the_management_api_is_named_as_such() {
    kept();
    let identity = json(&value!({"sub": "1", "email": "ann@example.test"}));
    // An account whose permissions are of a kind this release does not know.
    let account = json(&value!({"methodResponses": [["x:Account/get", {"list": [
        {"id": "b", "@type": "User", "roles": {"@type": "User"},
         "permissions": {"@type": "Whatever"}}
    ], "notFound": []}, "0"]]}));
    let error = checked(vec![identity, account]);
    assert_eq!(
        (error.status, error.message.as_str()),
        (503, "Authorization is temporarily unavailable")
    );
    let lines = named("the management API: x:Account/get returned an unsupported object");
    assert!(!lines.is_empty(), "{lines:?}");
}

#[test]
fn a_job_whose_start_meets_an_unreadable_answer_says_so() {
    kept();
    let mut answers = granted();
    answers.push(answer(200, "[not, json"));
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
            "Authorization could not be checked before execution: Stalwart answered in a form \
             this release of Garrison does not read, and the broker's journal names the answer. \
             Nothing was run.",
            None
        )
    );
    let lines = kept_lines(&format!("ERROR Rights for job {}", job.id), "UserInfo");
    assert_eq!(lines.len(), 1, "{lines:?}");
}
