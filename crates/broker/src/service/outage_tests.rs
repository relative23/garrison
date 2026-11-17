//! Stalwart that could not be reached or failed on its side at a check of a
//! user's rights: the check fails with 503, as for its rate limit, and the
//! broker's journal says how and at which request, at once and then once a
//! minute, not once per check. A job whose start meets it runs nothing, and
//! its record and its line say so. Beside it, every kind of failure of a
//! check has its answer and its line.

use garrison_testing::http::{answer, json};
use serde_json::json as value;

use super::limit_tests::{TOKEN, broker, granted, kept, kept_lines};
use super::tests::{REQUEST, make};
use super::*;

/// The kept lines that say Stalwart did not complete a check, and name `how`.
fn said(how: &str) -> Vec<String> {
    kept_lines(
        "WARN Stalwart did not complete a check of a user's rights",
        how,
    )
}

#[test]
fn an_outage_of_stalwart_at_a_check_is_said_in_the_journal_once() {
    kept();
    let identity = json(&value!({"sub": "1", "email": "ann@example.test"}));
    let failed = json(&value!({"methodResponses": [["error", {"type": "serverFail"}, "0"]]}));
    let cases = [
        (
            "UserInfo: Stalwart answered HTTP 503",
            vec![answer(503, ""); 20],
        ),
        // A connection closed without an answer, as by Stalwart restarting.
        ("UserInfo: Stalwart is unavailable", vec![String::new(); 20]),
        (
            "the management API: Stalwart could not complete the request",
            (0..20)
                .flat_map(|_| [identity.clone(), failed.clone()])
                .collect(),
        ),
    ];
    for (how, answers) in cases {
        let (broker, server, _directory) = broker(answers);
        for _ in 0..20 {
            let error = broker.authorize(TOKEN).unwrap_err();
            assert_eq!(
                (error.status, error.message.as_str()),
                (503, "Authorization is temporarily unavailable"),
                "{how}"
            );
        }
        server.requests();
        let lines = said(how);
        assert_eq!(lines.len(), 1, "{how}: {lines:?}");
    }
}

#[test]
fn a_job_whose_start_meets_an_outage_says_so_and_names_it() {
    kept();
    let mut answers = granted();
    answers.push(answer(502, ""));
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
            "Authorization could not be checked before execution: Stalwart did not complete the \
             check, and the broker's journal says why. Nothing was run.",
            None
        )
    );
    let lines = kept_lines(
        &format!("WARN Rights for job {} could not be checked", job.id),
        "(UserInfo: Stalwart answered HTTP 502)",
    );
    assert_eq!(lines.len(), 1, "{lines:?}");
}

/// Every kind of error a check of a user's rights can meet has its answer
/// and a line in the journal that names its cause: what ends the user's
/// session (401, 403) at info, and what refuses nobody (503), Stalwart's
/// outage and rate limit as a warning, Garrison's own setup and an answer
/// this release does not read as an error. Each reason here is the case's
/// own, so that the line found is this check's.
#[test]
fn every_kind_of_failure_of_a_check_has_its_answer_and_its_line() {
    kept();
    let unavailable = "Authorization is temporarily unavailable";
    let cases = [
        (
            Error::InvalidToken("The access token is no longer valid (case a)".into()),
            (401, "Sign-in required again"),
            "INFO Sign-in required again: The access token is no longer valid (case a)",
        ),
        (
            Error::Denied("This identity has no eligible Garrison profile (case b)".into()),
            (403, "Garrison access is not authorized"),
            "INFO Garrison access denied: This identity has no eligible Garrison profile (case b)",
        ),
        (
            Error::Unavailable("UserInfo: Stalwart answered HTTP 504 (case c)".into()),
            (503, unavailable),
            "WARN Stalwart did not complete a check of a user's rights (UserInfo: Stalwart \
             answered HTTP 504 (case c))",
        ),
        (
            Error::Limited("a budget of case d".into()),
            (503, unavailable),
            "WARN Stalwart refused a check of a user's rights for its rate limit (HTTP 429 to \
             a budget of case d)",
        ),
        (
            Error::Misconfigured("Garrison access policy: unreadable (case e)".into()),
            (
                503,
                "Garrison is not set up to check access rights; the broker's journal says why",
            ),
            "ERROR Access rights cannot be checked: Garrison access policy: unreadable (case e)",
        ),
        (
            Error::Unreadable("UserInfo: no subject (case f)".into()),
            (503, unavailable),
            "ERROR Access rights cannot be checked: Stalwart answered in a form this release of \
             Garrison does not read (UserInfo: no subject (case f))",
        ),
    ];
    for (error, (status, message), line) in cases {
        let setup = make(false);
        setup.tokens.set("admin-token", Err(error));
        let refused = setup.broker.authorize("admin-token").unwrap_err();
        assert_eq!(
            (refused.status, refused.message.as_str()),
            (status, message),
            "{line}"
        );
        assert_eq!(kept_lines(line, "").len(), 1, "{line}");
    }
}
