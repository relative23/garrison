//! What setup says where Stalwart answers one of its calls in a form this
//! release does not read: the method, what was wrong, and where the
//! supported Stalwart releases are named.

use garrison_core::files::ProtectedFileError;
use garrison_testing::http::{answer, serve};
use serde::de::IgnoredAny;
use serde_json::json;

use super::*;

#[test]
fn an_answer_this_release_does_not_read_is_said_as_one() {
    let server = serve(vec![
        answer(200, "<html>Welcome</html>"),
        answer(200, r#"{"methodResponses": []}"#),
        answer(200, r#"{"methodResponses": [["x:WebHook/get", [], "0"]]}"#),
        answer(200, &"x".repeat(MAX_ANSWER + 1)),
    ]);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer key".to_owned(),
    };
    let said = || {
        admin
            .call::<_, IgnoredAny>("x:WebHook/get", &json!({}))
            .unwrap_err()
            .state
    };
    let no_json = garrison_core::json::parse(b"<html>Welcome</html>", MAX_ANSWER).unwrap_err();
    assert_eq!(said(), states::unreadable("x:WebHook/get", no_json));
    for what in [
        "malformed answer",
        "malformed answer",
        "Stalwart response exceeds its size limit",
    ] {
        assert_eq!(said(), states::unreadable("x:WebHook/get", what));
    }
    server.requests();
}

/// Stalwart answers a wrong password, an unknown user and an API key it
/// does not know 401 (measured on Stalwart 1.1.0 and 1.2.0): setup says
/// that the administrator was refused and what to check, where it said
/// "x:ApiKey/get: HTTP 401". A credential it knows from an address it does
/// not take it from is answered 403.
#[test]
fn a_refused_administrator_is_said_as_such() {
    let server = serve(vec![answer(401, "{}"), answer(403, "{}")]);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Basic eDp5".to_owned(),
    };
    let said = || {
        admin
            .call::<_, IgnoredAny>("x:ApiKey/get", &json!({}))
            .unwrap_err()
            .state
    };
    assert_eq!(said(), states::administrator_refused());
    assert_eq!(said(), states::administrator_refused_here());
    server.requests();
}

/// A failure names the run that mends it: inside `garrison setup` the
/// wizard, which also takes the steps after this one, and not `garrison
/// stalwart setup`; so does a failure before Stalwart is asked anything.
#[test]
fn a_failure_names_the_run_that_mends_it() {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(vec![answer(401, "{}")]);
    let config = garrison_testing::config(directory.path(), &server.url);
    let credential = directory.path().join("admin.json");
    garrison_testing::write_private(&credential, br#"{"apiKey": "an-unknown-key"}"#);
    let asked = |again| Asked {
        skip_metrics: true,
        webhook_url: None,
        allowed: &[],
        rotate: false,
        again,
    };
    let refused = setup(&config, &Source::File(credential), &asked("garrison setup"));
    server.requests();
    assert_eq!(
        refused,
        Err(states::again(
            states::administrator_refused(),
            "garrison setup"
        ))
    );
    let missing = directory.path().join("missing.json");
    let unread = setup(
        &config,
        &Source::File(missing.clone()),
        &asked("garrison stalwart setup --rotate"),
    );
    let unavailable = ProtectedFileError::Unavailable(missing);
    assert_eq!(
        unread,
        Err(states::again(
            states::file_unread(unavailable),
            "garrison stalwart setup --rotate"
        ))
    );
}

/// Where a run fails once a new signature key or scrape credential is in
/// its file and before Stalwart has surely reloaded its settings, setup says
/// what may go without it until it runs again, inside the failure's state.
#[test]
fn a_failure_after_a_new_secret_says_what_may_go_without_it() {
    let error = || states::call_failed("x:Action/set", "Stalwart answered HTTP 503");
    assert_eq!(states::until(error(), false, false), error());
    let signature = states::signature_pending().to_string();
    let scrape = states::scrape_pending().to_string();
    for (key, credential) in [(true, false), (false, true), (true, true)] {
        let said = states::until(error(), key, credential);
        assert_eq!(said.name, error().name);
        assert_eq!(
            (said.text.contains(&signature), said.text.contains(&scrape)),
            (key, credential)
        );
    }
}

/// Stalwart refuses a request for its rate limit with 429, as where it sees
/// setup at another address than 127.0.0.1: setup says so and that a run
/// after its window goes through.
#[test]
fn a_rate_limit_is_said_as_one() {
    let server = serve(vec![answer(429, "{}")]);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer key".to_owned(),
    };
    let said = admin.call::<_, IgnoredAny>("x:ApiKey/get", &json!({}));
    server.requests();
    assert_eq!(said.unwrap_err().state, states::limited("x:ApiKey/get"));
}
