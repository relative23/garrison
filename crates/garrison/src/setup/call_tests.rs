//! What setup says where Stalwart answers one of its calls in a form this
//! release does not read: the method, what was wrong, and where the
//! supported Stalwart releases are named.

use garrison_testing::http::{answer, serve};
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
    };
    let pointer = ", which this release of Garrison does not read; see the supported Stalwart \
                   releases in the README";
    let no_json = said();
    assert!(
        no_json.starts_with("x:WebHook/get: invalid JSON") && no_json.ends_with(pointer),
        "{no_json}"
    );
    for what in [
        "malformed answer",
        "malformed answer",
        "Stalwart response exceeds its size limit",
    ] {
        assert_eq!(said(), format!("x:WebHook/get: {what}{pointer}"));
    }
    server.requests();
}

/// Stalwart answers a wrong password, an unknown user and an API key it
/// does not know 401 (measured on Stalwart 1.1.0): setup says that the
/// administrator was refused and what to check, where it said
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
    };
    assert_eq!(
        said(),
        "Stalwart refused the administrator (HTTP 401): check the user name and the password, \
         or the API key."
    );
    assert!(
        said()
            .starts_with("Stalwart refused the administrator from this host's address (HTTP 403)"),
    );
    server.requests();
}
