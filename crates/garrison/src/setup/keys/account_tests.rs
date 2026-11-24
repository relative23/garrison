//! Where a file's key is another administrator's: its keys of the
//! description are found in its account, kept or replaced there, and
//! removed from it.

use garrison_testing::http::{answer, json, serve};
use serde_json::json;

use super::tests::{COLLECTOR, NEW, OLD, listed, session};
use super::*;

/// What `ensure` does for the collector's key, which its file holds, where
/// the administrator's own account `b` has no key of its description and
/// Stalwart answers the session of the file's key with `session`, and the
/// requests after it with `after`: the step or the error, and the requests.
fn whose(session: String, after: Vec<String>) -> (Result<String, String>, Vec<String>) {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join(COLLECTOR.file);
    garrison_testing::write_private(&file, format!("{OLD}\n").as_bytes());
    let mut answers = vec![listed("b", &[]), session];
    answers.extend(after);
    let server = serve(answers);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer admin".to_owned(),
    };
    let networks = Enabled::of(["127.0.0.1/32"]);
    let shown = |text: String| text.replace(&directory.path().display().to_string(), "DIR");
    let outcome = ensure(&admin, directory.path(), &COLLECTOR, &networks, false)
        .map(|done| shown(done.step))
        .map_err(shown);
    (outcome, server.requests())
}

/// Where Stalwart's answer to the session of the file's key names no
/// account, as for its rate limit or an outage, the key may be another
/// administrator's: the run stops before it makes a key, which would leave
/// that one valid for good.
#[test]
fn a_key_whose_account_is_not_known_stops_the_run_before_a_key_is_made() {
    for status in [429, 503, 404] {
        let (outcome, requests) = whose(answer(status, "{}"), Vec::new());
        assert_eq!(
            outcome,
            Err(format!(
                "Asking Stalwart whose API key DIR/collector-native-key holds: Stalwart \
                 answered HTTP {status}"
            ))
        );
        assert_eq!(requests.len(), 2, "{status}");
    }
}

/// A key Stalwart does not know (401) belongs to no account, and one it
/// refuses from this host's address (403) names none: the run goes on with
/// the administrator's own keys, and the key try at its end says what is
/// wrong where Stalwart refuses the new key too.
#[test]
fn a_key_stalwart_does_not_know_or_refuses_here_names_no_account() {
    let made = json(&json!({"methodResponses": [["x:ApiKey/set",
        {"created": {"new": {"id": "fresh", "secret": NEW}}}, "0"]]}));
    for status in [401, 403] {
        let (outcome, requests) = whose(answer(status, "{}"), vec![made.clone()]);
        assert_eq!(
            outcome.as_deref(),
            Ok("created API key 'garrison collector' -> DIR/collector-native-key"),
            "{status}"
        );
        assert!(requests[2].contains(r#""create""#), "{}", requests[2]);
    }
}

/// A user without administrator rights is not shown the account that an
/// administrator's key belongs to, which Stalwart answers accountNotFound
/// (measured on Stalwart 1.1.0): setup says to run it as an administrator,
/// as where such a user may not make a key.
#[test]
fn an_account_the_administrator_may_not_see_is_said_as_such() {
    let missing = json(
        &json!({"methodResponses": [["error", {"type": "accountNotFound",
        "description": "The accountId does not correspond to a valid account"}, "0"]]}),
    );
    let (outcome, requests) = whose(session("c"), vec![missing]);
    assert_eq!(
        outcome,
        Err(
            "Stalwart does not show the administrator the account that the API key in \
             DIR/collector-native-key belongs to: run setup as an administrator who holds the \
             keys' permissions, as one with Stalwart's administrator role (x:ApiKey/get: \
             accountNotFound The accountId does not correspond to a valid account)"
                .to_owned()
        )
    );
    assert!(
        requests[2].contains(r#""accountId":"c""#),
        "{}",
        requests[2]
    );
}

/// What `ensure` does where the file's key belongs to another
/// administrator's account, `c`, which holds the key `k` of the
/// description: the step, the keys it replaces, and the requests.
fn ensured_elsewhere(rotate: bool) -> (String, Vec<Replaced>, Vec<String>) {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join(COLLECTOR.file);
    garrison_testing::write_private(&file, format!("{OLD}\n").as_bytes());
    let done = json(&json!({"methodResponses": [["x:ApiKey/set",
        {"created": {"new": {"id": "fresh", "secret": NEW}}, "updated": {"k": null}}, "0"]]}));
    let answers = vec![listed("b", &[]), session("c"), listed("c", &["k"]), done];
    let server = serve(answers);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer admin".to_owned(),
    };
    let networks = Enabled::of(["127.0.0.1/32"]);
    let done = ensure(&admin, directory.path(), &COLLECTOR, &networks, rotate).unwrap();
    let step = done
        .step
        .replace(&directory.path().display().to_string(), "DIR");
    (step, done.replaced, server.requests())
}

/// The keys setup makes are the administrator's, and another administrator
/// lists only its own account's: a run as a second administrator found none
/// of the first one's, made new keys and left those valid for good, after a
/// rotation too. The account the file's key belongs to is now asked as
/// well: its key is kept and updated there, and a rotation replaces it.
#[test]
fn the_keys_another_administrator_made_are_kept_or_replaced_in_its_account() {
    let (step, replaced, requests) = ensured_elsewhere(false);
    assert_eq!(
        step,
        "updated API key 'garrison collector' (secret unchanged)"
    );
    assert_eq!(replaced, Vec::new());
    assert!(
        requests[1].starts_with("GET /jmap/session "),
        "{}",
        requests[1]
    );
    assert!(requests[1].contains(&format!("Bearer {OLD}")));
    assert!(
        requests[2].contains(r#""accountId":"c""#),
        "{}",
        requests[2]
    );
    assert!(
        requests[3].contains(r#""accountId":"c""#) && requests[3].contains(r#""update":{"k""#),
        "{}",
        requests[3]
    );
    let (step, replaced, requests) = ensured_elsewhere(true);
    assert_eq!(
        step,
        "replaced API key 'garrison collector' -> DIR/collector-native-key"
    );
    let theirs = Replaced {
        account: Some("c".to_owned()),
        id: "k".to_owned(),
    };
    assert_eq!(replaced, vec![theirs]);
    // The new key is the administrator's own.
    assert!(!requests[3].contains("accountId"), "{}", requests[3]);
}

/// Each replaced key goes from the account that holds it.
#[test]
fn a_replaced_key_goes_from_its_account() {
    let gone =
        |id: &str| json(&json!({"methodResponses": [["x:ApiKey/set", {"destroyed": [id]}, "0"]]}));
    let server = serve(vec![gone("k"), gone("x")]);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer admin".to_owned(),
    };
    let replaced = [
        Replaced {
            account: Some("c".to_owned()),
            id: "k".to_owned(),
        },
        Replaced {
            account: None,
            id: "x".to_owned(),
        },
    ];
    remove(&admin, &replaced).unwrap();
    let requests = server.requests();
    assert!(
        requests[0].contains(r#""accountId":"c","destroy":["k"]"#),
        "{}",
        requests[0]
    );
    assert!(
        requests[1].contains(r#""destroy":["x"]"#) && !requests[1].contains("accountId"),
        "{}",
        requests[1]
    );
}
