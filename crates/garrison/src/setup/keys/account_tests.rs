//! Where a file's key is another administrator's: its keys of the
//! description are found in its account, kept or replaced there, and
//! removed from it.

use garrison_testing::http::{json, serve};
use serde_json::json;

use super::tests::{COLLECTOR, NEW, OLD, listed, session};
use super::*;

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
