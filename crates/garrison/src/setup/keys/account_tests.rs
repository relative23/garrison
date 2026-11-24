//! Where a file's key is another administrator's: its keys of the
//! description are found in its account, kept or replaced there, and
//! removed from it, also where others may read the file.

use garrison_testing::http::{answer, json, serve};
use serde_json::json;

use super::tests::{NEW, OLD, TAKEN, done, listed, made, session, settled};
use super::*;

/// Where Stalwart's answer to the session of the file's key names no
/// account, as for its rate limit or an outage, the key may be another
/// administrator's: the run stops before it changes anything, which would
/// leave that one valid for good.
#[test]
fn a_key_whose_account_is_not_known_stops_the_run_before_anything_changes() {
    let limited = "Stalwart refused the request for its limit of requests (HTTP 429), whose window \
                   is a minute unless it was set otherwise";
    for (status, said) in [
        (429, limited.to_owned()),
        (503, "Stalwart answered HTTP 503".to_owned()),
        (404, "Stalwart answered HTTP 404".to_owned()),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let answers = vec![listed("b", &[]), answer(status, "{}")];
        let written = format!("{OLD}\n");
        let (outcome, requests) =
            settled(directory.path(), (&written, 0o600), answers, false, &TAKEN);
        let path = directory.path().join("credentials/collector-native-key");
        assert_eq!(
            outcome,
            Err(format!(
                "Asking Stalwart whose API key {} holds: {said}",
                path.display()
            ))
        );
        assert_eq!(requests.len(), 2, "{status}");
    }
}

/// A key Stalwart does not know (401) belongs to no account, and one it
/// refuses from this host's address (403) names none: the run goes on with
/// the administrator's own keys, and the new key's try says what is wrong
/// where Stalwart refuses it too.
#[test]
fn a_key_stalwart_does_not_know_or_refuses_here_names_no_account() {
    for status in [401, 403] {
        let directory = tempfile::tempdir().unwrap();
        let answers = vec![
            listed("b", &[]),
            answer(status, "{}"),
            made(),
            answer(200, "{}"),
        ];
        let written = format!("{OLD}\n");
        let (outcome, requests) =
            settled(directory.path(), (&written, 0o600), answers, false, &TAKEN);
        assert_eq!(outcome, Ok(true), "{status}");
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
    let directory = tempfile::tempdir().unwrap();
    let answers = vec![listed("b", &[]), session("c"), missing];
    let written = format!("{OLD}\n");
    let (outcome, requests) = settled(directory.path(), (&written, 0o600), answers, false, &TAKEN);
    let path = directory.path().join("credentials/collector-native-key");
    assert_eq!(
        outcome,
        Err(format!(
            "Stalwart does not show the administrator the account that the API key in {} \
             belongs to: run setup as an administrator who holds the keys' permissions, as one \
             with Stalwart's administrator role (x:ApiKey/get: accountNotFound The accountId \
             does not correspond to a valid account)",
            path.display()
        ))
    );
    assert!(
        requests[2].contains(r#""accountId":"c""#),
        "{}",
        requests[2]
    );
}

/// The keys setup makes are the administrator's, and another administrator
/// lists only its own account's. The account the file's key belongs to is
/// asked as well: its key is kept and updated there, and a rotation, or a
/// file that others may read, replaces it with one in the administrator's
/// own account and removes it from the other one.
#[test]
fn the_keys_another_administrator_made_are_kept_or_replaced_in_its_account() {
    let directory = tempfile::tempdir().unwrap();
    let kept = vec![
        listed("b", &[]),
        session("c"),
        listed("c", &["k"]),
        done("x:ApiKey/set"),
        answer(200, "{}"),
    ];
    let written = format!("{OLD}\n");
    let (outcome, requests) = settled(directory.path(), (&written, 0o600), kept, false, &TAKEN);
    assert_eq!(outcome, Ok(true));
    assert!(
        requests[1].starts_with("GET /jmap/session "),
        "{}",
        requests[1]
    );
    assert!(requests[1].contains(&format!("Bearer {OLD}")));
    assert!(
        requests[3].contains(r#""accountId":"c""#) && requests[3].contains(r#""update":{"k""#),
        "{}",
        requests[3]
    );
    for (mode, rotate) in [(0o600, true), (0o644, false), (0o640, false)] {
        let directory = tempfile::tempdir().unwrap();
        let replaced = vec![
            listed("b", &[]),
            session("c"),
            listed("c", &["k"]),
            made(),
            answer(200, "{}"),
            done("x:ApiKey/set"),
        ];
        let (outcome, requests) =
            settled(directory.path(), (&written, mode), replaced, rotate, &TAKEN);
        assert_eq!(outcome, Ok(true), "{mode:o}");
        // The new key is the administrator's own; the old one goes from
        // the account that holds it.
        assert!(!requests[3].contains("accountId"), "{}", requests[3]);
        assert!(requests[4].contains(&format!("Bearer {NEW}")));
        assert!(
            requests[5].contains(r#""accountId":"c","destroy":["k"]"#),
            "{mode:o}: {}",
            requests[5]
        );
    }
}

/// A file's key is asked whose it is only where the file holds one.
#[test]
fn a_file_that_holds_no_key_is_not_asked_whose_it_is() {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(vec![listed("b", &[])]);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer admin".to_owned(),
    };
    let found = find(&admin, directory.path(), &[&tests::COLLECTOR], false).unwrap();
    server.requests();
    assert_eq!(found.len(), 1);
    assert_eq!((&found[0].existing, &found[0].keep), (&Vec::new(), &None));
}

/// A key that a run moved out of another administrator's account and could
/// not remove there is found while another file's key names that account:
/// each account the files' keys name is listed once, for every description.
#[test]
fn a_key_left_in_an_account_another_file_names_is_found() {
    const BROKER: Key = Key {
        file: "broker-native-key",
        description: "garrison broker",
        permissions: &["authenticate"],
        held: false,
    };
    let directory = tempfile::tempdir().unwrap();
    for name in [BROKER.file, tests::COLLECTOR.file] {
        garrison_testing::write_private(
            &directory.path().join(name),
            format!("{OLD}\n").as_bytes(),
        );
    }
    let keys = |account: &str, keys: &[(&str, &str)]| {
        let list: Vec<_> = keys
            .iter()
            .map(|(id, description)| json!({"id": id, "description": description}))
            .collect();
        json(&json!({"methodResponses": [["x:ApiKey/get",
            {"accountId": account, "list": list}, "0"]]}))
    };
    let answers = vec![
        keys("b", &[("new", "garrison broker")]),
        session("b"),
        session("c"),
        keys(
            "c",
            &[("k", "garrison collector"), ("left", "garrison broker")],
        ),
    ];
    let server = serve(answers);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer admin".to_owned(),
    };
    let found = find(
        &admin,
        directory.path(),
        &[&BROKER, &tests::COLLECTOR],
        false,
    )
    .unwrap();
    server.requests();
    let at = |account: Option<&str>, id: &str| AccountKey {
        account: account.map(str::to_owned),
        id: id.to_owned(),
    };
    assert_eq!(found[0].existing, [at(None, "new"), at(Some("c"), "left")]);
    assert_eq!(found[0].keep, None);
    assert_eq!(found[1].existing, [at(Some("c"), "k")]);
    assert!(found[1].keep.is_some());
}
