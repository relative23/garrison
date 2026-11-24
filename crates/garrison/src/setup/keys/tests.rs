use std::cell::RefCell;
use std::os::unix::fs::PermissionsExt;

use garrison_testing::http::{answer, json, serve};
use serde_json::json;

use super::*;

pub(super) const OLD: &str = "the-key-stalwart-has-0123456789";
pub(super) const NEW: &str = "the-key-stalwart-made-0123456789";
pub(super) const COLLECTOR: Key = Key {
    file: "collector-native-key",
    description: "garrison collector",
    permissions: &["authenticate"],
    held: false,
};

/// Stalwart's list of an account's keys of the collector's description.
pub(super) fn listed(account: &str, ids: &[&str]) -> String {
    let list: Vec<_> = ids
        .iter()
        .map(|id| json!({"id": id, "description": "garrison collector"}))
        .collect();
    json(&json!({"methodResponses": [["x:ApiKey/get",
        {"accountId": account, "list": list}, "0"]]}))
}

/// The session a key opens, which names the account it belongs to.
pub(super) fn session(account: &str) -> String {
    json(&json!({"username": "admin@example.test",
        "primaryAccounts": {"urn:stalwart:jmap": account}}))
}

/// Stalwart's answer to a new key.
pub(super) fn made() -> String {
    json(&json!({"methodResponses": [["x:ApiKey/set",
        {"created": {"new": {"id": "fresh", "secret": NEW}}}, "0"]]}))
}

/// Stalwart's answer to a change of a key or its removal.
pub(super) fn done(method: &str) -> String {
    json(&json!({"methodResponses": [[method, {"updated": null, "destroyed": null}, "0"]]}))
}

/// The collector's key file in the credentials folder of the test
/// configuration in `directory`.
pub(super) fn key_file(directory: &Path) -> std::path::PathBuf {
    directory.join("credentials").join(COLLECTOR.file)
}

/// What one key's run does with the collector's file holding `written` at
/// `mode`, while Stalwart answers `answers`: the error, if any, and the
/// requests. The key's service takes up a new key as `take_up` says.
pub(super) fn settled(
    directory: &Path,
    (written, mode): (&str, u32),
    answers: Vec<String>,
    rotate: bool,
    take_up: &dyn Fn(&Key) -> Result<(), String>,
) -> (Result<bool, String>, Vec<String>) {
    let file = key_file(directory);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    garrison_testing::write_private(&file, written.as_bytes());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
    let server = serve(answers);
    let config = garrison_testing::config(directory, &server.url);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer admin".to_owned(),
    };
    let networks = Enabled::of(["127.0.0.1/32"]);
    let credentials = &config.credentials_directory;
    let outcome = find(&admin, credentials, &[&COLLECTOR], rotate).and_then(|found| {
        let found = found.into_iter().next().unwrap();
        settle(&admin, &config, &COLLECTOR, found, &networks, take_up)
    });
    (outcome, server.requests())
}

/// A service that takes up its new key.
pub(super) const TAKEN: fn(&Key) -> Result<(), String> = |_| Ok(());

/// Requests in short: the method and what it does, or the request line.
fn named(requests: &[String]) -> Vec<String> {
    requests
        .iter()
        .map(|request| {
            let (head, body) = request.split_once("\r\n\r\n").unwrap();
            let Ok(call) = serde_json::from_str::<serde_json::Value>(body) else {
                return head
                    .lines()
                    .next()
                    .unwrap()
                    .split(' ')
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ");
            };
            let call = &call["methodCalls"][0];
            let what = ["create", "update", "destroy"]
                .into_iter()
                .find(|what| call[1].get(*what).is_some());
            format!("{} {}", call[0].as_str().unwrap(), what.unwrap_or(""))
                .trim_end()
                .to_owned()
        })
        .collect()
}

/// A key file that holds no key, as an empty one, gets a new key, as a
/// missing one does, and the key it replaces goes once the new one is
/// tried. A file that holds a key keeps it.
#[test]
fn a_key_file_that_holds_no_key_gets_a_new_one() {
    for written in ["", "\n", " \r\n", "short\n"] {
        let directory = tempfile::tempdir().unwrap();
        let answers = vec![
            listed("b", &["old"]),
            made(),
            answer(200, "{}"),
            done("x:ApiKey/set"),
        ];
        let (outcome, requests) =
            settled(directory.path(), (written, 0o600), answers, false, &TAKEN);
        assert_eq!(outcome, Ok(true), "{written:?}");
        assert_eq!(
            named(&requests),
            [
                "x:ApiKey/get",
                "x:ApiKey/set create",
                "GET /jmap/session",
                "x:ApiKey/set destroy"
            ],
            "{written:?}"
        );
        assert!(
            requests[2].contains(&format!("Bearer {NEW}")),
            "{written:?}"
        );
        assert!(requests[3].contains(r#""destroy":["old"]"#), "{written:?}");
        let held = std::fs::read_to_string(key_file(directory.path())).unwrap();
        assert_eq!(held, format!("{NEW}\n"), "{written:?}");
    }
    let directory = tempfile::tempdir().unwrap();
    let answers = vec![
        listed("b", &["old"]),
        session("b"),
        done("x:ApiKey/set"),
        answer(200, "{}"),
    ];
    let written = format!("{OLD}\n");
    let (outcome, requests) = settled(directory.path(), (&written, 0o600), answers, false, &TAKEN);
    assert_eq!(outcome, Ok(true));
    assert_eq!(
        named(&requests),
        [
            "x:ApiKey/get",
            "GET /jmap/session",
            "x:ApiKey/set update",
            "GET /jmap/session"
        ]
    );
}

/// A kept key whose rights Stalwart shows as setup gives them is left as it
/// is, and only tried: its networks as setup wrote them or as Stalwart
/// 1.1.0 and 1.2.0 show them, a single address without its prefix. One with
/// other rights is updated.
#[test]
fn a_kept_key_with_its_rights_is_left_as_it_is() {
    let directory = tempfile::tempdir().unwrap();
    for (shown, rights, changed) in [
        ("127.0.0.1", json!({"authenticate": true}), false),
        ("127.0.0.1/32", json!({"authenticate": true}), false),
        (
            "127.0.0.1",
            json!({"authenticate": true, "sysAccountGet": true}),
            true,
        ),
    ] {
        let held = json(
            &json!({"methodResponses": [["x:ApiKey/get", {"accountId": "b",
            "list": [{"id": "old", "description": "garrison collector", "secret": "****",
            "permissions": {"@type": "Replace", "permissions": rights},
            "allowedIps": {shown: true}}]}, "0"]]}),
        );
        let mut answers = vec![held, session("b")];
        if changed {
            answers.push(done("x:ApiKey/set"));
        }
        answers.push(answer(200, "{}"));
        let written = format!("{OLD}\n");
        let (outcome, requests) =
            settled(directory.path(), (&written, 0o600), answers, false, &TAKEN);
        assert_eq!(outcome, Ok(changed), "{shown}");
        let update = changed.then_some("x:ApiKey/set update");
        let asked: Vec<&str> = ["x:ApiKey/get", "GET /jmap/session"]
            .into_iter()
            .chain(update)
            .chain(["GET /jmap/session"])
            .collect();
        assert_eq!(named(&requests), asked, "{shown}");
    }
}

/// A key whose file other users may read may have been seen: it gets a new
/// key, written for this user alone, and the old one goes, so that the
/// cards that name setup as the fix for such a file are right.
#[test]
fn a_key_file_others_may_read_gets_a_new_key() {
    let directory = tempfile::tempdir().unwrap();
    let answers = vec![
        listed("b", &["old"]),
        session("b"),
        made(),
        answer(200, "{}"),
        done("x:ApiKey/set"),
    ];
    let written = format!("{OLD}\n");
    let (outcome, requests) = settled(directory.path(), (&written, 0o644), answers, false, &TAKEN);
    assert_eq!(outcome, Ok(true));
    assert!(
        requests[4].contains(r#""destroy":["old"]"#),
        "{}",
        requests[4]
    );
    let file = key_file(directory.path());
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        (std::fs::read_to_string(&file).unwrap(), mode),
        (format!("{NEW}\n"), 0o600)
    );
}

/// Where Stalwart has two keys of the description, as after a run that
/// stopped before the old one went, no run can tell which the file holds: a
/// plain run makes one anew and replaces both.
#[test]
fn two_keys_of_one_description_are_replaced_by_one() {
    let directory = tempfile::tempdir().unwrap();
    let answers = vec![
        listed("b", &["old", "older"]),
        session("b"),
        made(),
        answer(200, "{}"),
        done("x:ApiKey/set"),
        done("x:ApiKey/set"),
    ];
    let written = format!("{OLD}\n");
    let (outcome, requests) = settled(directory.path(), (&written, 0o600), answers, false, &TAKEN);
    assert_eq!(outcome, Ok(true));
    assert!(requests[4].contains(r#""destroy":["old"]"#));
    assert!(requests[5].contains(r#""destroy":["older"]"#));
}

/// The service that holds a key takes up the new one before the keys it
/// replaces go: where it cannot, they stay, and the run says why, so that
/// it never holds a key Stalwart no longer takes.
#[test]
fn a_new_key_is_taken_up_before_the_old_one_goes() {
    let directory = tempfile::tempdir().unwrap();
    let taken = RefCell::new(Vec::new());
    let take_up = |key: &Key| {
        let file = directory.path().join("credentials").join(key.file);
        taken
            .borrow_mut()
            .push(std::fs::read_to_string(file).unwrap());
        Ok(())
    };
    let answers = vec![
        listed("b", &["old"]),
        session("b"),
        made(),
        answer(200, "{}"),
        answer(503, "{}"),
    ];
    let written = format!("{OLD}\n");
    let (outcome, requests) = settled(directory.path(), (&written, 0o600), answers, true, &take_up);
    // The removal failed, after the service took up the new key.
    assert_eq!(*taken.borrow(), [format!("{NEW}\n")]);
    assert_eq!(
        outcome,
        Err(
            "x:ApiKey/set: Stalwart answered HTTP 503; the API key 'garrison collector' that the \
             new one replaced stays"
                .to_owned()
        )
    );
    assert_eq!(requests.len(), 5);
    let refused =
        |_: &Key| Err("Restart garrison-collector so it reads the new secret.".to_owned());
    let answers = vec![
        listed("b", &["old"]),
        session("b"),
        made(),
        answer(200, "{}"),
    ];
    let (outcome, requests) = settled(directory.path(), (&written, 0o600), answers, true, &refused);
    assert_eq!(
        outcome,
        Err("Restart garrison-collector so it reads the new secret.".to_owned())
    );
    // No removal was asked for.
    assert_eq!(requests.len(), 4);
}

/// Stalwart 1.1.0 and 1.2.0 hold at most five keys for an account. Where a
/// new key finds no room, nothing of that key changes, none goes first, and
/// setup names the keys of the account, of which one is to be removed.
#[test]
fn a_full_quota_changes_nothing_and_names_the_keys() {
    let directory = tempfile::tempdir().unwrap();
    let own = json(
        &json!({"methodResponses": [["x:ApiKey/get", {"accountId": "b", "list": [
        {"id": "old", "description": "garrison collector"},
        {"id": "o1", "description": "backup"},
        {"id": "o2", "description": null}]}, "0"]]}),
    );
    let full = json(
        &json!({"methodResponses": [["x:ApiKey/set", {"notCreated": {"new": {
        "type": "overQuota", "description": "You have exceeded your quota of 5 API keys."}}},
        "0"]]}),
    );
    let written = format!("{OLD}\n");
    let answers = vec![own, session("b"), full];
    let (outcome, requests) = settled(directory.path(), (&written, 0o600), answers, true, &TAKEN);
    assert_eq!(
        outcome,
        Err(
            "Stalwart takes no more API keys in the administrator's account, which holds \
             'garrison collector', 'backup', one without a description (o2): setup makes a new \
             key before it removes the one it replaces. Remove a key the account no longer needs \
             in the Stalwart WebUI; setup made no new key 'garrison collector' and removed none"
                .to_owned()
        )
    );
    assert_eq!(requests.len(), 3);
    let held = std::fs::read_to_string(key_file(directory.path())).unwrap();
    assert_eq!(held, written);
}

/// A key whose file cannot be written goes again, so that Stalwart keeps
/// no key whose secret nobody holds, and the error names the file.
#[test]
fn a_new_key_whose_file_cannot_be_written_goes_again() {
    if rustix::process::geteuid().is_root() {
        return; // Root writes any folder.
    }
    let directory = tempfile::tempdir().unwrap();
    let folder = directory.path().join("credentials");
    std::fs::create_dir(&folder).unwrap();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o500)).unwrap();
    let gone = json(&json!({"methodResponses": [["x:ApiKey/set",
        {"destroyed": ["fresh"]}, "0"]]}));
    let server = serve(vec![made(), gone]);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer admin".to_owned(),
    };
    let target = folder.join(COLLECTOR.file);
    let networks = Enabled::of(["127.0.0.1/32"]);
    let rights = KeyRights {
        permissions: KeyPermissions::Replace {
            permissions: Enabled::of(["authenticate"]),
        },
        allowed_ips: &networks,
    };
    let error = make(&admin, &target, COLLECTOR.description, rights).unwrap_err();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
    let requests = server.requests();
    assert!(
        error.starts_with(&format!("Could not write {}: ", target.display()))
            && error.ends_with("; the new API key was taken out of Stalwart again"),
        "{error}"
    );
    assert!(
        requests[1].contains(r#""destroy":["fresh"]"#),
        "{}",
        requests[1]
    );
}

/// What a try of the collector's key makes of Stalwart's answer `status`.
fn tried_with(status: u16) -> Result<(), String> {
    let directory = tempfile::tempdir().unwrap();
    let file = key_file(directory.path());
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    garrison_testing::write_private(&file, format!("{OLD}\n").as_bytes());
    let server = serve(vec![answer(status, "{}")]);
    let config = garrison_testing::config(directory.path(), &server.url);
    let outcome = tried(&config, &COLLECTOR);
    let requests = server.requests();
    assert!(requests[0].contains(&format!("Bearer {OLD}")));
    outcome
}

/// Stalwart answers a key it does not know 401 and one it knows from an
/// address the key does not allow 403 (measured): the second is a bridge
/// network.
#[test]
fn a_key_stalwart_does_not_take_is_told_from_one_it_refuses_here() {
    assert_eq!(tried_with(200), Ok(()));
    assert_eq!(
        tried_with(401),
        Err("Stalwart does not take the API key in collector-native-key (HTTP 401)".to_owned())
    );
    let bridge = tried_with(403).unwrap_err();
    assert!(
        bridge.starts_with(
            "Stalwart refuses the API key in collector-native-key from this host (HTTP \
             403): it sees this host at an address the key does not allow."
        ),
        "{bridge}"
    );
    assert_eq!(
        tried_with(404),
        Err(
            "Trying collector-native-key: Stalwart answered HTTP 404 for its JMAP session"
                .to_owned()
        )
    );
}

/// A user without administrator rights may read the keys, its own, but
/// not make Garrison's: setup says to run it as an administrator.
#[test]
fn an_account_that_may_not_grant_the_permissions_is_told_so() {
    let refusal = r#"x:ApiKey/set: {"new":{"description":"You are not authorized to grant permissions: sysRoleGet","type":"forbidden"}}"#;
    assert!(refused(refusal, "garrison broker").starts_with(
        "Stalwart refused the administrator the API key 'garrison broker', since it may \
             not grant the key's permissions: run setup as an administrator who holds them"
    ));
    assert_eq!(
        refused("x:ApiKey/set: Stalwart is unavailable", "garrison broker"),
        "x:ApiKey/set: Stalwart is unavailable (Stalwart did not return the new API key secret)"
    );
}

#[test]
fn networks_are_written_in_canonical_form() {
    assert_eq!(network("172.17.0.0/16").unwrap(), "172.17.0.0/16");
    assert_eq!(network("10.1.2.3").unwrap(), "10.1.2.3/32");
    assert_eq!(network("fd00::/8").unwrap(), "fd00::/8");
    assert_eq!(
        network("172.17.0.1/16"),
        Err(states::network_host_bits("172.17.0.1/16"))
    );
    for invalid in ["nonsense", "10.1.2.3/x"] {
        assert_eq!(network(invalid), Err(states::network_invalid(invalid)));
    }
}
