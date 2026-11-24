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
    without: "the cards that need the collector's key cannot read Stalwart",
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

/// What `ensure` does for the collector's key with the file holding
/// `written`, while Stalwart has the keys `listed` of that description in
/// the administrator's own account, which the file's key belongs to: the
/// step, the keys it replaces, what the file holds after, and whether it
/// asked Stalwart for a new key.
fn ensured(written: &str, ids: &[&str]) -> (String, Vec<String>, String, bool) {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join(COLLECTOR.file);
    garrison_testing::write_private(&file, written.as_bytes());
    let set = json(&json!({"methodResponses": [["x:ApiKey/set",
        {"created": {"new": {"id": "fresh", "secret": NEW}}, "updated": {"old": null}}, "0"]]}));
    let mut answers = vec![listed("b", ids)];
    // The file's key is asked whose it is only where it holds one.
    if holds_key(&file) {
        answers.push(session("b"));
    }
    answers.push(set);
    let server = serve(answers);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer admin".to_owned(),
    };
    let networks = Enabled::of(["127.0.0.1/32"]);
    let done = ensure(&admin, directory.path(), &COLLECTOR, &networks, false).unwrap();
    let requests = server.requests();
    let step = done
        .step
        .replace(&directory.path().display().to_string(), "DIR");
    let held = std::fs::read_to_string(&file).unwrap();
    assert_eq!(done.made, requests.last().unwrap().contains("\"create\""));
    let replaced = done.replaced.iter().map(|key| key.id.clone()).collect();
    (step, replaced, held, done.made)
}

/// A key file that holds no key, as an empty one, gets a new key, as a
/// missing one does, and the key it replaces goes: kept, the collector
/// would have no key while setup said "secret unchanged". A file that
/// holds a key keeps it.
#[test]
fn a_key_file_that_holds_no_key_gets_a_new_one() {
    for written in ["", "\n", " \r\n", "short\n"] {
        assert_eq!(
            ensured(written, &["old"]),
            (
                "created API key 'garrison collector' -> DIR/collector-native-key".to_owned(),
                vec!["old".to_owned()],
                format!("{NEW}\n"),
                true
            ),
            "{written:?}"
        );
    }
    assert_eq!(
        ensured(&format!("{OLD}\n"), &["old"]),
        (
            "updated API key 'garrison collector' (secret unchanged)".to_owned(),
            Vec::new(),
            format!("{OLD}\n"),
            false
        )
    );
}

/// A key whose file other users may read may have been seen: it gets a new
/// key, written for this user alone, and the old one goes, where setup once
/// kept it and said "secret unchanged". So the cards that name setup as
/// the fix for such a file are right.
#[test]
fn a_key_file_others_may_read_gets_a_new_key() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join(COLLECTOR.file);
    garrison_testing::write_private(&file, format!("{OLD}\n").as_bytes());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let set = json(&json!({"methodResponses": [["x:ApiKey/set",
        {"created": {"new": {"id": "fresh", "secret": NEW}}, "updated": {"old": null}}, "0"]]}));
    let server = serve(vec![listed("b", &["old"]), set]);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer admin".to_owned(),
    };
    let networks = Enabled::of(["127.0.0.1/32"]);
    let done = ensure(&admin, directory.path(), &COLLECTOR, &networks, false).unwrap();
    server.requests();
    let step = done
        .step
        .replace(&directory.path().display().to_string(), "DIR");
    let replaced: Vec<String> = done.replaced.iter().map(|key| key.id.clone()).collect();
    assert_eq!(
        (step.as_str(), replaced, done.made),
        (
            "created API key 'garrison collector' -> DIR/collector-native-key",
            vec!["old".to_owned()],
            true
        )
    );
    let written = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        (std::fs::read_to_string(&file).unwrap(), written),
        (format!("{NEW}\n"), 0o600)
    );
}

/// Where Stalwart has two keys of the description, as after a rotation
/// that was stopped before it removed the old one, no run can tell which
/// the file holds: a plain run makes one anew and replaces both, where
/// it once updated the first and kept the other for good.
#[test]
fn two_keys_of_one_description_are_replaced_by_one() {
    assert_eq!(
        ensured(&format!("{OLD}\n"), &["old", "older"]),
        (
            "replaced the 2 API keys 'garrison collector' with one -> \
             DIR/collector-native-key"
                .to_owned(),
            vec!["old".to_owned(), "older".to_owned()],
            format!("{NEW}\n"),
            true
        )
    );
}

/// Stalwart holds at most five keys for an account. Where a new key finds
/// no room beside the old ones, these go first and the new one is made
/// then, so that a rotation stopped after it made its keys does not
/// leave every later run refused.
#[test]
fn a_full_quota_lets_the_old_keys_go_first() {
    let directory = tempfile::tempdir().unwrap();
    let listed = listed("b", &["old", "older"]);
    let full = json(
        &json!({"methodResponses": [["x:ApiKey/set", {"notCreated": {"new": {
        "type": "overQuota", "description": "You have exceeded your quota of 5 API keys."}}},
        "0"]]}),
    );
    let gone =
        |id: &str| json(&json!({"methodResponses": [["x:ApiKey/set", {"destroyed": [id]}, "0"]]}));
    let made = json(&json!({"methodResponses": [["x:ApiKey/set",
        {"created": {"new": {"id": "fresh", "secret": NEW}}}, "0"]]}));
    let server = serve(vec![listed, full, gone("old"), gone("older"), made]);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer admin".to_owned(),
    };
    let networks = Enabled::of(["127.0.0.1/32"]);
    let done = ensure(&admin, directory.path(), &COLLECTOR, &networks, true).unwrap();
    let requests = server.requests();
    assert!(requests[2].contains(r#""destroy":["old"]"#));
    assert!(requests[3].contains(r#""destroy":["older"]"#));
    assert_eq!(
        done.step
            .replace(&directory.path().display().to_string(), "DIR"),
        "replaced API key 'garrison collector' -> DIR/collector-native-key (the old ones \
         went first: Stalwart's quota of API keys left no room)"
    );
    assert_eq!(
        (done.replaced, done.made, done.gone_first),
        (Vec::<Replaced>::new(), true, true)
    );
    let held = std::fs::read_to_string(directory.path().join(COLLECTOR.file)).unwrap();
    assert_eq!(held, format!("{NEW}\n"));
}

/// Where the old keys went for the quota and the new one cannot be made,
/// or where their removal failed, the error says what goes without a key
/// Stalwart takes until a run of setup makes one.
#[test]
fn a_new_key_that_finds_no_room_says_what_goes_without_one() {
    let full = json(
        &json!({"methodResponses": [["x:ApiKey/set", {"notCreated": {"new": {
        "type": "overQuota", "description": "You have exceeded your quota of 5 API keys."}}},
        "0"]]}),
    );
    let gone = json(&json!({"methodResponses": [["x:ApiKey/set", {"destroyed": ["old"]}, "0"]]}));
    let quota = "Stalwart's quota of API keys left the new key no room";
    let without =
        "the cards that need the collector's key cannot read Stalwart until setup makes its key";
    let cases = [
        (
            vec![listed("b", &["old"]), full.clone(), gone, answer(503, "{}")],
            format!(
                "x:ApiKey/set: Stalwart answered HTTP 503 (Stalwart did not return the new API \
                 key secret); {quota}, so the old ones went first: {without}"
            ),
        ),
        (
            vec![listed("b", &["old"]), full, answer(503, "{}")],
            format!(
                "x:ApiKey/set: Stalwart answered HTTP 503; {quota}, so setup was removing the \
                 old ones first: where they are gone, {without}"
            ),
        ),
    ];
    for (answers, said) in cases {
        let directory = tempfile::tempdir().unwrap();
        let server = serve(answers);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let networks = Enabled::of(["127.0.0.1/32"]);
        let error = ensure(&admin, directory.path(), &COLLECTOR, &networks, true)
            .err()
            .unwrap();
        server.requests();
        assert_eq!(error, said);
    }
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
    let listed = listed("b", &[]);
    let made = json(&json!({"methodResponses": [["x:ApiKey/set",
        {"created": {"new": {"id": "fresh", "secret": NEW}}}, "0"]]}));
    let gone = json(&json!({"methodResponses": [["x:ApiKey/set",
        {"destroyed": ["fresh"]}, "0"]]}));
    let server = serve(vec![listed, made, gone]);
    let admin = Admin {
        url: format!("{}/jmap/", server.url),
        authorization: "Bearer admin".to_owned(),
    };
    let networks = Enabled::of(["127.0.0.1/32"]);
    let error = ensure(&admin, &folder, &COLLECTOR, &networks, false)
        .err()
        .unwrap();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
    let requests = server.requests();
    let target = folder.join(COLLECTOR.file);
    assert!(
        error.starts_with(&format!("Could not write {}: ", target.display()))
            && error.ends_with("; the new API key was taken out of Stalwart again"),
        "{error}"
    );
    assert!(
        requests[2].contains(r#""destroy":["fresh"]"#),
        "{}",
        requests[2]
    );
}

/// What `verify` makes of Stalwart's answer to the collector's key.
fn tried(status: u16) -> Result<Vec<&'static str>, String> {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join(COLLECTOR.file);
    garrison_testing::write_private(&file, format!("{OLD}\n").as_bytes());
    let server = serve(vec![answer(status, "{}")]);
    let config = garrison_testing::config(directory.path(), &server.url);
    let tried = verify(&config, directory.path(), &[&COLLECTOR]);
    let requests = server.requests();
    assert!(requests[0].contains(&format!("Bearer {OLD}")));
    tried.map(|unknown| unknown.iter().map(|key| key.file).collect())
}

/// Stalwart answers a key it does not know 401 and one it knows from an
/// address the key does not allow 403 (measured): the first is a key to
/// make anew, the second a bridge network.
#[test]
fn a_key_stalwart_does_not_know_is_told_from_one_it_refuses_here() {
    assert_eq!(tried(200), Ok(Vec::new()));
    assert_eq!(tried(401), Ok(vec!["collector-native-key"]));
    let bridge = tried(403).unwrap_err();
    assert!(
        bridge.starts_with(
            "Stalwart refuses the API key in collector-native-key from this host (HTTP \
             403): it sees this host at an address the key does not allow."
        ),
        "{bridge}"
    );
    assert_eq!(
        tried(404),
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
    assert!(network("172.17.0.1/16").is_err());
    assert!(network("nonsense").is_err());
}
