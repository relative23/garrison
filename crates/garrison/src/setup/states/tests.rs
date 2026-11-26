//! Setup's states, each with its whole line: the one place in setup's tests
//! where their words stand.

use std::path::Path;

use garrison_core::files::ProtectedFileError;

use super::*;
use crate::state::State;

type Rows = Vec<State>;

/// What setup refuses before it asks Stalwart anything.
fn before() -> Rows {
    let folder = Path::new("/etc/garrison/credentials");
    let denied = "Permission denied (os error 13)";
    let missing = ProtectedFileError::Unavailable("/root/admin.json".into());
    vec![
        no_administrator(),
        again(file_unread(missing), "garrison stalwart setup"),
        input_unread("Input/output error (os error 5)"),
        administrator_too_long(),
        administrator_not_json("invalid JSON: expected value at line 1 column 1"),
        administrator_unusable(),
        ask_failed(
            "/usr/bin/systemd-ask-password",
            "No such file or directory (os error 2)",
        ),
        no_secret(),
        not_root(folder, denied),
        folder_unwritable(
            folder,
            "Read-only file system (os error 30)",
            "garrison setup",
        ),
        network_invalid("nonsense"),
        network_host_bits("172.17.0.1/16"),
    ]
}

/// How Stalwart answered, where it did not do what setup asked.
fn answers() -> Rows {
    let refusal = r#"{"new":{"type":"invalidProperties","properties":["url"]}}"#;
    vec![
        call_failed("x:ApiKey/get", "Stalwart is unavailable"),
        limited("x:ApiKey/get"),
        again(administrator_refused(), "garrison stalwart setup"),
        administrator_refused_here(),
        unreadable("x:WebHook/get", "malformed answer"),
        stalwart_error("x:MtaMilter/get", "forbidden", "Forbidden"),
        again(
            until(stalwart_refused("x:WebHook/set", refusal), true, false),
            "garrison stalwart setup --rotate",
        ),
        event_forbidden("smtp.raw-input"),
    ]
}

/// What setup's files and keys meet.
fn keys() -> Rows {
    let file = Path::new("/etc/garrison/credentials/broker-native-key");
    let forbidden = stalwart_refused(
        "x:ApiKey/set",
        r#"{"new":{"description":"You are not authorized to grant permissions: sysRoleGet","type":"forbidden"}}"#,
    );
    let missing = stalwart_error(
        "x:ApiKey/get",
        "accountNotFound",
        "The accountId does not correspond to a valid account",
    );
    vec![
        taken_out(unwritten(file, "Permission denied (os error 13)")),
        no_random("getrandom: this target is not supported"),
        owner_unknown(file, LIMITED),
        account_unseen(file, &missing),
        webhooks_unreadable(&stalwart_error("x:WebHook/get", "forbidden", "Forbidden")),
        account_full("'garrison broker', 'backup'", "garrison broker"),
        key_not_granted("garrison broker", &forbidden),
        secret_missing(),
        key_untried("broker-native-key", "The endpoint did not answer"),
        key_untaken("broker-native-key"),
        again(
            key_refused_here("broker-native-key"),
            "garrison stalwart setup --rotate",
        ),
        old_key_kept(&restart_asked("garrison-broker", true)),
    ]
}

/// What a run says it did, or left, of the services and the secrets.
fn outcomes() -> Rows {
    vec![
        as_asked(),
        reloaded(Some(&restarted("garrison-ingest", true))),
        restart_asked("garrison-ingest and garrison-broker", false),
        read_at_start("garrison-broker", true),
        restarted("garrison-ingest", true),
        signature_pending(),
        scrape_pending(),
    ]
}

/// Lines the table's states say for other data, and with the clauses that
/// keep a state's name: their words are the table's too.
fn others() -> Vec<(State, &'static str)> {
    let file = Path::new("/etc/garrison/credentials/broker-native-key");
    let unavailable = || call_failed("x:ApiKey/set", "Stalwart answered HTTP 503");
    let reload = call_failed("x:Action/set", "Stalwart answered HTTP 503");
    vec![
        (reloaded(None), "Settings reloaded. [setup-reloaded]"),
        (
            left_in(unwritten(file, "Permission denied (os error 13)")),
            "Could not write /etc/garrison/credentials/broker-native-key: Permission denied (os \
             error 13); the new API key stays in Stalwart without its secret, and the next run \
             replaces it [setup-unwritten]",
        ),
        (
            unreturned(unavailable()),
            "x:ApiKey/set: Stalwart answered HTTP 503 (Stalwart did not return the new API key \
             secret) [setup-call-failed]",
        ),
        (
            replaced_stays(unavailable(), "garrison broker"),
            "x:ApiKey/set: Stalwart answered HTTP 503; the API key 'garrison broker' that the new \
             one replaced stays [setup-call-failed]",
        ),
        (
            again(until(reload, true, true), "garrison stalwart setup"),
            "x:Action/set: Stalwart answered HTTP 503; the receiver may refuse Stalwart's batches \
             until setup runs again, and Stalwart sends them again for an hour \
             [setup-signature-pending]; the exporter may refuse the collector's scrape until setup \
             runs again [setup-scrape-pending]. Run `garrison stalwart setup` again once this is \
             mended. [setup-call-failed]",
        ),
        (
            restart_asked("garrison-broker", true),
            "Restart garrison-broker so it reads the new secret. [setup-restart-asked]",
        ),
        (
            read_at_start("garrison-ingest and garrison-broker", false),
            "The services read the new secrets when they start. [setup-read-at-start]",
        ),
        (
            restarted("garrison-ingest and garrison-broker", false),
            "garrison-ingest and garrison-broker restarted with the new secrets. [setup-restarted]",
        ),
    ]
}

#[test]
fn every_state_of_setup_says_its_line() {
    let rows = [before(), answers(), keys(), outcomes()].concat();
    let sources = [include_str!("../states.rs"), include_str!("keys.rs")];
    crate::state::table(&sources, &rows);
    for (state, line) in others() {
        assert_eq!(state.to_string(), line, "{}", state.name);
    }
}

/// A failure keeps its name with the clauses that say what mends it and
/// what it leaves; the table holds the words they add.
#[test]
fn a_failure_keeps_its_name_with_what_it_leaves() {
    let refused = administrator_unusable;
    for said in [
        again(refused(), "garrison setup"),
        until(refused(), true, false),
        unreturned(refused()),
        taken_out(refused()),
        left_in(refused()),
        replaced_stays(refused(), "garrison broker"),
    ] {
        assert_eq!(said.name, refused().name);
        assert_ne!(said, refused());
    }
}
