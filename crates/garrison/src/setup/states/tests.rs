//! Setup's states, each with its whole line: the one place in setup's tests
//! where their words stand.

use std::path::Path;

use garrison_core::files::ProtectedFileError;

use super::*;
use crate::state::State;

type Rows = Vec<(State, &'static str)>;

/// What setup refuses before it asks Stalwart anything.
fn before() -> Rows {
    let folder = Path::new("/etc/garrison/credentials");
    let denied = "Permission denied (os error 13)";
    let missing = ProtectedFileError::Unavailable("/root/admin.json".into());
    vec![
        (
            no_administrator(),
            "Name the Stalwart administrator: run this at a terminal to be asked, or pass \
             --admin-credential - with the JSON on standard input, or --admin-credential FILE. \
             [setup-no-administrator]",
        ),
        (
            again(file_unread(missing), "garrison stalwart setup"),
            "Protected file is unavailable: /root/admin.json. Run `garrison stalwart setup` again \
             once this is mended. [setup-file-unread]",
        ),
        (
            input_unread("Input/output error (os error 5)"),
            "standard input: Input/output error (os error 5) [setup-input-unread]",
        ),
        (
            administrator_too_long(),
            "The administrator on standard input is too long. [setup-administrator-too-long]",
        ),
        (
            administrator_not_json("invalid JSON: expected value at line 1 column 1"),
            "invalid JSON: expected value at line 1 column 1 [setup-administrator-not-json]",
        ),
        (
            administrator_unusable(),
            r#"The administrator needs {"username","secret"} or {"apiKey"} [setup-administrator-unusable]"#,
        ),
        (
            ask_failed(
                "/usr/bin/systemd-ask-password",
                "No such file or directory (os error 2)",
            ),
            "/usr/bin/systemd-ask-password: No such file or directory (os error 2) \
             [setup-ask-failed]",
        ),
        (
            no_secret(),
            "No secret was entered; nothing was changed. [setup-no-secret]",
        ),
        (
            not_root(folder, denied),
            "Setup cannot write the credentials folder /etc/garrison/credentials: Permission \
             denied (os error 13). Run it as root, as `sudo garrison stalwart setup`; nothing was \
             changed. [setup-not-root]",
        ),
        (
            folder_unwritable(
                folder,
                "Read-only file system (os error 30)",
                "garrison setup",
            ),
            "Setup cannot write the credentials folder /etc/garrison/credentials: Read-only file \
             system (os error 30). Nothing was changed; run `garrison setup` again once this is \
             mended. [setup-folder-unwritable]",
        ),
        (
            network_invalid("nonsense"),
            "invalid network nonsense [setup-network-invalid]",
        ),
        (
            network_host_bits("172.17.0.1/16"),
            "172.17.0.1/16 has host bits set [setup-network-host-bits]",
        ),
    ]
}

/// How Stalwart answered, where it did not do what setup asked.
fn answers() -> Rows {
    let refusal = r#"{"new":{"type":"invalidProperties","properties":["url"]}}"#;
    vec![
        (
            call_failed("x:ApiKey/get", "Stalwart is unavailable"),
            "x:ApiKey/get: Stalwart is unavailable [setup-call-failed]",
        ),
        (
            limited("x:ApiKey/get"),
            "x:ApiKey/get: Stalwart refused the request for its limit of requests (HTTP 429), \
             whose window is a minute unless it was set otherwise [setup-limited]",
        ),
        (
            again(administrator_refused(), "garrison stalwart setup"),
            "Stalwart refused the administrator (HTTP 401): check the user name and the password, \
             or the API key. Run `garrison stalwart setup` again once this is mended. \
             [setup-administrator-refused]",
        ),
        (
            administrator_refused_here(),
            "Stalwart refused the administrator from this host's address (HTTP 403): its API key \
             may not allow that address. [setup-administrator-refused-here]",
        ),
        (
            unreadable("x:WebHook/get", "malformed answer"),
            "x:WebHook/get: malformed answer, which this release of Garrison does not read; see \
             the supported Stalwart releases in the README [setup-unreadable]",
        ),
        (
            stalwart_error("x:MtaMilter/get", "forbidden", "Forbidden"),
            "x:MtaMilter/get: forbidden Forbidden [setup-stalwart-error]",
        ),
        (
            again(
                until(stalwart_refused("x:WebHook/set", refusal), true, false),
                "garrison stalwart setup --rotate",
            ),
            "x:WebHook/set: {\"new\":{\"type\":\"invalidProperties\",\"properties\":[\"url\"]}}; \
             the receiver may refuse Stalwart's batches until setup runs again, and Stalwart sends \
             them again for an hour [setup-signature-pending]. Run `garrison stalwart setup \
             --rotate` again once this is mended. [setup-stalwart-refused]",
        ),
        (
            event_forbidden("smtp.raw-input"),
            "This build of Garrison would ask Stalwart for the event smtp.raw-input, which \
             Garrison must never record, so the webhook was not changed. Install Garrison again \
             from its release archive. [setup-event-forbidden]",
        ),
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
        (
            taken_out(unwritten(file, "Permission denied (os error 13)")),
            "Could not write /etc/garrison/credentials/broker-native-key: Permission denied (os \
             error 13); the new API key was taken out of Stalwart again [setup-unwritten]",
        ),
        (
            no_random("getrandom: this target is not supported"),
            "getrandom: this target is not supported [setup-no-random]",
        ),
        (
            owner_unknown(file, LIMITED),
            "Asking Stalwart whose API key /etc/garrison/credentials/broker-native-key holds: \
             Stalwart refused the request for its limit of requests (HTTP 429), whose window is a \
             minute unless it was set otherwise [setup-key-owner-unknown]",
        ),
        (
            account_unseen(file, &missing),
            "Stalwart does not show the administrator the account that the API key in \
             /etc/garrison/credentials/broker-native-key belongs to: run setup as an \
             administrator who holds the keys' permissions, as one with Stalwart's administrator \
             role (x:ApiKey/get: accountNotFound The accountId does not correspond to a valid \
             account [setup-stalwart-error]) [setup-account-unseen]",
        ),
        (
            webhooks_unreadable(&stalwart_error("x:WebHook/get", "forbidden", "Forbidden")),
            "Stalwart does not let the administrator read its webhooks: run setup as an \
             administrator who holds the keys' permissions, as one with Stalwart's administrator \
             role (x:WebHook/get: forbidden Forbidden [setup-stalwart-error]) \
             [setup-webhooks-unreadable]",
        ),
        (
            account_full("'garrison broker', 'backup'", "garrison broker"),
            "Stalwart takes no more API keys in the administrator's account, which holds \
             'garrison broker', 'backup': setup makes a new key before it removes the one it \
             replaces. Remove a key the account no longer needs in the Stalwart WebUI; setup made \
             no new key 'garrison broker' and removed none [setup-account-full]",
        ),
        (
            key_not_granted("garrison broker", &forbidden),
            "Stalwart refused the administrator the API key 'garrison broker', since it may not \
             grant the key's permissions: run setup as an administrator who holds them, as one \
             with Stalwart's administrator role (x:ApiKey/set: {\"new\":{\"description\":\"You \
             are not authorized to grant permissions: sysRoleGet\",\"type\":\"forbidden\"}} \
             [setup-stalwart-refused]) [setup-key-not-granted]",
        ),
        (
            secret_missing(),
            "Stalwart did not return the new API key secret [setup-key-secret-missing]",
        ),
        (
            key_untried("broker-native-key", "The endpoint did not answer"),
            "Trying broker-native-key: The endpoint did not answer [setup-key-untried]",
        ),
        (
            key_untaken("broker-native-key"),
            "Stalwart does not take the API key in broker-native-key (HTTP 401) \
             [setup-key-untaken]",
        ),
        (
            again(
                key_refused_here("broker-native-key"),
                "garrison stalwart setup --rotate",
            ),
            "Stalwart refuses the API key in broker-native-key from this host (HTTP 403): it sees \
             this host at an address the key does not allow. That happens when Stalwart runs in a \
             Docker or Podman bridge network; run it in the host network instead (docker run \
             --network host, or network_mode: host with Compose). Run `garrison stalwart setup \
             --rotate` again once this is mended. [setup-key-refused-here]",
        ),
        (
            old_key_kept(&restart_asked("garrison-broker", true)),
            "Restart garrison-broker so it reads the new secret. [setup-restart-asked] Until then \
             it holds the API key the new one replaces, which stays in Stalwart \
             [setup-old-key-kept]",
        ),
    ]
}

/// What a run says it did, or left, of the services and the secrets.
fn outcomes() -> Rows {
    vec![
        (
            as_asked(),
            "Stalwart is set up as asked; nothing was changed. [setup-as-asked]",
        ),
        (
            reloaded(Some(&restarted("garrison-ingest", true))),
            "Settings reloaded. garrison-ingest restarted with the new secret. [setup-restarted] \
             [setup-reloaded]",
        ),
        (
            restart_asked("garrison-ingest and garrison-broker", false),
            "Restart garrison-ingest and garrison-broker so they read the new secrets. \
             [setup-restart-asked]",
        ),
        (
            read_at_start("garrison-broker", true),
            "garrison-broker reads the new secret when it starts. [setup-read-at-start]",
        ),
        (
            restarted("garrison-ingest", true),
            "garrison-ingest restarted with the new secret. [setup-restarted]",
        ),
        (
            signature_pending(),
            "the receiver may refuse Stalwart's batches until setup runs again, and Stalwart sends \
             them again for an hour [setup-signature-pending]",
        ),
        (
            scrape_pending(),
            "the exporter may refuse the collector's scrape until setup runs again \
             [setup-scrape-pending]",
        ),
    ]
}

/// Lines the table's states say for other data, and with the clauses that
/// keep a state's name: their words are the table's too.
fn others() -> Rows {
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
