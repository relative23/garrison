//! The actions a policy names against those the broker runs. One that
//! garrison.toml has gained since the broker started, which `garrison access
//! update` gives the profiles, refuses nobody and is offered to nobody until
//! the broker starts anew, which its journal says once; one that
//! garrison.toml does not have either is a broken setup, whose line names it
//! and the command that takes it out.

use garrison_testing::http::serve;
use garrison_testing::{config, config_text, credentials, policy_document, write_policy};
use serde_json::{Value, json};

use super::limit_tests::{TOKEN, granted, kept, kept_lines};
use super::tests::{REQUEST, Systemd};
use super::*;

/// The action garrison.toml has gained since the broker started.
const ADDED: &str = r#"
[[actions]]
id = "run_added"
title = "Run the added job"
description = "Another job."
confirmation = "RUN ADDED"
unit = "added.service"
operation = "start"
cooldown_seconds = 60
timeout_seconds = 60
"#;

/// A broker started with the test configuration's two actions, whose
/// garrison.toml now names `run_added` as well, with a policy whose
/// administrators have `actions`, and a stand-in for Stalwart that answers
/// `checks` checks of the administrator's rights.
fn started(
    actions: Value,
    checks: usize,
) -> (
    Arc<Broker>,
    garrison_testing::http::Server,
    tempfile::TempDir,
) {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(granted().into_iter().cycle().take(4 * checks).collect());
    let config = config(directory.path(), &server.url);
    let path = directory.path().join("garrison.toml");
    std::fs::write(&path, config_text(directory.path(), &server.url) + ADDED).unwrap();
    let mut document = policy_document();
    document["profiles"]["administrator"]["actions"] = actions;
    write_policy(&config, &document);
    let authority = Authority::new(&config, credentials(&config)).reading_actions_from(&path);
    let store = JobStore::open(&directory.path().join("jobs.sqlite")).unwrap();
    let broker = Broker::new(
        Box::new(authority),
        config.broker.actions.clone(),
        store,
        Box::new(Arc::new(Systemd::default())),
        Box::new(|work| {
            work();
            Ok(())
        }),
    );
    (broker, server, directory)
}

#[test]
fn an_action_garrison_toml_gained_since_the_start_refuses_nobody() {
    kept();
    let granting = json!(["run_backup", "run_monitor", "run_added"]);
    let (broker, server, _directory) = started(granting, 3);
    for _ in 0..2 {
        let catalog = broker.catalog(TOKEN).unwrap();
        let offered: Vec<String> = catalog
            .actions
            .into_iter()
            .map(|action| action.id)
            .collect();
        assert_eq!(offered, ["run_monitor", "run_backup"]);
    }
    // It runs no unit it was not started with.
    let refused = broker
        .submit(TOKEN, "run_added", REQUEST, "RUN ADDED")
        .unwrap_err();
    assert_eq!(
        (refused.status, refused.message.as_str()),
        (403, "This maintenance action is not authorized")
    );
    server.requests();
    let said = kept_lines("WARN The access policy names run_added", "");
    assert_eq!(said.len(), 1, "once: {said:?}");
    assert!(
        said[0].contains("until the installer runs again"),
        "{}",
        said[0]
    );
}

#[test]
fn an_action_garrison_toml_does_not_have_is_a_broken_setup() {
    kept();
    let (broker, server, _directory) = started(json!(["run_backup", "run_never"]), 1);
    let error = broker.catalog(TOKEN).unwrap_err();
    drop(server);
    assert_eq!(
        (error.status, error.message.as_str()),
        (
            503,
            "Garrison is not set up to check access rights; the broker's journal says why"
        )
    );
    let said = kept_lines("ERROR Access rights cannot be checked", "run_never");
    assert_eq!(
        said,
        [
            "ERROR Access rights cannot be checked: Garrison access policy: profile administrator \
          names run_never, which garrison.toml does not have: run `garrison access update`, \
          which takes it out of the profiles"
        ]
    );
}
