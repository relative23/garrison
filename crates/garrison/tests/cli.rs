//! The `garrison` binary: exit codes, outputs and the files it writes.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

mod support;

use std::io::Read;
use std::process::Command;

use garrison_core::config::Database;
use serde_json::{Value, json};
use support::{finished, prepared, run, text};

#[test]
fn the_version_and_a_missing_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let version = run(directory.path(), &["--version"]);
    assert_eq!(
        text(&version.stdout),
        format!("garrison {}\n", env!("CARGO_PKG_VERSION"))
    );
    let nothing = run(directory.path(), &[]);
    assert_eq!(nothing.status.code(), Some(2));
    assert!(text(&nothing.stderr).contains("Usage: garrison"));
    let missing = run(directory.path(), &["check-config"]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(
        text(&missing.stderr).starts_with("Cannot load "),
        "{}",
        text(&missing.stderr)
    );
}

#[test]
fn a_service_that_stops_says_why_in_the_journal_format() {
    let directory = prepared();
    // Without its signature key credential the receiver cannot start.
    let plain = run(directory.path(), &["ingest"]);
    assert_eq!(plain.status.code(), Some(1));
    let logged = text(&plain.stderr);
    assert!(
        logged.starts_with("ERROR garrison: The ingest service stopped: "),
        "{logged}"
    );
    // Under systemd, stderr is the stream that $JOURNAL_STREAM names.
    let (mut reader, writer) = std::io::pipe().unwrap();
    let stream = rustix::fs::fstat(&writer).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_garrison"));
    command
        .arg("--config")
        .arg(directory.path().join("garrison.toml"))
        .arg("ingest")
        .env_remove("CREDENTIALS_DIRECTORY")
        .env(
            "JOURNAL_STREAM",
            format!("{}:{}", stream.st_dev, stream.st_ino),
        )
        .stderr(writer);
    assert_eq!(command.status().unwrap().code(), Some(1));
    drop(command);
    let mut journal = String::new();
    reader.read_to_string(&mut journal).unwrap();
    assert!(
        journal.starts_with("<3>ERROR garrison: The ingest service stopped: "),
        "{journal}"
    );
}

#[test]
fn services_read_credentials_from_systemd_or_the_configured_directory() {
    let directory = prepared();
    let missing_key = |credentials: &str| {
        let output = finished(
            Command::new(env!("CARGO_BIN_EXE_garrison"))
                .arg("--config")
                .arg(directory.path().join("garrison.toml"))
                .arg("ingest")
                .env("CREDENTIALS_DIRECTORY", credentials),
        );
        text(&output.stderr)
    };
    let configured = directory.path().join("credentials/webhook-signature-key");
    assert!(missing_key("/run/credentials/x").contains("/run/credentials/x/webhook-signature-key"));
    // An empty variable is no directory.
    assert!(missing_key("").contains(&configured.display().to_string()));
}

#[test]
fn check_config_reports_providers_actions_and_the_policy() {
    let directory = prepared();
    let valid = run(directory.path(), &["check-config"]);
    assert_eq!(valid.status.code(), Some(0), "{}", text(&valid.stderr));
    assert_eq!(
        text(&valid.stdout),
        format!(
            "Configuration valid: 1 providers, 2 actions.\nAccess policy valid: {}\n",
            directory.path().join("policy.json").display()
        )
    );
    // The test origins are reserved names, as the example's are.
    assert!(
        text(&valid.stderr).contains(
            "Warning: deployment.public_origin https://admin.example.test is a placeholder"
        ),
        "{}",
        text(&valid.stderr)
    );
    // Its directories are the test's, not those of the units.
    let credentials = directory.path().join("credentials");
    assert!(
        text(&valid.stderr).contains(&format!(
            "Warning: credentials_directory is {}, but the units load every credential from \
             /etc/garrison/credentials",
            credentials.display()
        )),
        "{}",
        text(&valid.stderr)
    );
    assert!(text(&valid.stderr).contains("Warning: broker.socket is "));
    std::fs::remove_file(directory.path().join("policy.json")).unwrap();
    let unusable = run(directory.path(), &["check-config"]);
    assert_eq!(unusable.status.code(), Some(1));
    // The reason of a failure is on standard error, as for every command.
    assert!(
        text(&unusable.stderr).contains("Access policy not usable: "),
        "{}",
        text(&unusable.stderr)
    );
    assert!(!text(&unusable.stdout).contains("Access policy"));
}

/// systemd hands a service only the credentials its unit loads, under the
/// names it loads them as: another name is never there. check-config
/// refuses it; notify-test, which reads the configured directory as root,
/// sends nothing on a channel the collector could not use.
#[test]
fn a_credential_name_the_unit_does_not_load_is_refused() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let config = std::fs::read_to_string(&path).unwrap().replacen(
        "[collector]\n",
        "[collector]\nnative_key = \"credential:my-key\"\n",
        1,
    ) + "\n[notifications]\nntfy_url = \"https://127.0.0.1:9/topic\"\n\
         token = \"credential:my-token\"\n";
    std::fs::write(&path, config).unwrap();
    // The file is there, in the directory the operator commands read.
    garrison_testing::write_private(
        &directory.path().join("credentials/my-token"),
        b"tk_0123456789abcdefghij",
    );
    let refused = run(directory.path(), &["check-config"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    let said = text(&refused.stderr);
    for line in [
        "Configuration not usable: collector.native_key is credential:my-key, but \
         garrison-collect.service loads this secret only as credential:collector-native-key. \
         Write collector.native_key = \"credential:collector-native-key\" and keep the \
         secret in /etc/garrison/credentials/collector-native-key.\n",
        "Configuration not usable: notifications.token is credential:my-token, but \
         garrison-collect.service and garrison-watch.service load this secret only as \
         credential:ntfy-token. Write notifications.token = \"credential:ntfy-token\" and \
         keep the secret in /etc/garrison/credentials/ntfy-token.\n",
    ] {
        assert!(said.contains(line), "{said}");
    }
    assert_eq!(text(&refused.stdout), "");
    let test = run(directory.path(), &["notify-test"]);
    assert_eq!(
        (test.status.code(), text(&test.stdout)),
        (Some(2), String::new()),
        "{}",
        text(&test.stderr)
    );
    assert!(
        text(&test.stderr).contains("notifications.token is credential:my-token, but "),
        "{}",
        text(&test.stderr)
    );
    assert!(!text(&test.stderr).contains("collector.native_key"));
}

/// A secret named by its path the service would read itself, as its own
/// user, which a command running as root cannot judge for it: notify-test
/// and doctor would call a file usable that the collector cannot read.
#[test]
fn a_secret_named_by_its_path_is_refused() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let token = directory.path().join("ntfy-token");
    garrison_testing::write_private(&token, b"tk_0123456789abcdefghij");
    let config = std::fs::read_to_string(&path).unwrap()
        + &format!(
            "\n[notifications]\nntfy_url = \"https://127.0.0.1:9/topic\"\ntoken = \"{}\"\n",
            token.display()
        );
    std::fs::write(&path, config).unwrap();
    let refused = run(directory.path(), &["check-config"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert!(
        text(&refused.stderr).contains(&format!(
            "Configuration not usable: notifications.token names the file {}, which the \
             service would read itself, as its own user; garrison-collect.service and \
             garrison-watch.service load this secret for it only as credential:ntfy-token. \
             Move the file to /etc/garrison/credentials/ntfy-token (root, mode 0600) and write \
             notifications.token = \"credential:ntfy-token\".\n",
            token.display()
        )),
        "{}",
        text(&refused.stderr)
    );
    let test = run(directory.path(), &["notify-test"]);
    assert_eq!(
        (test.status.code(), text(&test.stdout)),
        (Some(2), String::new()),
        "{}",
        text(&test.stderr)
    );
    assert!(
        text(&test.stderr).starts_with("Not tested: notifications.token names the file "),
        "{}",
        text(&test.stderr)
    );
}

#[test]
fn check_config_refuses_two_providers_that_report_one_observation() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let mut config = std::fs::read_to_string(&path).unwrap();
    // A second check of the host: every run would report host.resources twice.
    config.push_str("\n[[providers]]\ntype = \"host\"\n");
    std::fs::write(&path, config).unwrap();
    let refused = run(directory.path(), &["check-config"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        text(&refused.stderr).contains(
            "providers[1] (host) reports the observation host.resources as well as providers[0] (host)"
        ),
        "{}",
        text(&refused.stderr)
    );
}

/// The broker's unit hides /home from it, as /root, /run/user, /tmp,
/// /var/tmp and /dev. check-config refuses a policy there in the file the
/// units read (units.rs holds that) and warns in any other, such as this one.
#[test]
fn check_config_names_a_policy_where_the_broker_cannot_read_it() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let policy = directory.path().join("policy.json");
    let config = std::fs::read_to_string(&path).unwrap().replace(
        &format!("policy = \"{}\"", policy.display()),
        "policy = \"/home/garrison-cli-test/policy.json\"",
    );
    std::fs::write(&path, config).unwrap();
    let checked = run(directory.path(), &["check-config"]);
    assert!(
        text(&checked.stderr).contains(
            "Warning: broker.policy is /home/garrison-cli-test/policy.json, under /home, which \
             garrison-broker.service hides from the broker (ProtectHome=true): the broker cannot \
             read it there, and nobody can sign in. Keep the policy where the broker sees it, \
             such as /etc/garrison/access-policy.json, and name that in broker.policy.\n"
        ),
        "{}",
        text(&checked.stderr)
    );
    // Nothing is there, which check-config says after it.
    assert_eq!(checked.status.code(), Some(1));
    assert!(text(&checked.stderr).contains("Access policy not usable: "));
}

#[test]
fn the_switch_snippet_comes_from_the_interface_next_to_the_binary() {
    // A release layout: bin/garrison and static/ beside it.
    let release = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    std::fs::create_dir(release.path().join("bin")).unwrap();
    let binary = release.path().join("bin/garrison");
    std::fs::hard_link(env!("CARGO_BIN_EXE_garrison"), &binary).unwrap();
    let directory = prepared();
    let switch = || {
        Command::new(&binary)
            .arg("--config")
            .arg(directory.path().join("garrison.toml"))
            .arg("stalwart-switch")
            .output()
            .unwrap()
    };
    let missing = switch();
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        text(&missing.stderr)
            .ends_with("stalwart-switch.js is missing; build the interface first.\n")
    );
    std::fs::create_dir(release.path().join("static")).unwrap();
    std::fs::write(
        release.path().join("static/stalwart-switch.js"),
        "/* row */",
    )
    .unwrap();
    let snippet = switch();
    assert_eq!(snippet.status.code(), Some(0), "{}", text(&snippet.stderr));
    let snippet = text(&snippet.stdout);
    assert!(
        snippet.contains(
            r#"<script src="https://admin.example.test/admin/stalwart-switch.js" integrity="sha384-"#
        ),
        "{snippet}"
    );
}

#[test]
fn the_polkit_rule_allows_exactly_the_actions() {
    let directory = prepared();
    let rule = run(directory.path(), &["polkit-rule"]);
    assert_eq!(text(&rule.stdout), include_str!("fixtures/polkit.rules"));
}

#[test]
fn the_nginx_include_sends_requests_to_the_configured_web_port() {
    let directory = prepared();
    let shipped = include_str!("../../../deploy/nginx/garrison.conf");
    let default = run(directory.path(), &["nginx", "--snippet"]);
    assert_eq!(default.status.code(), Some(0), "{}", text(&default.stderr));
    assert_eq!(text(&default.stdout), shipped);
    let path = directory.path().join("garrison.toml");
    let config = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, config.replace("[web]\n", "[web]\nport = 9443\n")).unwrap();
    let moved = run(directory.path(), &["nginx", "--snippet"]);
    assert_eq!(
        text(&moved.stdout),
        shipped.replace("127.0.0.1:8091;", "127.0.0.1:9443;")
    );
}

#[test]
fn a_backup_drops_sessions_and_passes_its_self_check() {
    let directory = prepared();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let store = garrison_web::store::WebStore::open(&config.database(Database::Web)).unwrap();
    let session = garrison_web::store::NewSession {
        subject: "1",
        email: "1@example.test",
        token: "token-0123456789abcdef",
        client_ip: None,
        lifetime: 600,
    };
    store.create(&session).unwrap();
    drop(store);
    garrison_broker::store::JobStore::open(&config.database(Database::Jobs)).unwrap();
    let target = directory.path().join("backup");
    let backup = run(
        directory.path(),
        &["backup", "--to", target.to_str().unwrap()],
    );
    assert_eq!(backup.status.code(), Some(0), "{}", text(&backup.stderr));
    assert_eq!(
        text(&backup.stdout),
        format!(
            "- web: copied\n- ingest: absent\n- collector: absent\n- broker: copied\nBackup written to {}\n",
            target.display()
        )
    );
    let copy = rusqlite::Connection::open(target.join("web/web.sqlite")).unwrap();
    let sessions: i64 = copy
        .query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(sessions, 0, "access tokens are not in a backup");
    // The restore after a rollback finds the policy under this name.
    assert!(target.join("access-policy.json").is_file());
    let receipt = directory.path().join("self-check.json");
    let check = run(
        directory.path(),
        &[
            "self-check",
            "--state",
            target.to_str().unwrap(),
            "--receipt",
            receipt.to_str().unwrap(),
        ],
    );
    assert_eq!(check.status.code(), Some(0), "{}", text(&check.stdout));
    let report: Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(report["result"], "passed");
    assert_eq!(
        report["databases"]["ingest"],
        json!({"ok": null, "absent": true})
    );
    assert_eq!(report["databases"]["web"]["schemaVersion"], 1);
    // A receipt named without a directory lands in the working directory.
    let relative = Command::new(env!("CARGO_BIN_EXE_garrison"))
        .current_dir(directory.path())
        .args(["--config", "garrison.toml", "self-check", "--state"])
        .arg(&target)
        .args(["--receipt", "relative.json"])
        .env_remove("CREDENTIALS_DIRECTORY")
        .output()
        .unwrap();
    assert_eq!(
        relative.status.code(),
        Some(0),
        "{}",
        text(&relative.stderr)
    );
    assert!(directory.path().join("relative.json").is_file());
    std::fs::write(target.join("broker/jobs.sqlite"), b"not a database").unwrap();
    let damaged = run(
        directory.path(),
        &["self-check", "--state", target.to_str().unwrap()],
    );
    assert_eq!(damaged.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&damaged.stdout).unwrap();
    assert_eq!(report["message"], "Problems in: broker");
}

#[test]
fn modules_writes_the_choice_and_keeps_the_previous_file() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let before = std::fs::read_to_string(&path).unwrap();
    let chosen = run(
        directory.path(),
        &["modules", "--set", "antivirus,logs", "--yes"],
    );
    assert_eq!(chosen.status.code(), Some(0), "{}", text(&chosen.stderr));
    let after = std::fs::read_to_string(&path).unwrap();
    assert!(
        after.contains("modules = [\"antivirus\", \"logs\"]\n"),
        "{after}"
    );
    let previous = directory.path().join("garrison.toml.previous");
    assert_eq!(std::fs::read_to_string(previous).unwrap(), before);
    // Without root nothing is restarted; the output says what to restart.
    assert!(text(&chosen.stdout).contains("Restart garrison-broker.service"));
    let again = run(
        directory.path(),
        &["modules", "--set", "logs antivirus", "--yes"],
    );
    assert!(text(&again.stdout).contains("nothing was changed"));
    // A typo is refused before anything is written.
    let typo = run(
        directory.path(),
        &["modules", "--set", "antivirus,backup", "--yes"],
    );
    assert_eq!(typo.status.code(), Some(2));
    assert!(text(&typo.stderr).starts_with("backup is not a module ID"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), after);
}
