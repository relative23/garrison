//! What every command owes a script that runs it: the reason of a failure
//! on standard error with a status other than 0, no question where no
//! terminal is, and the configuration that `--config` names, or a refusal
//! of the option (installation.md, "Unattended installation").

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::process::Command;

use support::{finished, prepared, run, text};

/// `garrison modules --set` without `--yes` would ask before it writes,
/// and nobody can answer where no terminal is: it refuses, names `--yes`
/// and writes nothing.
#[test]
fn modules_asks_nobody_where_no_terminal_is() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let before = std::fs::read_to_string(&path).unwrap();
    let asked = run(directory.path(), &["modules", "--set", "antivirus,logs"]);
    assert_eq!(asked.status.code(), Some(2), "{}", text(&asked.stdout));
    assert_eq!(
        text(&asked.stderr),
        "garrison modules asks before it writes, and no terminal is here to answer: add --yes \
         to write it.\n"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
}

/// notify-test reads the channels' secrets, which only root may read on a
/// host: without root it says so, as doctor does, and blames no channel.
#[test]
fn notify_test_without_root_says_to_run_as_root() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let config = std::fs::read_to_string(&path).unwrap()
        + "\n[notifications]\nntfy_url = \"https://127.0.0.1:9/topic\"\n";
    std::fs::write(&path, config).unwrap();
    let test = run(directory.path(), &["notify-test"]);
    assert_eq!(
        (test.status.code(), text(&test.stdout), text(&test.stderr)),
        (
            Some(2),
            String::new(),
            "Run as root: the channels' secrets are files only root may read.\n".to_owned()
        )
    );
}

/// The commands that use the units' own configuration, or read none,
/// refuse `--config` before they do anything, where they ignored it.
#[test]
fn a_command_that_follows_no_config_refuses_it() {
    let directory = tempfile::tempdir().unwrap();
    let named = directory.path().join("garrison.toml");
    let units = "uses /etc/garrison/garrison.toml, the units' configuration";
    let none = "reads no configuration";
    for (command, why) in [
        (&["install"][..], units),
        (&["uninstall", "--dry-run"], units),
        (&["setup"], units),
        (&["upgrade", "garrison-0.2.0-x86_64.tar.gz"], units),
        (&["restore", "--from", "/var/backups/garrison"], units),
        (&["backup-check", "restic"], none),
        (&["detect"], none),
    ] {
        let ran = finished(
            Command::new(env!("CARGO_BIN_EXE_garrison"))
                .arg("--config")
                .arg(&named)
                .args(command),
        );
        let refused = format!(
            "garrison {} {why}, so it takes no --config ({}).\n",
            command[0],
            named.display()
        );
        assert_eq!(
            (ran.status.code(), text(&ran.stdout), text(&ran.stderr)),
            (Some(2), String::new(), refused),
            "{command:?}"
        );
    }
}
