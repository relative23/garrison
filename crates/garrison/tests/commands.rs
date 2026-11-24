//! What every command owes a script that runs it: the reason of a failure
//! on standard error with a status other than 0, no question where no
//! terminal is, and the configuration that `--config` names, or a refusal
//! of the option (installation.md, "Unattended installation").

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{prepared, run, text};

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
