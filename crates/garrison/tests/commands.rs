//! What every command owes a script that runs it: the reason of a failure
//! on standard error with a status other than 0, no question where no
//! terminal is, and the configuration that `--config` names, or a refusal
//! of the option (installation.md, "Unattended installation").

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

/// How a command takes `--config`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Takes {
    /// It reads the file the option names; `watch` looks even where it
    /// does not load, as a stopped collector's cause may be just that.
    Follows,
    /// It uses the units' own file or none, and refuses the option.
    Refuses,
}

/// One command, as reviewed against the four questions: its arguments, its
/// help line, how it takes `--config`, and how it ends run without root,
/// without a terminal and on the tests' configuration: `None` for a service,
/// which serves until systemd stops it, and for detect, which reads this
/// host and whose own tests read fixtures.
type Row = (&'static [&'static str], &'static str, Takes, Option<i32>);

use Takes::{Follows, Refuses};

const ROWS: [Row; 30] = [
    (
        &["install"],
        "Install or upgrade from this extracted release, or roll back (root)",
        Refuses,
        Some(1),
    ),
    (
        &["uninstall", "--dry-run"],
        "Take Garrison off this host; data and configuration stay (root)",
        Refuses,
        Some(1),
    ),
    (
        &["setup"],
        "Set Garrison up step by step at a terminal: addresses, modules, Stalwart, access, start (root)",
        Refuses,
        Some(2),
    ),
    (
        &["upgrade", "garrison-0.2.0-x86_64.tar.gz"],
        "Install a newer release once its signature checks out (root)",
        Refuses,
        Some(1),
    ),
    (
        &["restore", "--from", "/var/backups/garrison"],
        "Put back the state that `garrison backup` wrote (root)",
        Refuses,
        Some(1),
    ),
    (
        &["watch"],
        "One look at whether the collector still runs (systemd timer)",
        Follows,
        Some(0),
    ),
    (
        &["backup-check", "restic"],
        "Ask restic or borg about its repository and write a report for the collector (root)",
        Refuses,
        Some(1),
    ),
    (
        &["detect"],
        "Show what this host already runs, without changing anything",
        Refuses,
        None,
    ),
    (&["web"], "The web service (systemd)", Follows, None),
    (&["ingest"], "The webhook receiver (systemd)", Follows, None),
    (
        &["collect"],
        "One collection run (systemd timer)",
        Follows,
        None,
    ),
    (
        &["broker"],
        "The maintenance broker (systemd)",
        Follows,
        None,
    ),
    (
        &["milter"],
        "The macro milter, where the configuration switches it on (systemd)",
        Follows,
        None,
    ),
    (
        &["check-config"],
        "Validate the configuration, the providers and the access policy",
        Follows,
        Some(0),
    ),
    (
        &["modules"],
        "Choose the modules this installation offers (root)",
        Follows,
        Some(0),
    ),
    (
        &["polkit-rule"],
        "Print the polkit rule for the configured actions",
        Follows,
        Some(0),
    ),
    (
        &["stalwart-switch"],
        "Print the nginx include for the Stalwart WebUI",
        Follows,
        Some(1),
    ),
    (
        &["nginx"],
        "Print the nginx server block for Garrison's host name, for the nginx installed here",
        Follows,
        Some(0),
    ),
    (
        &["access", "init"],
        "Create the policy and bind native administrator roles",
        Follows,
        Some(1),
    ),
    (&["access", "list"], "Show the policy", Follows, Some(0)),
    (
        &["access", "bind-role", "r9", "--profile", "viewer"],
        "Give a native role a Garrison profile",
        Follows,
        Some(1),
    ),
    (
        &["access", "unbind-role", "r9"],
        "Remove the profile of a native role",
        Follows,
        Some(0),
    ),
    (
        &["access", "deny", "9"],
        "Deny a subject regardless of roles",
        Follows,
        Some(0),
    ),
    (
        &["access", "check", "9"],
        "Show the current grant of a subject",
        Follows,
        Some(1),
    ),
    (
        &["access", "update"],
        "Give the profiles the actions garrison.toml has now, as init does",
        Follows,
        Some(0),
    ),
    (
        &["stalwart", "setup"],
        "Connect Stalwart: the webhook, the API keys, the sign-in client, the metrics access and the macro filter's entry",
        Follows,
        Some(2),
    ),
    (
        &["backup", "--to", "{D}/backup"],
        "Write consistent copies of Garrison state",
        Follows,
        Some(0),
    ),
    (
        &["doctor"],
        "Check the whole installation and say what to do about each problem (root)",
        Follows,
        Some(2),
    ),
    (
        &["notify-test"],
        "Send a test message on every configured notification channel (root)",
        Follows,
        Some(2),
    ),
    (
        &["self-check"],
        "Verify Garrison databases",
        Follows,
        Some(0),
    ),
];

/// The commands that hold others, with their help lines.
const GROUPS: [(&str, &str); 2] = [
    ("access", "Manage Garrison access policy (root)"),
    ("stalwart", "Configure Stalwart for Garrison"),
];

/// The commands and help lines `garrison <group> --help` lists, help aside.
fn listed(group: &[&str]) -> Vec<(Vec<String>, String)> {
    // The help wraps at the width its environment names; a wide one keeps
    // every command's line whole, wherever the test runs.
    let help = finished(
        Command::new(env!("CARGO_BIN_EXE_garrison"))
            .args(group)
            .arg("--help")
            .env("COLUMNS", "400"),
    );
    let help = text(&help.stdout);
    let commands = help.split("\nCommands:\n").nth(1).unwrap();
    let commands = commands.split("\n\n").next().unwrap();
    commands
        .lines()
        .filter_map(|line| {
            let (name, about) = line.trim_start().split_once("  ")?;
            let mut path: Vec<String> = group.iter().map(|word| (*word).to_owned()).collect();
            path.push(name.to_owned());
            (name != "help").then(|| (path, about.trim().to_owned()))
        })
        .collect()
}

/// `garrison` with `arguments`, without a terminal and with standard input
/// a pipe that stays open until it ends: a command that read it would wait
/// until it is killed.
fn ran(arguments: &[String]) -> std::process::Output {
    use std::io::Read;
    let mut child = Command::new(env!("CARGO_BIN_EXE_garrison"))
        .args(arguments)
        .env_remove("CREDENTIALS_DIRECTORY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = child.stdin.take();
    let drain = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut data = Vec::new();
            pipe.read_to_end(&mut data).unwrap();
            data
        })
    };
    let stdout = drain(Box::new(child.stdout.take().unwrap()));
    let stderr = drain(Box::new(child.stderr.take().unwrap()));
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("{arguments:?} still ran after 30 s: does it read standard input?");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    drop(input);
    std::process::Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    }
}

/// Every command `--help` lists, through the four questions a script asks
/// of it, each answered in a row reviewed for it, so that a new command
/// fails here until it has one: what its help says, which the row holds;
/// whether it asks, which none may where no terminal is, so each runs
/// without one and with standard input a pipe that stays open; how it
/// takes `--config`: with one that is not there it names that file and
/// fails, or refuses the option; and where a failure's reason goes: run on
/// the tests' configuration and without root, it ends as its row says,
/// with the reason of a failure on standard error, but for self-check's
/// report, which keeps its failures on standard output.
#[test]
fn every_command_is_held_to_the_four_questions() {
    let mut shown: Vec<(Vec<String>, String)> = listed(&[]);
    for (group, _) in GROUPS {
        shown.extend(listed(&[group]));
    }
    let mut reviewed: Vec<(Vec<String>, String)> = GROUPS
        .iter()
        .map(|(group, help)| (vec![(*group).to_owned()], (*help).to_owned()))
        .collect();
    for (command, help, _, _) in ROWS {
        let named = command.iter().take_while(|word| !word.starts_with('-'));
        let named: Vec<String> = named.map(|word| (*word).to_owned()).collect();
        let path = if GROUPS.iter().any(|(group, _)| *group == named[0]) {
            named[..2].to_vec()
        } else {
            named[..1].to_vec()
        };
        reviewed.push((path, help.to_owned()));
    }
    shown.sort();
    reviewed.sort();
    assert_eq!(
        shown, reviewed,
        "a command without its row, or a help line changed"
    );
    let mut wrong = Vec::new();
    for (command, _, takes, ends) in ROWS {
        let directory = prepared();
        let missing = directory.path().join("missing.toml");
        let at = |word: &str| word.replace("{D}", &directory.path().display().to_string());
        let mut arguments = vec!["--config".to_owned(), missing.display().to_string()];
        arguments.extend(command.iter().map(|word| at(word)));
        let named = ran(&arguments);
        let (stdout, stderr) = (text(&named.stdout), text(&named.stderr));
        let right = match (takes, command[0]) {
            (Follows, "watch") => {
                named.status.code() == Some(0)
                    && stderr.contains(&format!("{} does not load", missing.display()))
            }
            (Follows, _) => {
                named.status.code() == Some(2)
                    && stdout.is_empty()
                    && stderr.starts_with(&format!("Cannot load {}", missing.display()))
            }
            (Refuses, _) => {
                named.status.code() == Some(2)
                    && stdout.is_empty()
                    && stderr.contains("so it takes no --config")
            }
        };
        if !right {
            wrong.push(format!(
                "{command:?} with --config {missing:?}: {:?} {stdout:?} {stderr:?}",
                named.status.code()
            ));
        }
        let Some(expected) = ends else {
            continue;
        };
        let mut arguments = vec![
            "--config".to_owned(),
            directory.path().join("garrison.toml").display().to_string(),
        ];
        arguments.extend(command.iter().map(|word| at(word)));
        if takes == Refuses {
            arguments.drain(..2);
        }
        let configured = ran(&arguments);
        let (stdout, stderr) = (text(&configured.stdout), text(&configured.stderr));
        let code = configured.status.code();
        let reason = match code {
            Some(0) => true,
            _ if command[0] == "self-check" => !stdout.is_empty(),
            _ => !stderr.is_empty(),
        };
        if code != Some(expected) || !reason {
            wrong.push(format!("{command:?}: {code:?} {stdout:?} {stderr:?}"));
        }
    }
    assert_eq!(wrong, Vec::<String>::new());
}
