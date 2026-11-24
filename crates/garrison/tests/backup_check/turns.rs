//! Two runs of one report at once, as a weekly check and a monthly restore
//! started by timers of their own: the one that starts second waits for
//! the first, so that neither writes back a check or restore the other
//! replaced.

use std::io::{BufRead, BufReader};
use std::process::Stdio;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;

use super::case::{Case, HERE, OLD};
use super::stand_in::read;
use super::support::{finished, states, text};

/// A check that fails while another run restores is the last check the
/// report holds, beside that run's restore.
#[test]
fn a_check_made_while_another_run_restores_is_the_one_kept() {
    let case = Case::new("restic");
    case.checked(&HERE, &[("REPO_ID", OLD)]);
    let report = case.report.display().to_string();
    let go = case.tools.directory.path().join("go");
    let until = go.display().to_string();
    // The restore waits until the file `go` is there.
    let restore = [
        "restic",
        "--repo",
        "/srv/repo",
        "--restore",
        "/etc/hosts",
        "--report",
        &report,
    ];
    let holding = [
        ("REPO_ID", OLD),
        ("HOLD", "restore"),
        ("HOLD_UNTIL", &until),
    ];
    let mut restoring = case.tools.command(&restore, &holding);
    let restoring = thread::spawn(move || finished(&mut restoring));
    let deadline = Instant::now() + Duration::from_secs(30);
    while !go.with_extension("held").exists() {
        assert!(Instant::now() < deadline, "the restore never began");
        thread::sleep(Duration::from_millis(10));
    }
    // The check, which fails, starts while the restore waits; it ends, or
    // says that it waits for the restore's run.
    let check = [
        "restic",
        "--repo",
        "/srv/repo",
        "--verify",
        "--report",
        &report,
    ];
    let mut checking = case
        .tools
        .command(&check, &[("REPO_ID", OLD), ("BROKEN", "check")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (sender, said) = mpsc::channel();
    let stderr = BufReader::new(checking.stderr.take().unwrap());
    thread::spawn(move || {
        for line in stderr.lines() {
            let _ = sender.send(line.unwrap());
        }
    });
    let first = said.recv_timeout(Duration::from_secs(30)).ok();
    std::fs::write(&go, "").unwrap();
    let restored = restoring.join().unwrap();
    assert_eq!(
        restored.status.code(),
        Some(0),
        "{}",
        text(&restored.stderr)
    );
    assert_eq!(checking.wait().unwrap().code(), Some(1));
    let written = read(&case.report);
    assert_eq!(
        (&written["verify"]["ok"], &written["restore"]["ok"]),
        (&json!(false), &json!(true)),
        "{written}"
    );
    let first = first.unwrap_or_default();
    assert_eq!(states(first.as_bytes()), ["backup-check-waits"], "{first}");
    assert!(first.contains(&report), "{first}");
}

/// A link or a pipe at the lock's name is no lock: the run ends before it
/// asks the tool, says what to do, and changes neither the link nor what it
/// leads to.
#[test]
fn a_lock_that_is_no_file_of_the_users_own_ends_the_run() {
    let case = Case::new("restic");
    let lock = case.report.with_extension("json.lock");
    let elsewhere = case.tools.directory.path().join("elsewhere");
    std::fs::write(&elsewhere, "kept").unwrap();
    for what in ["link", "pipe"] {
        if what == "link" {
            std::os::unix::fs::symlink(&elsewhere, &lock).unwrap();
        } else {
            let fifo = rustix::fs::FileType::Fifo;
            let mode = rustix::fs::Mode::from_raw_mode(0o600);
            rustix::fs::mknodat(rustix::fs::CWD, &lock, fifo, mode, 0).unwrap();
        }
        let ran = case.run(&HERE, &[("REPO_ID", OLD)]);
        assert_eq!(ran.status.code(), Some(1), "{what}");
        assert_eq!(states(&ran.stderr), ["backup-check-lock-other"], "{what}");
        assert!(
            text(&ran.stderr).contains(&lock.display().to_string()),
            "{what}"
        );
        assert_eq!(case.tools.calls(), Vec::<String>::new(), "{what}");
        assert!(!case.report.exists(), "{what}");
        std::fs::remove_file(&lock).unwrap();
    }
    assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "kept");
}
