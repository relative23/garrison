//! `garrison backup-check`: what it asks restic and borg, what it writes
//! down, and how it ends. The tools here are stand-ins that answer as the
//! real ones do and note how they were called; the last test asks a real
//! restic (`cargo test -p garrison --test backup_check -- --ignored`).

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

// The tests of one part, beside this crate's root.
#[path = "backup_check/case.rs"]
mod case;
#[path = "backup_check/repositories.rs"]
mod repositories;
#[path = "backup_check/spellings.rs"]
mod spellings;
#[path = "backup_check/stand_in.rs"]
mod stand_in;
#[path = "backup_check/turns.rs"]
mod turns;

use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};
use stand_in::{REPOSITORY_ID, Tools, read, timeless};
use support::{finished, text};

#[test]
fn restic_is_asked_without_a_lock_and_the_report_keeps_the_last_check() {
    let tools = Tools::new();
    let report = tools.report("restic");
    let to = report.to_str().unwrap();
    let all = tools.run(
        &[
            "restic",
            "--repo",
            "/srv/repo",
            "--verify",
            "--restore",
            "/etc/hosts",
            "--report",
            to,
        ],
        None,
    );
    assert_eq!(all.status.code(), Some(0), "{}", text(&all.stderr));
    assert_eq!(
        text(&all.stdout),
        format!(
            "restic: 2 snapshots, the newest of 2026-11-11T02:00:04+00:00.\n\
             Integrity check: passed (no errors were found)\n\
             Restore test: passed (/etc/hosts: 1 files, 8 bytes)\n\
             Report written to {to}.\n"
        )
    );
    // Listing and measuring take no lock, so they never wait for a backup
    // that runs; the restore goes to a directory of its own, which is gone.
    let calls = tools.calls();
    assert_eq!(
        calls[..4],
        [
            "restic TZ=unset -r /srv/repo snapshots --json --no-lock",
            "restic TZ=unset -r /srv/repo stats --json --mode raw-data --no-lock",
            "restic TZ=unset -r /srv/repo cat config --no-lock",
            "restic TZ=unset -r /srv/repo check",
        ]
    );
    let restore: Vec<&str> = calls[4].split(' ').collect();
    assert_eq!(
        [&restore[..8], &restore[9..]].concat(),
        [
            "restic",
            "TZ=unset",
            "-r",
            "/srv/repo",
            "restore",
            "latest",
            "--no-lock",
            "--target",
            "--include",
            "/etc/hosts",
        ]
    );
    assert!(
        restore[8].starts_with("/var/tmp/garrison-restore-"),
        "{}",
        restore[8]
    );
    assert!(!Path::new(restore[8]).exists());
    let complete = json!({
        "tool": "restic", "repository": "/srv/repo", "repositoryId": REPOSITORY_ID, "problem": null,
        "snapshots": {"count": 2, "newest": "2026-11-11T02:00:04+00:00", "sizeBytes": 300_006},
        "verify": {"ok": true, "detail": "no errors were found"},
        "restore": {"ok": true, "detail": "/etc/hosts: 1 files, 8 bytes"},
    });
    assert_eq!(timeless(read(&report)), complete);
    let checked = read(&report)["verify"]["at"].clone();

    // The daily run only lists: the last check and restore stay in the report.
    let listed = tools.run(&["restic", "--repo", "/srv/repo", "--report", to], None);
    assert_eq!(listed.status.code(), Some(0));
    assert_eq!(tools.calls().len(), 3);
    assert_eq!(timeless(read(&report)), complete);
    assert_eq!(read(&report)["verify"]["at"], checked);
}

#[test]
fn what_restic_fails_at_ends_the_command_with_its_last_word() {
    let tools = Tools::new();
    let report = tools.report("restic");
    let to = report.to_str().unwrap();
    let whole = tools.run(
        &[
            "restic",
            "--repo",
            "/srv/repo",
            "--verify",
            "--restore",
            "/etc/hosts",
            "--report",
            to,
        ],
        None,
    );
    assert_eq!(whole.status.code(), Some(0));
    tools.calls();

    // A check that fails ends the command with 1 and names the tool's last word.
    let damaged = tools.run(
        &["restic", "--repo", "/srv/repo", "--verify", "--report", to],
        Some("check"),
    );
    assert_eq!(damaged.status.code(), Some(1));
    assert_eq!(
        read(&report)["verify"]["detail"],
        "Fatal: the repository is locked by another process"
    );
    assert_eq!(read(&report)["verify"]["ok"], false);
    assert_eq!(read(&report)["restore"]["ok"], true);
    assert_eq!(tools.calls().len(), 4);

    // A repository that cannot be listed: no snapshots are claimed, and
    // neither check nor restore is tried.
    let locked = tools.run(
        &[
            "restic",
            "--repo",
            "/srv/repo",
            "--verify",
            "--restore",
            "/etc/hosts",
            "--report",
            to,
        ],
        Some("snapshots"),
    );
    assert_eq!(locked.status.code(), Some(1));
    assert!(
        text(&locked.stderr).contains("restic did not list its snapshots: Fatal: the repository"),
        "{}",
        text(&locked.stderr)
    );
    assert_eq!(tools.calls().len(), 1);
    let after = read(&report);
    assert_eq!(after["snapshots"], Value::Null);
    assert_eq!(
        after["problem"],
        "Fatal: the repository is locked by another process"
    );

    // A path the newest snapshot does not hold restores nothing.
    let missing = tools.run(
        &[
            "restic",
            "--repo",
            "/srv/repo",
            "--restore",
            "/etc/hosts",
            "--report",
            to,
        ],
        Some("restore"),
    );
    assert_eq!(missing.status.code(), Some(1));
    assert_eq!(read(&report)["restore"]["ok"], false);
}

#[test]
fn borg_runs_in_utc_and_restores_from_its_newest_archive() {
    let tools = Tools::new();
    let report = tools.report("borg");
    let to = report.to_str().unwrap();
    let all = tools.run(
        &[
            "borg",
            "--repo",
            "/srv/borg",
            "--verify",
            "--restore",
            "/etc/hosts",
            "--report",
            to,
        ],
        None,
    );
    assert_eq!(all.status.code(), Some(0), "{}", text(&all.stderr));
    assert!(text(&all.stdout).starts_with(
        "borg: 2 archives, the newest of 2026-11-11T02:00:04+00:00.\n\
         Integrity check: passed (no problems found)\n"
    ));
    // borg writes its times in the zone it runs in, restores into the
    // directory it runs in, and names paths without their first slash.
    assert_eq!(
        tools.calls(),
        [
            "borg TZ=UTC list --json /srv/borg",
            "borg TZ=UTC info --json /srv/borg",
            "borg TZ=UTC check /srv/borg",
            "borg TZ=UTC extract /srv/borg::host-2026-11-11 etc/hosts",
        ]
    );
    assert_eq!(
        timeless(read(&report)),
        json!({
            "tool": "borg", "repository": "/srv/borg", "repositoryId": REPOSITORY_ID, "problem": null,
            "snapshots": {"count": 2, "newest": "2026-11-11T02:00:04+00:00", "sizeBytes": 4096},
            "verify": {"ok": true, "detail": "no problems found"},
            "restore": {"ok": true, "detail": "/etc/hosts: 1 files, 8 bytes"},
        })
    );
    // Without --repo borg reads its own environment, and nothing is added.
    let own = tools.run(&["borg", "--report", to], None);
    assert_eq!(own.status.code(), Some(0));
    assert_eq!(
        tools.calls(),
        ["borg TZ=UTC list --json", "borg TZ=UTC info --json"]
    );
    assert_eq!(
        read(&report)["repository"],
        "(named in the tool's own configuration)"
    );
}

#[test]
fn another_tool_or_a_place_that_cannot_be_written_ends_the_command() {
    let tools = Tools::new();
    let other = tools.run(&["tar"], None);
    assert_eq!(other.status.code(), Some(2));
    assert!(text(&other.stderr).contains("The backup tool is restic or borg."));
    assert_eq!(tools.calls(), Vec::<String>::new());
    let nowhere = tools.run(
        &[
            "restic",
            "--repo",
            "/srv/repo",
            "--report",
            "/proc/garrison/restic.json",
        ],
        None,
    );
    assert_eq!(nowhere.status.code(), Some(1));
    assert_eq!(
        text(&nowhere.stderr),
        "The report's folder /proc/garrison cannot be made: No such file or directory (os error \
         2).\n"
    );
    assert_eq!(tools.calls(), Vec::<String>::new());
    // A folder at the report's name takes no report.
    let folder = tools.report("restic");
    std::fs::create_dir(&folder).unwrap();
    let to = folder.to_str().unwrap();
    let taken = tools.run(&["restic", "--repo", "/srv/repo", "--report", to], None);
    assert_eq!(taken.status.code(), Some(1));
    assert!(
        text(&taken.stderr).contains(&format!("The report could not be written to {to}: ")),
        "{}",
        text(&taken.stderr)
    );
}

/// The report the last run wrote is read as the collector reads it: no link
/// is followed, nothing but a regular file is opened, and no more than a
/// report's size is read. What is not such a file keeps no check, and the
/// run writes its report in its place.
#[test]
fn the_last_report_is_read_only_from_a_file_of_its_own() {
    let tools = Tools::new();
    let report = tools.report("restic");
    let to = report.to_str().unwrap();
    let checked = tools.run(&["restic", "--verify", "--report", to], None);
    assert_eq!(checked.status.code(), Some(0), "{}", text(&checked.stderr));
    let elsewhere = tools.directory.path().join("elsewhere.json");
    std::fs::rename(&report, &elsewhere).unwrap();
    let mut large = read(&elsewhere);
    large["problem"] = json!("p".repeat(256 * 1024));
    let place = |what: &str| match what {
        "link" => std::os::unix::fs::symlink(&elsewhere, &report).unwrap(),
        "pipe" => rustix::fs::mknodat(
            rustix::fs::CWD,
            &report,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap(),
        _ => std::fs::write(&report, large.to_string()).unwrap(),
    };
    for what in ["link", "pipe", "a file larger than a report"] {
        place(what);
        let listed = tools.run(&["restic", "--report", to], None);
        assert_eq!(listed.status.code(), Some(0), "{what}");
        assert_eq!(
            text(&listed.stderr),
            format!(
                "The last report, {to}, cannot be read: it must be a file, not a link, of at \
                 most 256 KiB of valid JSON. Its last integrity check and test restore are \
                 not kept.\n"
            ),
            "{what}"
        );
        let written = std::fs::symlink_metadata(&report).unwrap();
        assert!(written.file_type().is_file(), "{what}");
        assert_eq!(read(&report)["verify"], Value::Null, "{what}");
        std::fs::remove_file(&report).unwrap();
    }
    // The file the link named is as it was.
    assert_eq!(read(&elsewhere)["verify"]["ok"], true);
}

/// A repository of the real restic with two snapshots of a small directory.
#[test]
#[ignore = "needs restic on the PATH"]
fn a_real_restic_repository_is_listed_checked_and_restored() {
    let directory = tempfile::tempdir().unwrap();
    let (repo, data) = (directory.path().join("repo"), directory.path().join("data"));
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("letter.txt"), "A letter.\n").unwrap();
    std::fs::write(data.join("numbers.bin"), vec![7u8; 100_000]).unwrap();
    let restic = |arguments: &[&str]| {
        let output = finished(
            Command::new("restic")
                .arg("-r")
                .arg(&repo)
                .args(arguments)
                .env("RESTIC_PASSWORD", "only-for-this-test"),
        );
        assert!(
            output.status.success(),
            "restic {arguments:?}: {}",
            text(&output.stderr)
        );
    };
    restic(&["init"]);
    let source = data.to_str().unwrap();
    restic(&["backup", source]);
    restic(&["backup", source]);
    let report = directory.path().join("restic.json");
    let ran = finished(
        Command::new(env!("CARGO_BIN_EXE_garrison"))
            .args([
                "backup-check",
                "restic",
                "--verify",
                "--restore",
                source,
                "--report",
            ])
            .arg(&report)
            // As a backup job names its repository: in the environment.
            .env("RESTIC_REPOSITORY", &repo)
            .env("RESTIC_PASSWORD", "only-for-this-test"),
    );
    assert_eq!(
        ran.status.code(),
        Some(0),
        "{}{}",
        text(&ran.stdout),
        text(&ran.stderr)
    );
    let written = read(&report);
    assert_eq!(written["repository"], repo.to_str().unwrap());
    let id = written["repositoryId"].as_str().unwrap();
    assert!(
        id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{id}"
    );
    assert_eq!(written["snapshots"]["count"], 2);
    assert!(written["snapshots"]["newest"].is_string());
    // What is stored is less than the data: the second file compresses.
    let size = written["snapshots"]["sizeBytes"].as_u64().unwrap();
    assert!(size > 0 && size < 100_000, "{size}");
    assert_eq!(written["verify"]["ok"], true, "{written}");
    assert_eq!(written["verify"]["detail"], "no errors were found");
    assert_eq!(
        written["restore"]["detail"],
        format!("{source}: 2 files, 100010 bytes")
    );
    // The password is nowhere in the report.
    assert!(!written.to_string().contains("only-for-this-test"));
}
