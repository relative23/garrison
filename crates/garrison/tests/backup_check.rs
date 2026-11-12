//! `garrison backup-check`: what it asks restic and borg, what it writes
//! down, and how it ends. The tools here are stand-ins that answer as the
//! real ones do and note how they were called; the last test asks a real
//! restic (`cargo test -p garrison --test backup_check -- --ignored`).

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use support::{finished, text};

/// restic and borg as far as the command asks them. `BROKEN` names a step
/// that fails; every call is noted in `CALLS` with borg's time zone.
const STAND_IN: &str = r#"#!/bin/sh
tool=$(basename "$0")
echo "$tool TZ=${TZ-unset} $*" >> "$CALLS"
for word in "$@"; do
    case $word in snapshots | stats | check | restore | list | info | extract) verb=$word; break ;; esac
done
if [ "${BROKEN-}" = "$verb" ]; then
    echo "progress that is not the last word"
    echo "Fatal: the repository is locked by another process" >&2
    exit 1
fi
case $tool-$verb in
    restic-snapshots)
        printf '%s' '[{"time":"2026-11-10T02:00:03.839457992Z","paths":["/srv"],"id":"c92ca1cc","short_id":"c92ca1cc"},
            {"time":"2026-11-11T02:00:04.601910362Z","paths":["/srv"],"id":"0039082a","short_id":"0039082a"}]' ;;
    restic-stats) printf '{"total_size":300006,"snapshots_count":2}' ;;
    restic-check) echo "check all packs"; echo "no errors were found" ;;
    restic-restore)
        while [ $# -gt 0 ]; do
            case $1 in --target) target=$2 ;; --include) path=$2 ;; esac
            shift
        done
        mkdir -p "$target$(dirname "$path")" && printf 'restored' > "$target$path" ;;
    borg-list)
        printf '%s' '{"archives":[{"name":"host-2026-11-11","time":"2026-11-11T02:00:04.000000"},
            {"name":"host-2026-11-10","time":"2026-11-10T02:00:03.000000"}],"repository":{"id":"1f"}}' ;;
    borg-info) printf '{"cache":{"stats":{"unique_csize":4096,"total_size":9000}}}' ;;
    borg-check) ;;
    borg-extract) mkdir -p "$(dirname "$3")" && printf 'restored' > "$3" ;;
    *) echo "unexpected call: $*" >&2; exit 64 ;;
esac
"#;

/// A directory with both stand-ins, first in the search path of a run.
struct Tools {
    directory: tempfile::TempDir,
}

impl Tools {
    fn new() -> Tools {
        let directory = tempfile::tempdir().unwrap();
        for name in ["restic", "borg"] {
            let path = directory.path().join(name);
            std::fs::write(&path, STAND_IN).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Tools { directory }
    }

    fn report(&self, tool: &str) -> PathBuf {
        self.directory.path().join(format!("{tool}.json"))
    }

    /// One run of the command with `arguments`, and with `broken` failing.
    fn run(&self, arguments: &[&str], broken: Option<&str>) -> Output {
        let path = format!(
            "{}:{}",
            self.directory.path().display(),
            std::env::var("PATH").unwrap()
        );
        let mut command = Command::new(env!("CARGO_BIN_EXE_garrison"));
        command
            .arg("backup-check")
            .args(arguments)
            .env("PATH", path)
            .env("CALLS", self.directory.path().join("calls"))
            .env_remove("RESTIC_REPOSITORY")
            .env_remove("BORG_REPO")
            .env_remove("TZ");
        if let Some(broken) = broken {
            command.env("BROKEN", broken);
        }
        finished(&mut command)
    }

    /// How the stand-ins were called since the last look.
    fn calls(&self) -> Vec<String> {
        let path = self.directory.path().join("calls");
        let noted = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        noted.lines().map(str::to_owned).collect()
    }
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// A report without the times of the run that wrote it.
fn timeless(mut report: Value) -> Value {
    for part in ["snapshots", "verify", "restore"] {
        if let Some(part) = report[part].as_object_mut() {
            assert!(part.remove("at").is_some());
        }
    }
    report
}

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
        calls[..3],
        [
            "restic TZ=unset -r /srv/repo snapshots --json --no-lock",
            "restic TZ=unset -r /srv/repo stats --json --mode raw-data --no-lock",
            "restic TZ=unset -r /srv/repo check",
        ]
    );
    let restore: Vec<&str> = calls[3].split(' ').collect();
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
        "tool": "restic", "repository": "/srv/repo", "problem": null,
        "snapshots": {"count": 2, "newest": "2026-11-11T02:00:04+00:00", "sizeBytes": 300_006},
        "verify": {"ok": true, "detail": "no errors were found"},
        "restore": {"ok": true, "detail": "/etc/hosts: 1 files, 8 bytes"},
    });
    assert_eq!(timeless(read(&report)), complete);
    let checked = read(&report)["verify"]["at"].clone();

    // The daily run only lists: the last check and restore stay in the report.
    let listed = tools.run(&["restic", "--repo", "/srv/repo", "--report", to], None);
    assert_eq!(listed.status.code(), Some(0));
    assert_eq!(tools.calls().len(), 2);
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
    assert_eq!(tools.calls().len(), 3);

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
            "tool": "borg", "repository": "/srv/borg", "problem": null,
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
    assert!(
        text(&nowhere.stderr).contains("The report could not be written to /proc/garrison/"),
        "{}",
        text(&nowhere.stderr)
    );
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
