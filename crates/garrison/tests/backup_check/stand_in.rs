//! restic and borg as stand-ins that answer as the real ones do and note
//! how they were called, and what the tests read of a report.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

use super::support::finished;

/// restic and borg as far as the command asks them. `BROKEN` names a step
/// that fails; every call is noted in `CALLS` with borg's time zone.
/// `REPO_ID` is the ID the repository has, whatever its name; empty, none.
/// borg's listing reports the repository's location in borg's own form,
/// as its documentation of `--json` gives it: `user@host:repo` and
/// `ssh://user@host/./repo` alike.
pub(super) const STAND_IN: &str = r#"#!/bin/sh
tool=$(basename "$0")
echo "$tool TZ=${TZ-unset} $*" >> "$CALLS"
for word in "$@"; do
    case $word in snapshots | stats | check | restore | list | info | extract | cat) verb=$word; break ;; esac
done
id=${REPO_ID-5e1f0c3a9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f}
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
    restic-cat) printf '{"version":2,"id":"%s","chunker_polynomial":"27e6426c4ae9ff"}' "$id" ;;
    restic-check) echo "check all packs"; echo "no errors were found" ;;
    restic-restore)
        while [ $# -gt 0 ]; do
            case $1 in --target) target=$2 ;; --include) path=$2 ;; esac
            shift
        done
        mkdir -p "$target$(dirname "$path")" && printf 'restored' > "$target$path" ;;
    borg-list)
        repo=${BORG_REPO-}
        for word in "$@"; do case $word in list | --json) ;; *) repo=$word ;; esac; done
        # The location borg reports: a folder here as given, one elsewhere as ssh://.
        case $repo in
            ssh://* | /*) location=$repo ;;
            file://*) location=${repo#file://} ;;
            *:*) path=${repo#*:}
                 case $path in /*) ;; "~"*) path=/$path ;; *) path=/./$path ;; esac
                 location=ssh://${repo%%:*}$path ;;
            *) location=$repo ;;
        esac
        where=${location:+,\"location\":\"$location\"}
        printf '{"archives":[{"name":"host-2026-11-11","time":"2026-11-11T02:00:04.000000"},
            {"name":"host-2026-11-10","time":"2026-11-10T02:00:03.000000"}],"repository":{"id":"%s"%s}}' "$id" "$where" ;;
    borg-info) printf '{"cache":{"stats":{"unique_csize":4096,"total_size":9000}}}' ;;
    borg-check) ;;
    borg-extract) mkdir -p "$(dirname "$3")" && printf 'restored' > "$3" ;;
    *) echo "unexpected call: $*" >&2; exit 64 ;;
esac
"#;

/// The ID the stand-ins give the repository where `REPO_ID` gives none.
pub(super) const REPOSITORY_ID: &str =
    "5e1f0c3a9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f";

/// A directory with both stand-ins, first in the search path of a run.
pub(super) struct Tools {
    pub(super) directory: tempfile::TempDir,
}

impl Tools {
    pub(super) fn new() -> Tools {
        let directory = tempfile::tempdir().unwrap();
        for name in ["restic", "borg"] {
            let path = directory.path().join(name);
            std::fs::write(&path, STAND_IN).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Tools { directory }
    }

    pub(super) fn report(&self, tool: &str) -> PathBuf {
        self.directory.path().join(format!("{tool}.json"))
    }

    /// One run of the command with `arguments`, and with `broken` failing.
    pub(super) fn run(&self, arguments: &[&str], broken: Option<&str>) -> Output {
        let broken: Vec<(&str, &str)> = broken.map(|step| ("BROKEN", step)).into_iter().collect();
        self.run_with(arguments, &broken)
    }

    /// One run of the command with `arguments` in an environment that holds
    /// `environment` besides the stand-ins, as a backup job's unit gives it.
    pub(super) fn run_with(&self, arguments: &[&str], environment: &[(&str, &str)]) -> Output {
        finished(&mut self.command(arguments, environment))
    }

    /// The command that `run_with` runs, for a run that needs more of it.
    pub(super) fn command(&self, arguments: &[&str], environment: &[(&str, &str)]) -> Command {
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
            .env_remove("RESTIC_REPOSITORY_FILE")
            .env_remove("BORG_REPO")
            .env_remove("TZ")
            .envs(environment.iter().copied());
        command
    }

    /// How the stand-ins were called since the last look.
    pub(super) fn calls(&self) -> Vec<String> {
        let path = self.directory.path().join("calls");
        let noted = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        noted.lines().map(str::to_owned).collect()
    }
}

pub(super) fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// A report without the times of the run that wrote it.
pub(super) fn timeless(mut report: Value) -> Value {
    for part in ["snapshots", "verify", "restore"] {
        if let Some(part) = report[part].as_object_mut() {
            assert!(part.remove("at").is_some());
        }
    }
    report
}
