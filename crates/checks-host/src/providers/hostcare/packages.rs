//! Asking the host's package manager for the updates it would install.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::UNIX_EPOCH;
use std::{fs, io};

use super::reading::{self, Pending};
use crate::command::Runner;
use crate::providers::ran::not_run;

/// What changes when packages are installed or removed or new metadata is
/// fetched: rpm's and dpkg's databases, apt's package cache and the folder
/// of its package lists, where an image may keep no cache. The
/// `repomd.xml` of each repository in dnf's cache comes on top.
const CHANGES: [&str; 8] = [
    "var/lib/rpm/rpmdb.sqlite",
    "var/lib/rpm/rpmdb.sqlite-wal",
    "var/lib/rpm/Packages",
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "usr/lib/sysimage/rpm/rpmdb.sqlite-wal",
    "var/lib/dpkg/status",
    "var/cache/apt/pkgcache.bin",
    APT_LISTS,
];

/// Where apt keeps the package lists that `apt-get update` fetches.
const APT_LISTS: &str = "var/lib/apt/lists";

const DNF: [&str; 5] = [
    "dnf",
    "-q",
    "-C",
    "--setopt=cachedir=/var/cache/dnf",
    "--setopt=logdir=/tmp",
];

/// The package manager's own list, read from the metadata it has: no lock is
/// taken and nothing is fetched. With it, what the list was read from.
pub(super) fn pending(root: &Path, runner: &dyn Runner) -> (String, Result<Pending, String>) {
    let has = |program: &str| root.join("usr/bin").join(program).exists();
    let run = |arguments: &[&str]| {
        runner
            .run(arguments)
            .map_err(|error| not_run(arguments[0], &error))
    };
    if has("apt-get") {
        let source = "apt-get -s dist-upgrade".to_owned();
        // Without lists apt answers "0 upgraded", from nothing it knows of.
        if let Err(problem) = apt_lists(root) {
            return (source, Err(problem));
        }
        // A full upgrade: plain `upgrade` keeps back every update that needs
        // a package not installed yet, as each kernel with a new ABI does,
        // and prints no line for it (measured on Debian 13 and Ubuntu 24.04).
        let simulated = run(&[
            "apt-get",
            "-s",
            "-o",
            "Debug::NoLocking=true",
            "dist-upgrade",
        ]);
        let listed = simulated.and_then(|output| {
            if output.code == Some(0) {
                Ok(reading::apt(&output.stdout))
            } else {
                Err("apt-get could not work out the upgrade".to_owned())
            }
        });
        (source, listed)
    } else if has("dnf5") {
        let problem = "this check does not read dnf 5 yet".to_owned();
        ("dnf".to_owned(), Err(problem))
    } else if has("dnf") {
        // An unprivileged user reads the system's cache; its own would be empty.
        let security = [&DNF[..], &["updateinfo", "list", "--security", "--updates"]].concat();
        let every = [&DNF[..], &["check-update"]].concat();
        let listed = run(&security).and_then(|output| {
            if output.code != Some(0) {
                return Err(locked_out(&unreadable(root))
                    .unwrap_or_else(|| "dnf could not list the security updates".to_owned()));
            }
            let security = reading::dnf_security(&output.stdout);
            // 100 says that updates exist, 0 that none do.
            let every = run(&every)?;
            if !matches!(every.code, Some(0 | 100)) {
                return Err("dnf could not list the updates".to_owned());
            }
            Ok(Pending {
                security,
                other: reading::dnf_updates(&every.stdout).saturating_sub(security),
            })
        });
        ("dnf updateinfo, from its cache".to_owned(), listed)
    } else {
        let problem = "no package manager this check reads was found (apt, dnf 4)".to_owned();
        ("package manager".to_owned(), Err(problem))
    }
}

/// Whether apt has fetched a package list, a file of a repository's packages
/// (`…_Packages`, or compressed, `…_Packages.lz4`), and why not.
fn apt_lists(root: &Path) -> Result<(), String> {
    let missing = || {
        format!(
            "apt has no package lists in /{APT_LISTS}; `apt-get update` fetches them, as the \
             host's update job does"
        )
    };
    let entries = match fs::read_dir(root.join(APT_LISTS)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(missing()),
        Err(error) => {
            return Err(format!(
                "apt's package lists in /{APT_LISTS} cannot be read: {error}"
            ));
        }
        Ok(entries) => entries,
    };
    let mut entries = entries.flatten();
    if entries.any(|entry| entry.file_name().to_string_lossy().contains("_Packages")) {
        Ok(())
    } else {
        Err(missing())
    }
}

/// When the installed packages or the metadata fetched for them last
/// changed, in seconds since the epoch.
pub(super) fn last_change(root: &Path) -> Option<i64> {
    let repositories = fs::read_dir(root.join("var/cache/dnf"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path().join("repodata/repomd.xml"));
    CHANGES
        .iter()
        .map(|path| root.join(path))
        .chain(repositories)
        .filter_map(|path| {
            fs::metadata(path)
                .and_then(|metadata| metadata.modified())
                .ok()
        })
        .filter_map(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .filter_map(|since| i64::try_from(since.as_secs()).ok())
        .max()
}

/// Where apt notes each time it fetches its package lists, or tries to: the
/// folder it fetches them into, which `apt-get update` and apt-daily's
/// update write in also where the servers cannot be reached; the lists keep
/// the servers' times (measured on Debian 13).
const APT_TRIED: &str = "var/lib/apt/lists/partial";
/// Where dnf notes each refresh of its metadata, also one that cannot reach
/// the mirrors; `repomd.xml` keeps the time it last changed (measured on
/// `AlmaLinux` 10).
const DNF_TRIED: &str = "var/cache/dnf/expired_repos.json";
/// Metadata that its package manager has not fetched for this long is out
/// of date: the distributions' own jobs fetch at least daily, and Debian
/// signs its security suite for a week.
const WEEK: i64 = 7 * 86_400;

/// Why the metadata that the pending updates are counted from is out of
/// date at `now`, the seconds since the epoch, where it is: a list of
/// apt's has expired, or the package manager has not fetched its metadata,
/// nor tried to, for a week.
pub(super) fn stale(root: &Path, now: i64) -> Option<String> {
    let (manager, tried, mends) = if root.join("usr/bin/apt-get").exists() {
        if let Some(expired) = expired(root, now) {
            return Some(expired);
        }
        (
            "apt has not fetched its package lists",
            APT_TRIED,
            "`apt-get update` fetches them, as the host's update job does",
        )
    } else {
        (
            "dnf has not refreshed its metadata",
            DNF_TRIED,
            "`dnf makecache` refreshes it, as the dnf-makecache timer does",
        )
    };
    let tried = fs::metadata(root.join(tried))
        .and_then(|metadata| metadata.modified())
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_secs()).ok())?;
    let age = now.saturating_sub(tried);
    (age >= WEEK).then(|| {
        let days = age / 86_400;
        format!("{manager} for {days} days, so updates published since are not counted: {mends}.")
    })
}

/// What apt says of a list it fetched whose `Valid-Until` is before `now`:
/// one it could not fetch again, however often it tried.
fn expired(root: &Path, now: i64) -> Option<String> {
    let entries = fs::read_dir(root.join(APT_LISTS)).ok()?;
    let mut lists: Vec<(String, String)> = entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with("_InRelease") || name.ends_with("_Release"))
        .filter_map(|name| {
            let mut head = String::new();
            // The fields come before the list of files; a head is enough.
            fs::File::open(root.join(APT_LISTS).join(&name))
                .and_then(|file| file.take(4096).read_to_string(&mut head))
                .ok()?;
            let valid = head
                .lines()
                .find_map(|line| line.strip_prefix("Valid-Until: "))?;
            (reading::release_date(valid)? < now).then(|| (name, valid.trim().to_owned()))
        })
        .collect();
    lists.sort();
    let (name, valid) = lists.into_iter().next()?;
    Some(format!(
        "apt's list {name} expired on {valid}, so updates published since are not counted: \
         `apt-get update` says why apt could not fetch it again."
    ))
}

/// The repositories whose folder in dnf's cache only root may read. Made
/// under umask 077, one such folder keeps an unprivileged reader like this
/// check out, and dnf then answers nothing at all.
pub(super) fn unreadable(root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(root.join("var/cache/dnf")) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|entry| {
            entry.metadata().is_ok_and(|metadata| {
                metadata.is_dir() && metadata.permissions().mode() & 0o005 != 0o005
            })
        })
        .map(|entry| repository(&entry.file_name().to_string_lossy()))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// `epel-74fe7744c98fc60d`, a folder in dnf's cache, holds the repository `epel`.
fn repository(folder: &str) -> String {
    folder
        .rsplit_once('-')
        .filter(|(_, hash)| hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map_or(folder, |(name, _)| name)
        .to_owned()
}

/// What to tell when unreadable cache folders are why dnf failed. Under
/// umask 077 dnf makes the files in them as closed as the folders, so only
/// the cache made again under the default umask mends it (measured,
/// 2026-11-24).
fn locked_out(repositories: &[String]) -> Option<String> {
    let (last, rest) = repositories.split_last()?;
    let (names, folder) = if rest.is_empty() {
        (last.clone(), "folder")
    } else {
        (format!("{} and {last}", rest.join(", ")), "folders")
    };
    Some(format!(
        "only root may read the dnf cache {folder} of {names} in /var/cache/dnf: make the cache \
         again under umask 022 (dnf clean all; umask 022; dnf makecache)"
    ))
}
