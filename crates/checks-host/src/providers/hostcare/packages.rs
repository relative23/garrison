//! Asking the host's package manager for the updates it would install.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::UNIX_EPOCH;

use super::reading::{self, Pending};
use crate::command::Runner;

/// What changes when packages are installed or removed or new metadata is
/// fetched: rpm's and dpkg's databases and apt's package cache. The
/// `repomd.xml` of each repository in dnf's cache comes on top.
const CHANGES: [&str; 7] = [
    "var/lib/rpm/rpmdb.sqlite",
    "var/lib/rpm/rpmdb.sqlite-wal",
    "var/lib/rpm/Packages",
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "usr/lib/sysimage/rpm/rpmdb.sqlite-wal",
    "var/lib/dpkg/status",
    "var/cache/apt/pkgcache.bin",
];

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
            .map_err(|error| format!("{} did not run: {error}", arguments[0]))
    };
    if has("apt-get") {
        let simulated = run(&["apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"]);
        let listed = simulated.and_then(|output| {
            if output.code == Some(0) {
                Ok(reading::apt(&output.stdout))
            } else {
                Err("apt-get could not work out the upgrade".to_owned())
            }
        });
        ("apt-get -s upgrade".to_owned(), listed)
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

/// What to tell when unreadable cache folders are why dnf failed.
fn locked_out(repositories: &[String]) -> Option<String> {
    let (last, rest) = repositories.split_last()?;
    let (names, folder, them) = if rest.is_empty() {
        (last.clone(), "folder", "it")
    } else {
        (format!("{} and {last}", rest.join(", ")), "folders", "them")
    };
    Some(format!(
        "only root may read the dnf cache {folder} of {names} in /var/cache/dnf; \
         chmod 755 on {them} lets this check read {them}"
    ))
}
