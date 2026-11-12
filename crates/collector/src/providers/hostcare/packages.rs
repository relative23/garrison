//! Asking the host's package manager for the updates it would install.

use std::path::Path;

use super::reading::{self, Pending};
use crate::command::Runner;

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
                return Err("dnf could not list the security updates".to_owned());
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
