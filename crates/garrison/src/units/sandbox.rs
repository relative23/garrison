//! What the sandboxes of Garrison's units hide from their services:
//! root reads a file there, and the service never does.

use std::path::{Path, PathBuf};

use garrison_collector::Provider;
use garrison_collector::context::{HostPath, Use};
use garrison_core::config;

use super::{BROKER, COLLECT};

/// The places `garrison-broker.service` and `garrison-collect.service` hide
/// from their services, each with the setting that does, as a container
/// showed them (systemd 257): inaccessible (`ProtectHome=true`, and for the
/// kernel's own files `ProtectKernelModules=true`, `ProtectKernelTunables=true`
/// and `ProtectKernelLogs=true`), or the service's own and empty
/// (`PrivateTmp=true`, and `PrivateDevices=true` for `/dev`, into which
/// systemd still binds the host's `/dev/shm` and `/dev/mqueue`). The third
/// value says that the service's own place lies on the file system of the
/// host's, so that statvfs there measures that one. Which of these each
/// unit sets: [`BROKER_SETS`], [`COLLECT_SETS`].
const HIDDEN: [(&str, &str, bool); 11] = [
    ("/home", "ProtectHome=true", false),
    ("/root", "ProtectHome=true", false),
    ("/run/user", "ProtectHome=true", false),
    ("/tmp", "PrivateTmp=true", true),
    ("/var/tmp", "PrivateTmp=true", true),
    ("/dev", "PrivateDevices=true", false),
    ("/lib/modules", "ProtectKernelModules=true", false),
    ("/usr/lib/modules", "ProtectKernelModules=true", false),
    ("/proc/kallsyms", "ProtectKernelTunables=true", false),
    ("/proc/kcore", "ProtectKernelTunables=true", false),
    ("/proc/kmsg", "ProtectKernelLogs=true", false),
];
const DEV_SHARED: [&str; 2] = ["/dev/shm", "/dev/mqueue"];
/// The settings of [`HIDDEN`] that `garrison-broker.service` sets.
const BROKER_SETS: [&str; 6] = [
    "ProtectHome=true",
    "PrivateTmp=true",
    "PrivateDevices=true",
    "ProtectKernelModules=true",
    "ProtectKernelTunables=true",
    "ProtectKernelLogs=true",
];
/// Those that `garrison-collect.service` sets: not `ProtectKernelModules=`,
/// which hid the installed kernels from host care's restart check.
const COLLECT_SETS: [&str; 5] = [
    "ProtectHome=true",
    "PrivateTmp=true",
    "PrivateDevices=true",
    "ProtectKernelTunables=true",
    "ProtectKernelLogs=true",
];

/// The settings of [`HIDDEN`] that any of Garrison's service units sets.
/// Each starts its service from the release, which none of them may hide.
const ANY_SETS: [&str; 6] = [
    "ProtectHome=true",
    "PrivateTmp=true",
    "PrivateDevices=true",
    "ProtectKernelModules=true",
    "ProtectKernelTunables=true",
    "ProtectKernelLogs=true",
];

/// The place that a unit with the settings `sets` hides and that holds
/// `path`, the setting that hides it and whether statvfs there measures the
/// host's file system.
fn hidden_place(path: &Path, sets: &[&str]) -> Option<(&'static str, &'static str, bool)> {
    if DEV_SHARED.iter().any(|shared| path.starts_with(shared)) {
        return None;
    }
    HIDDEN
        .into_iter()
        .find(|(place, setting, _)| sets.contains(setting) && path.starts_with(place))
}

/// Why the broker's unit keeps it from reading the policy at `policy`, and
/// what to do; `None` where it reads it there. `resolved` is the same path
/// with the links of its folders followed, as the broker's open follows
/// them: either path in a hidden place hides the file.
fn hidden_at(policy: &Path, resolved: Option<&Path>) -> Option<(String, String)> {
    let (hidden, (place, setting, _)) = hidden_place(policy, &BROKER_SETS)
        .map(|found| (policy, found))
        .or_else(|| resolved.and_then(|path| Some((path, hidden_place(path, &BROKER_SETS)?))))?;
    let through = if hidden == policy {
        String::new()
    } else {
        format!(", which leads to {}", hidden.display())
    };
    Some((
        format!(
            "broker.policy is {}{through}, under {place}, which {BROKER} hides from the broker \
             ({setting}): the broker cannot read it there, and nobody can sign in",
            policy.display()
        ),
        "Keep the policy where the broker sees it, such as /etc/garrison/access-policy.json, \
         and name that in broker.policy"
            .to_owned(),
    ))
}

/// [`hidden_at`] for the policy at `policy`.
pub(crate) fn hidden_policy(policy: &Path) -> Option<(String, String)> {
    let resolved = policy
        .parent()
        .and_then(|folder| std::fs::canonicalize(folder).ok())
        .zip(policy.file_name())
        .map(|(folder, name)| folder.join(name));
    hidden_at(policy, resolved.as_deref())
}

/// What check-config says of a policy the broker's unit hides: a refusal
/// (`Err`) for the configuration the units read, since they start every
/// service with the default file, and a warning for any other, such as a
/// draft's or a test's, which no unit runs.
pub(crate) fn policy_place(policy: &Path, configuration: &Path) -> Result<Option<String>, String> {
    let Some((what, fix)) = hidden_policy(policy) else {
        return Ok(None);
    };
    let said = format!("{what}. {fix}.");
    if configuration == Path::new(config::DEFAULT_PATH) {
        Err(said)
    } else {
        Ok(Some(said))
    }
}

/// Why the collector's unit keeps the check of type `kind` from the path one
/// of its options names, and what to do; `None` where the collector sees it.
/// `resolved` is the same path with its links followed, as the check's
/// open, exec or statvfs follows them: either path in a hidden place hides
/// it. The service's own `/tmp` and `/var/tmp` lie on the host's file
/// systems, so statvfs of exactly those measures the right one.
fn hidden_check(
    kind: &str,
    host: &HostPath<'_>,
    resolved: Option<&Path>,
) -> Option<(String, String)> {
    let path = host.path;
    let found = |at: &Path| {
        hidden_place(at, &COLLECT_SETS).filter(|(place, _, same)| {
            !(host.used == Use::Measures && *same && at == Path::new(place))
        })
    };
    let (hidden, (place, setting, _)) = found(path)
        .map(|place| (path, place))
        .or_else(|| resolved.and_then(|at| Some((at, found(at)?))))?;
    let through = if hidden == path {
        String::new()
    } else {
        format!(", which leads to {}", hidden.display())
    };
    let cannot = match host.used {
        Use::Reads => "the check cannot read it there",
        Use::Runs => "the check cannot run it there",
        Use::Measures if hidden == Path::new(place) => {
            "the check would measure the unit's own file system there instead"
        }
        Use::Measures => "the check cannot measure it there",
    };
    let option = host.option;
    Some((
        format!(
            "providers[{kind}].{option} is {}{through}, under {place}, which {COLLECT} hides \
             from the collector ({setting}): {cannot}",
            path.display()
        ),
        format!(
            "Keep it where the collector sees it and name that in providers[{kind}].{option}, \
             or show the collector that place read-only at another one \
             (docs/operator/checks.md, \"Paths the collector cannot see\")"
        ),
    ))
}

/// Why the units cannot start the release at `base`, and what to do;
/// `None` where they can. Every unit starts its service from `base`, and
/// one that hides the place `base` leads to through a link finds no
/// program there.
pub(crate) fn hidden_base(base: &Path) -> Option<String> {
    base_hidden_at(base, resolved(base).as_deref())
}

fn base_hidden_at(base: &Path, resolved: Option<&Path>) -> Option<String> {
    let (at, (place, setting, _)) = hidden_place(base, &ANY_SETS)
        .map(|found| (base, found))
        .or_else(|| resolved.and_then(|at| Some((at, hidden_place(at, &ANY_SETS)?))))?;
    let through = if at == base {
        String::new()
    } else {
        format!(" leads to {}, which lies", at.display())
    };
    Some(format!(
        "{}{through} under {place}, which Garrison's units hide from their services \
         ({setting}): none of them could start the program there. Link {} to a folder \
         outside /home, /root, /run/user, /tmp and /var/tmp, or mount the disk there",
        base.display(),
        base.display()
    ))
}

/// `path` with its links followed, as far as it is there; else the same for
/// its folder, with its own name after it.
fn resolved(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok().or_else(|| {
        path.parent()
            .and_then(|folder| std::fs::canonicalize(folder).ok())
            .zip(path.file_name())
            .map(|(folder, name)| folder.join(name))
    })
}

/// [`hidden_check`] for every path the checks name, in their order.
pub(crate) fn hidden_paths(providers: &[Box<dyn Provider>]) -> Vec<(String, String)> {
    providers
        .iter()
        .flat_map(|provider| {
            provider
                .paths()
                .iter()
                .filter_map(|host| {
                    hidden_check(provider.name(), host, resolved(host.path).as_deref())
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// What check-config says of the checks' paths the collector's unit hides:
/// refusals (`Err`) for the configuration the units read, and warnings for
/// any other, as for the access policy.
pub(crate) fn collector_places(
    providers: &[Box<dyn Provider>],
    configuration: &Path,
) -> Result<Vec<String>, Vec<String>> {
    let said: Vec<String> = hidden_paths(providers)
        .into_iter()
        .map(|(what, fix)| format!("{what}. {fix}."))
        .collect();
    if configuration == Path::new(config::DEFAULT_PATH) && !said.is_empty() {
        Err(said)
    } else {
        Ok(said)
    }
}

#[cfg(test)]
mod tests;
