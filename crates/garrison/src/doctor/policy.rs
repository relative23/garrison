//! The access policy, as the broker meets it. The broker reads it for each
//! request as its own user, garrison-broker, in its own group and those
//! /etc/group lists it in (its unit's `User=` and `Group=`), and takes it
//! only where root owns it, its group may not change it and others may not
//! read it (`garrison_core::files::read_protected`). doctor reads as root,
//! who may read more, so it judges owner, group and mode, and the folders
//! above, for the broker.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use garrison_core::config::Config;

use super::Finding;
use crate::units;

/// The user, and the group, the broker's unit runs it as.
const BROKER: &str = "garrison-broker";

/// Who the broker is on this host: its user and the groups systemd gives it.
#[derive(Clone, Debug)]
pub(super) struct Reader {
    pub(super) uid: u32,
    pub(super) groups: Vec<u32>,
}

/// Owner, group and mode of a file or a folder.
#[derive(Clone, Copy, Debug)]
pub(super) struct Seen {
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mode: u32,
}

impl Seen {
    fn of(metadata: &fs::Metadata) -> Seen {
        Seen {
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
        }
    }
}

/// The names of this host's users and groups, for the lines.
#[derive(Debug, Default)]
pub(super) struct Names {
    users: BTreeMap<u32, String>,
    groups: BTreeMap<u32, String>,
}

impl Names {
    /// `owner:group`, as `ls -l` names them; a number where no name is known.
    fn of(&self, seen: Seen) -> String {
        let name = |names: &BTreeMap<u32, String>, id: u32| {
            names.get(&id).cloned().unwrap_or_else(|| id.to_string())
        };
        format!(
            "{}:{}",
            name(&self.users, seen.uid),
            name(&self.groups, seen.gid)
        )
    }
}

/// The users and groups that `passwd` and `group`, the files' text, name,
/// and the broker among them.
pub(super) fn accounts(passwd: &str, group: &str) -> (Names, Option<Reader>) {
    let mut names = Names::default();
    let mut broker = None;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let (Some(name), Some(Ok(id))) =
            (fields.first(), fields.get(2).map(|id| id.parse::<u32>()))
        else {
            continue;
        };
        names.users.entry(id).or_insert_with(|| (*name).to_owned());
        if *name == BROKER {
            broker = Some(id);
        }
    }
    let mut groups = Vec::new();
    for line in group.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let (Some(name), Some(Ok(id))) =
            (fields.first(), fields.get(2).map(|id| id.parse::<u32>()))
        else {
            continue;
        };
        names.groups.entry(id).or_insert_with(|| (*name).to_owned());
        let member = fields
            .get(3)
            .is_some_and(|members| members.split(',').any(|member| member == BROKER));
        if *name == BROKER || member {
            groups.push(id);
        }
    }
    (names, broker.map(|uid| Reader { uid, groups }))
}

/// Whether `reader` may do `bits` (4 to read, 1 to enter a folder) with
/// what is seen so, as the kernel decides it: by the owner's bits for its
/// owner, the group's for a member of its group, the others' for anybody
/// else.
fn may(seen: Seen, reader: &Reader, bits: u32) -> bool {
    let class = if seen.uid == reader.uid {
        seen.mode >> 6
    } else if reader.groups.contains(&seen.gid) {
        seen.mode >> 3
    } else {
        seen.mode
    };
    class & bits == bits
}

/// Whether the broker takes a policy seen so, as `read_protected` does.
fn taken(file: Seen) -> bool {
    file.uid == 0 && file.mode & 0o026 == 0
}

/// What the broker meets at the policy at `path`, seen so, in the folders
/// above it, seen so.
pub(super) fn readable(
    path: &Path,
    file: Seen,
    folders: &[(PathBuf, Seen)],
    broker: Option<&Reader>,
    names: &Names,
) -> Finding {
    let shown = format!("{}, mode {:o}", names.of(file), file.mode);
    let fix = format!("chown root:{BROKER} {0} && chmod 640 {0}", path.display());
    if !taken(file) {
        return Finding::fail(
            format!(
                "the broker takes only an access policy that root owns and others may not read \
                 ({shown}), so nobody can sign in: {}",
                path.display()
            ),
            fix,
        );
    }
    let Some(broker) = broker else {
        return Finding::unknown(format!(
            "whether the broker can read the access policy: this host has no user {BROKER}"
        ));
    };
    if !may(file, broker, 0o4) {
        return Finding::fail(
            format!(
                "{BROKER} may not read the access policy ({shown}), so nobody can sign in: {}",
                path.display()
            ),
            fix,
        );
    }
    if let Some((folder, seen)) = folders.iter().find(|(_, seen)| !may(*seen, broker, 0o1)) {
        return Finding::fail(
            format!(
                "{BROKER} may not enter {} ({}, mode {:o}), so it cannot read the access policy \
                 and nobody can sign in",
                folder.display(),
                names.of(*seen),
                seen.mode
            ),
            "Move the policy to /etc/garrison/access-policy.json and set broker.policy to it.",
        );
    }
    Finding::ok(format!(
        "the broker may read the access policy, which only root may change ({shown})"
    ))
}

/// The folders above `path`, each as it is seen, nearest first.
fn folders(path: &Path) -> Vec<(PathBuf, Seen)> {
    path.ancestors()
        .skip(1)
        .filter(|folder| !folder.as_os_str().is_empty())
        .filter_map(|folder| {
            let metadata = fs::metadata(folder).ok()?;
            Some((folder.to_owned(), Seen::of(&metadata)))
        })
        .collect()
}

pub(super) fn checks(config: &Config) -> Vec<Finding> {
    let path = &config.broker.policy;
    let mut findings = Vec::new();
    match fs::symlink_metadata(path) {
        Err(_) => findings.push(Finding::fail(
            format!("the access policy is missing: {}", path.display()),
            "Run `garrison access init`, which makes it.",
        )),
        // Neither the installer nor the broker follows a link here.
        Ok(metadata) if !metadata.is_file() => findings.push(Finding::fail(
            format!(
                "the access policy is a link or a folder, not a file: {}",
                path.display()
            ),
            "Remove it; then `garrison access init` makes the file itself there.",
        )),
        Ok(metadata) => {
            let read = |file: &str| fs::read_to_string(file).unwrap_or_default();
            let (names, broker) = accounts(&read("/etc/passwd"), &read("/etc/group"));
            findings.push(readable(
                path,
                Seen::of(&metadata),
                &folders(path),
                broker.as_ref(),
                &names,
            ));
        }
    }
    // Root may read a policy that the broker's unit hides from it.
    if let Some((what, fix)) = units::hidden_policy(path) {
        findings.push(Finding::fail(what, format!("{fix}.")));
    }
    findings
}

#[cfg(test)]
mod tests;
