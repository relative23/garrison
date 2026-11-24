//! The access policy, as the broker meets it. The broker reads it for each
//! request as its own user, garrison-broker, in its own group and those
//! /etc/group lists it in (its unit's `User=` and `Group=`), and takes it
//! only where root or the broker owns it, its group may not change it and
//! others may neither read nor change it
//! (`garrison_core::files::read_protected`). doctor reads as root, who may
//! read more, so it judges owner, group and mode, and the folders above, for
//! the broker; and what the policy grants, as the broker reads it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use garrison_authz::policy::{Policy, parse_policy};
use garrison_core::config::Config;
use garrison_core::files::{ProtectedFileError, open_regular_file};
use garrison_core::json::{self, JsonError};
use serde_json::Value;

use super::{Finding, Level, counted};
use crate::units;

/// The user, and the group, the broker's unit runs it as.
const BROKER: &str = "garrison-broker";
/// As much of the policy as the broker reads.
const LIMIT: usize = 64 * 1024;
/// Where the installer and `garrison access init` keep the policy.
const DEFAULT: &str = "/etc/garrison/access-policy.json";

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
/// what is seen so, as the kernel decides it: root always, and otherwise by
/// the owner's bits for its owner, the group's for a member of its group,
/// the others' for anybody else.
fn may(seen: Seen, reader: &Reader, bits: u32) -> bool {
    if reader.uid == 0 {
        return true;
    }
    let class = if seen.uid == reader.uid {
        seen.mode >> 6
    } else if reader.groups.contains(&seen.gid) {
        seen.mode >> 3
    } else {
        seen.mode
    };
    class & bits == bits
}

/// Why `read_protected`, reading as `reader`, does not take a policy seen
/// so: it takes one that root or its reader owns, whose group may not
/// change it and that others may neither read nor change. `None` for the
/// reader where the host has no broker, which leaves only the mode to judge.
fn refusals(file: Seen, reader: Option<&Reader>) -> Vec<&'static str> {
    let mut why = Vec::new();
    if reader.is_some_and(|reader| file.uid != 0 && file.uid != reader.uid) {
        why.push("a user other than root and the broker owns it");
    }
    if file.mode & 0o020 != 0 {
        why.push("its group may change it");
    }
    match file.mode & 0o006 {
        0 => {}
        0o004 => why.push("others may read it"),
        _ => why.push("others may change it"),
    }
    why
}

/// Whether the broker takes a policy seen so, as `read_protected` does.
fn taken(file: Seen, broker: Option<&Reader>) -> bool {
    refusals(file, broker).is_empty() && (file.uid == 0 || broker.is_some())
}

/// What mends a folder above the policy that the broker may not enter: the
/// mode the installer gives `/etc/garrison` where it lies on the way there,
/// and the default place elsewhere.
fn entered(folder: &Path) -> String {
    if Path::new(DEFAULT).starts_with(folder) {
        format!("chmod 755 {}", folder.display())
    } else {
        format!("Move the policy to {DEFAULT} and set broker.policy to it.")
    }
}

/// What the broker meets at the policy at `path`, seen so, in the folders
/// above it, seen so: as `read_protected` takes it when the broker reads it,
/// which enters every folder above and opens the file as the broker.
pub(super) fn readable(
    path: &Path,
    file: Seen,
    folders: &[(PathBuf, Seen)],
    broker: Option<&Reader>,
    names: &Names,
) -> Finding {
    let shown = format!("{}, mode {:o}", names.of(file), file.mode);
    let fix = format!("chown root:{BROKER} {0} && chmod 640 {0}", path.display());
    let refused = |why: &[&str]| {
        Finding::fail(
            format!(
                "the broker does not take the access policy ({shown}): {}, so nobody can sign \
                 in: {}",
                why.join(", and "),
                path.display()
            ),
            fix.clone(),
        )
    };
    let Some(broker) = broker else {
        let why = refusals(file, None);
        if !why.is_empty() {
            return refused(&why);
        }
        return Finding::unknown(format!(
            "whether the broker can read the access policy: this host has no user {BROKER}"
        ));
    };
    if let Some((folder, seen)) = folders.iter().find(|(_, seen)| !may(*seen, broker, 0o1)) {
        return Finding::fail(
            format!(
                "{BROKER} may not enter {} ({}, mode {:o}), so it cannot read the access policy \
                 and nobody can sign in",
                folder.display(),
                names.of(*seen),
                seen.mode
            ),
            entered(folder),
        );
    }
    if !may(file, broker, 0o4) {
        return Finding::fail(
            format!(
                "{BROKER} may not read the access policy ({shown}), so nobody can sign in: {}",
                path.display()
            ),
            fix,
        );
    }
    let why = refusals(file, Some(broker));
    if !why.is_empty() {
        return refused(&why);
    }
    if file.uid == broker.uid && broker.uid != 0 {
        return Finding::warn(
            format!(
                "{BROKER} owns the access policy ({shown}), which the installer keeps root's, so \
                 that only root may change what it grants"
            ),
            fix,
        );
    }
    Finding::ok(format!(
        "the broker may read the access policy, which only root may change ({shown})"
    ))
}

/// The actions the policy's profiles name that garrison.toml does not have,
/// where those alone keep the broker from using it.
fn beyond(config: &Config) -> Vec<String> {
    let Some(raw) = garrison_core::files::read_json(&config.broker.policy, LIMIT) else {
        return Vec::new();
    };
    let configured: BTreeSet<&str> = config
        .broker
        .actions
        .iter()
        .map(|action| action.id.as_str())
        .collect();
    let named: BTreeSet<&str> = raw
        .get("profiles")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|profiles| profiles.values())
        .filter_map(|profile| profile.get("actions")?.as_array())
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let widened: BTreeSet<&str> = configured.union(&named).copied().collect();
    if parse_policy(&raw, &widened).is_err() {
        return Vec::new();
    }
    named
        .difference(&configured)
        .map(|action| (*action).to_owned())
        .collect()
}

/// What the policy grants, as the broker reads it once it takes the file
/// (see [`readable`]): never through a link, no more than the broker reads,
/// and with the actions garrison.toml names. Root reads more than the broker
/// does, but `read_protected` as root would refuse a policy the broker owns,
/// which the broker takes.
pub(crate) fn granted(config: &Config) -> Result<Policy, Unread> {
    let path = &config.broker.policy;
    let unread =
        |error: ProtectedFileError| Unread::Other(format!("Garrison access policy: {error}"));
    let mut data = Vec::new();
    open_regular_file(path)
        .and_then(|file| file.take(LIMIT as u64 + 1).read_to_end(&mut data))
        .map_err(|_| unread(ProtectedFileError::Unavailable(path.clone())))?;
    let raw = json::parse(&data, LIMIT).map_err(|error| match error {
        JsonError::TooLarge => Unread::TooLarge,
        JsonError::Invalid(_) => unread(ProtectedFileError::InvalidJson(path.clone())),
    })?;
    let actions: BTreeSet<&str> = config
        .broker
        .actions
        .iter()
        .map(|action| action.id.as_str())
        .collect();
    parse_policy(&raw, &actions).map_err(|error| Unread::Other(error.to_string()))
}

/// Why what a policy grants does not read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unread {
    /// The file is larger than the broker reads, so it is no policy.
    TooLarge,
    /// Anything else, in the broker's words.
    Other(String),
}

/// What the policy grants, read and checked as the broker reads it.
pub(super) fn content(config: &Config) -> Finding {
    let policy = match granted(config) {
        Ok(policy) => policy,
        Err(Unread::TooLarge) => {
            let path = &config.broker.policy;
            let mut fix = crate::access::way_out(path);
            fix.replace_range(..1, &fix[..1].to_uppercase());
            return Finding::fail(
                format!(
                    "the access policy is larger than the broker reads ({} KiB), so nobody can \
                     sign in: {}",
                    LIMIT / 1024,
                    path.display()
                ),
                format!("{fix}."),
            );
        }
        Err(Unread::Other(error)) => {
            let beyond = beyond(config);
            if !beyond.is_empty() {
                return Finding::fail(
                    format!(
                        "the access policy names actions garrison.toml does not have ({}), so \
                         nobody can sign in",
                        beyond.join(", ")
                    ),
                    "Run `garrison access update`, which mends it.",
                );
            }
            let why = error.trim_start_matches("Garrison access policy: ");
            return Finding::fail(
                format!("the access policy does not read ({why}), so nobody can sign in"),
                "Correct it as docs/operator/access.md shows.",
            );
        }
    };
    if policy.role_bindings.is_empty() && policy.subjects.is_empty() {
        return Finding::fail(
            "the access policy binds no role and no account, so nobody can sign in",
            "Bind the role of your administrators: garrison access bind-role <role-id> \
             --profile administrator",
        );
    }
    Finding::ok(format!(
        "the access policy binds {} and {}",
        counted(policy.role_bindings.len(), "role", "roles"),
        counted(policy.subjects.len(), "account", "accounts")
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

/// What the broker meets at the policy at `path` on this host: a failure
/// where no file of its own is there (`Err`); else what [`readable`] finds
/// for this host's broker, and whether the broker takes the file.
fn met(path: &Path) -> Result<(Finding, bool), Finding> {
    match fs::symlink_metadata(path) {
        Err(_) => Err(Finding::fail(
            format!("the access policy is missing: {}", path.display()),
            "Run `garrison access init`, which makes it.",
        )),
        // Neither the installer nor the broker follows a link here.
        Ok(metadata) if !metadata.is_file() => Err(Finding::fail(
            format!(
                "the access policy is a link or a folder, not a file: {}",
                path.display()
            ),
            "Remove it; then `garrison access init` makes the file itself there.",
        )),
        Ok(metadata) => {
            let read = |file: &str| fs::read_to_string(file).unwrap_or_default();
            let (names, broker) = accounts(&read("/etc/passwd"), &read("/etc/group"));
            let file = Seen::of(&metadata);
            let found = readable(path, file, &folders(path), broker.as_ref(), &names);
            Ok((found, taken(file, broker.as_ref())))
        }
    }
}

/// The access policy at `path` as the broker meets it, for check-config.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Met {
    /// No file of its own is there: what is wrong and what mends it.
    Missing(String),
    /// The broker does not take it: what is wrong and what mends it.
    Refused(String),
    /// The broker takes it, or nothing says it does not: what to warn of.
    Taken(Option<String>),
}

/// [`met`] for check-config, with each finding as one sentence and its fix.
pub(crate) fn as_the_broker(path: &Path) -> Met {
    match met(path) {
        Err(missing) => Met::Missing(said(&missing)),
        Ok((found, _)) => verdict(&found),
    }
}

/// One finding of [`readable`] as check-config says it.
fn verdict(found: &Finding) -> Met {
    match found.level {
        Level::Ok => Met::Taken(None),
        Level::Warn => Met::Taken(Some(said(found))),
        Level::Unknown => Met::Taken(Some(format!("it is not known {}.", found.what))),
        Level::Fail => Met::Refused(said(found)),
    }
}

/// A finding and its fix as one line: a fix that is a command is to be run.
fn said(found: &Finding) -> String {
    match &found.fix {
        Some(fix) if fix.ends_with('.') => format!("{}. {fix}", found.what),
        Some(fix) => format!("{}. Run `{fix}`.", found.what),
        None => format!("{}.", found.what),
    }
}

pub(super) fn checks(config: &Config) -> Vec<Finding> {
    let path = &config.broker.policy;
    let mut findings = Vec::new();
    match met(path) {
        Err(missing) => findings.push(missing),
        Ok((found, taken)) => {
            findings.push(found);
            // Root reads what the broker would take; one it does not take
            // grants nothing to judge.
            if taken {
                findings.push(content(config));
            }
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
