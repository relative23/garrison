//! `garrison access ...`: manage the access policy (root only).
//!
//! There is deliberately no web endpoint that writes the policy. Every change
//! keeps the previous file as a timestamped backup, so a mistake can be undone
//! with `cp`. The files beside the policy are reached as `folder` says.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

use clap::Subcommand;
use garrison_authz::policy::{Policy, is_profile_name, parse_policy};
use garrison_authz::{Authority, Error, SUPPORTED};
use garrison_core::config::Config;
use garrison_core::files::{ProtectedFileError, read_protected};
use garrison_stalwart::jmap::JmapClient;
use garrison_stalwart::oidc::is_subject;
use garrison_stalwart::permissions::native_rights;
use serde_json::{Value, json};

use crate::{complain, credentials, say};

mod defaults;
mod folder;

use defaults::{Candidate, administrator_roles, default_profiles};
use folder::{Current, Folder, MAX_POLICY};

const POLICY_GROUP: &str = "garrison-broker";

fn profile_name(value: &str) -> Result<String, String> {
    if is_profile_name(value) {
        Ok(value.to_owned())
    } else {
        Err(format!("invalid profile name '{value}'"))
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Create the policy and bind native administrator roles.
    Init {
        /// Start over with the default policy, keeping a backup; where no role qualifies, a policy that reads stays.
        #[arg(long)]
        force: bool,
    },
    /// Show the policy.
    List,
    /// Give a native role a Garrison profile.
    BindRole {
        /// The native role ID, as Stalwart shows it.
        role: String,
        /// The profile: viewer, operator, administrator or one of the policy's own.
        #[arg(long, value_parser = profile_name)]
        profile: String,
    },
    /// Remove the profile of a native role.
    UnbindRole {
        /// The native role ID.
        role: String,
    },
    /// Deny a subject regardless of roles.
    Deny {
        /// The OIDC subject, for a local account its numeric account ID.
        subject: String,
        /// Lift the denial instead.
        #[arg(long)]
        undo: bool,
    },
    /// Show the current grant of a subject.
    Check {
        /// The OIDC subject, for a local account its numeric account ID.
        subject: String,
    },
    /// Give the profiles the actions garrison.toml has now, as init does.
    Update,
}

/// JSON with two-space indentation and a final newline.
fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

pub(crate) fn group_id(name: &str) -> Option<u32> {
    let groups = fs::read_to_string("/etc/group").ok()?;
    groups.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        fields.nth(1)?.parse().ok()
    })
}

/// Validate, back up the previous file and put the new one in its place.
fn save(config: &Config, folder: &Folder, policy: &Policy) -> Result<(), String> {
    let document = policy.to_document();
    // Never write an invalid policy.
    parse_policy(&document, &action_ids(config)).map_err(|error| error.to_string())?;
    let path = &config.broker.policy;
    let text = format!("{}\n", pretty(&document));
    // Nor one larger than the broker reads, which would be none.
    if text.len() > MAX_POLICY {
        return Err(format!(
            "The policy would be larger than the broker reads ({} KiB): the change is not saved, \
             and {} stays as it is.",
            MAX_POLICY / 1024,
            path.display()
        ));
    }
    let kept = match folder.current()? {
        Current::File => Some(folder.back_up(&folder.content()?)?),
        Current::Missing => None,
        Current::Other => return Err(not_a_file(path)),
    };
    let group = group_id(POLICY_GROUP).map(rustix::fs::Gid::from_raw);
    if let Some(note) = folder.replace(text.as_bytes(), group)? {
        say(&note);
    }
    match kept {
        Some(backup) => say(&format!(
            "Saved {}; the previous file is kept as {}.",
            path.display(),
            backup.display()
        )),
        None => say(&format!("Saved {}", path.display())),
    }
    Ok(())
}

/// Hold `<policy>.lock` while the policy is read and written; with `make`,
/// in a folder made where it is missing.
fn locked<T>(
    config: &Config,
    make: bool,
    work: impl FnOnce(&Folder) -> Result<T, String>,
) -> Result<T, String> {
    let folder = Folder::open(&config.broker.policy, make)?;
    let _held = folder.lock()?;
    work(&folder)
}

/// What to say of a link, a folder or anything else at the policy's name,
/// which neither this command nor the installer changes.
fn not_a_file(path: &Path) -> String {
    format!(
        "{} is a link or a folder, not a file: remove it; then `garrison access init` makes \
         the file itself there.",
        path.display()
    )
}

fn authority(config: &Config) -> Authority {
    Authority::new(config, credentials(config))
}

/// What the command says where it got no answer it can use, by its kind:
/// an answer this release does not read with where the supported Stalwart
/// releases are named, any other as the error says it.
fn said(error: Error) -> String {
    match error {
        Error::Unreadable(why) => format!(
            "Stalwart answered in a form this release of Garrison does not read ({why}); \
             {SUPPORTED}"
        ),
        Error::Unavailable(why)
        | Error::Limited(why)
        | Error::InvalidToken(why)
        | Error::Denied(why)
        | Error::Misconfigured(why) => why,
    }
}

/// Whether there is a file at the policy's name to read.
fn there(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(folder::missing(path)),
        Ok(kind) if !kind.is_file() => Err(not_a_file(path)),
        _ => Ok(()),
    }
}

fn load(config: &Config) -> Result<Policy, String> {
    let path = &config.broker.policy;
    there(path)?;
    authority(config).policy().map_err(|error| {
        // What keeps the policy from reading beside such actions comes
        // first: `update` cannot mend it.
        if let Err(other) = written(config) {
            return other;
        }
        let gone = gone(config);
        if gone.is_empty() {
            return said(error);
        }
        removed(path, &gone)
    })
}

/// What to say of the policy at `path`, which names the actions `gone` that
/// garrison.toml no longer has.
fn removed(path: &Path, gone: &[String]) -> String {
    format!(
        "The access policy {} names {}, which garrison.toml no longer has: run `garrison access \
         update`, which takes {} out of the profiles.",
        path.display(),
        gone.join(", "),
        if gone.len() == 1 { "it" } else { "them" }
    )
}

/// The actions the policy's profiles name, as it is written; none where it
/// cannot be read.
fn named(config: &Config) -> BTreeSet<String> {
    let Ok(raw) = read_protected(&config.broker.policy, MAX_POLICY) else {
        return BTreeSet::new();
    };
    let profiles = raw["profiles"].as_object().into_iter().flatten();
    profiles
        .filter_map(|(_, profile)| profile["actions"].as_array())
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// The actions the policy names that garrison.toml no longer has.
fn gone(config: &Config) -> Vec<String> {
    let configured = action_ids(config);
    named(config)
        .into_iter()
        .filter(|action| !configured.contains(action.as_str()))
        .collect()
}

fn action_ids(config: &Config) -> BTreeSet<&str> {
    config
        .broker
        .actions
        .iter()
        .map(|action| action.id.as_str())
        .collect()
}

/// The policy as it is written, actions that garrison.toml no longer has
/// among them, which `update` takes out.
fn written(config: &Config) -> Result<Policy, String> {
    let path = &config.broker.policy;
    there(path)?;
    let raw = read_protected(path, MAX_POLICY).map_err(|error| match error {
        ProtectedFileError::TooLarge(_) => format!(
            "The access policy {} is larger than the broker reads ({} KiB), so it is no policy: \
             copy back the last backup beside it ({}.<time>.bak) with sudo cp.",
            path.display(),
            MAX_POLICY / 1024,
            path.display()
        ),
        error => format!("Garrison access policy: {error}"),
    })?;
    let named = named(config);
    let mut known = action_ids(config);
    known.extend(named.iter().map(String::as_str));
    parse_policy(&raw, &known).map_err(|error| error.to_string())
}

/// The profiles get the actions of garrison.toml, as `defaults::follow`
/// gives them.
fn update(config: &Config) -> Result<u8, String> {
    locked(config, false, |folder| {
        let mut policy = written(config)?;
        let changes = defaults::follow(config, &mut policy);
        if changes.is_empty() {
            say("The profiles have the actions garrison.toml names; nothing to change.");
            return Ok(0);
        }
        save(config, folder, &policy)?;
        for change in &changes {
            say(change);
        }
        say(
            "Run the installer again now: it writes the polkit rule for these actions and \
             restarts the broker, which reads them only when it starts. Until then a broker \
             that does not know an action the policy names lets nobody use Garrison.",
        );
        Ok(0)
    })
}

fn native(config: &Config) -> Result<JmapClient, String> {
    Ok(authority(config)
        .native_client()
        .map_err(said)?
        .with_timeout(std::time::Duration::from_secs(10)))
}

fn init(config: &Config, force: bool) -> Result<u8, String> {
    let path = &config.broker.policy;
    let exists = || {
        say(&format!(
            "{} exists; use --force to replace it (a backup is kept).",
            path.display()
        ));
        Ok(1)
    };
    match fs::symlink_metadata(path) {
        Ok(kind) if !kind.is_file() => return Err(not_a_file(path)),
        Ok(_) if !force => return exists(),
        _ => {}
    }
    // Under the lock, so that nothing that came meanwhile is replaced
    // without --force, and before Stalwart is asked.
    let done = locked(config, true, |folder| {
        let there = matches!(folder.current()?, Current::File);
        if !force && there {
            return Ok(None);
        }
        let candidates = administrator_roles(config)?;
        let bound = defaults::qualified(&candidates);
        // A new policy would bind nobody and sign everyone out: one that
        // reads stays, whatever --force says.
        let kept = (bound.is_empty() && there)
            .then(|| written(config).ok())
            .flatten();
        if kept.is_none() {
            let policy = Policy {
                profiles: default_profiles(config),
                role_bindings: bound
                    .iter()
                    .map(|role| (role.clone(), "administrator".to_owned()))
                    .collect(),
                ..Policy::default()
            };
            save(config, folder, &policy)?;
        }
        Ok(Some((candidates, bound, kept)))
    })?;
    let Some((candidates, bound, kept)) = done else {
        return exists();
    };
    if bound.is_empty() {
        complain(&match kept {
            None => defaults::unbound(&candidates),
            Some(policy) => kept_said(config, &policy, &candidates),
        });
        return Ok(1);
    }
    for role in &bound {
        let named = candidates.get(role).map_or_else(
            || role.clone(),
            |candidate| defaults::named(role, candidate),
        );
        say(&format!(
            "Bound native role {named} to profile administrator."
        ));
    }
    Ok(0)
}

/// What `init --force` says where it keeps `policy`, since no role
/// qualifies: what keeps that policy from working, if anything, and what to
/// do then.
fn kept_said(config: &Config, policy: &Policy, candidates: &BTreeMap<String, Candidate>) -> String {
    let path = &config.broker.policy;
    let mut lines = vec![format!(
        "No native administrator role with full administrative rights was found, and a new \
         default policy would bind no role and sign everyone out: {} is kept as it is.",
        path.display()
    )];
    let gone = gone(config);
    if !gone.is_empty() {
        lines.push(removed(path, &gone));
    }
    if policy.role_bindings.is_empty() && policy.subjects.is_empty() {
        lines.push(format!(
            "It binds no role or account either, so nobody can sign in yet. {}",
            defaults::requires()
        ));
        lines.extend(defaults::candidates_said(candidates));
    }
    lines.join("\n")
}

/// What the broker would grant `subject` now, as it decides it.
fn check(config: &Config, subject: &str) -> Result<u8, String> {
    let policy = load(config)?;
    let account = policy.account_for(subject).map_err(said)?;
    let rights = native_rights(&native(config)?, &account).map_err(said)?;
    let result = policy
        .capabilities(subject, &rights.permissions, &rights.roles)
        .and_then(|capabilities| authority(config).offered(capabilities))
        .map_err(said)?;
    let mut modules: Vec<&str> = result.modules.iter().map(|id| id.as_str()).collect();
    modules.sort_unstable();
    say(&pretty(&json!({
        "account": account,
        "roles": rights.roles,
        "profiles": result.profiles,
        "modules": modules,
        "actions": result.actions,
    })));
    Ok(0)
}

fn execute(config: &Config, command: &Command) -> Result<u8, String> {
    match command {
        Command::Init { force } => init(config, *force),
        Command::List => {
            say(&pretty(&load(config)?.to_document()));
            Ok(0)
        }
        Command::BindRole { role, profile } => locked(config, false, |folder| {
            let mut policy = load(config)?;
            if !policy.profiles.contains_key(profile) {
                let known: Vec<&str> = policy.profiles.keys().map(String::as_str).collect();
                say(&format!(
                    "Unknown profile {profile}; known: {}",
                    known.join(", ")
                ));
                return Ok(1);
            }
            // The role must exist; what it lacks for the profile is said.
            let client = native(config)?;
            let authentication = defaults::authentication(&client)?;
            let Some(judged) = defaults::judged(&client, &authentication, role)? else {
                return Err(format!(
                    "Stalwart has no role {role}: bind one of the roles the native \
                     administration shows (Roles)."
                ));
            };
            policy.role_bindings.insert(role.clone(), profile.clone());
            save(config, folder, &policy)?;
            if let Some(note) = defaults::fit(&policy, profile, role, judged.rights.as_ref()) {
                say(&note);
            }
            Ok(0)
        }),
        Command::UnbindRole { role } => locked(config, false, |folder| {
            let mut policy = load(config)?;
            policy.role_bindings.remove(role);
            save(config, folder, &policy).map(|()| 0)
        }),
        Command::Deny { subject, undo } => {
            if !is_subject(subject) {
                say("Invalid subject");
                return Ok(1);
            }
            locked(config, false, |folder| {
                let mut policy = load(config)?;
                if *undo {
                    policy.denied.remove(subject);
                } else {
                    policy.denied.insert(subject.clone());
                }
                save(config, folder, &policy).map(|()| 0)
            })
        }
        Command::Check { subject } => check(config, subject),
        Command::Update => update(config),
    }
}

pub(crate) fn run(config: &Config, command: &Command) -> u8 {
    execute(config, command).unwrap_or_else(|error| {
        complain(&error);
        1
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_are_found_by_their_exact_name() {
        let groups = fs::read_to_string("/etc/group").unwrap();
        let (name, gid) = groups
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                Some((
                    fields.first()?.to_string(),
                    fields.get(2)?.parse::<u32>().ok()?,
                ))
            })
            .find(|(_, gid)| *gid > 1)
            .unwrap();
        assert_eq!(group_id(&name), Some(gid));
        assert_eq!(group_id("root"), Some(0));
        assert_eq!(group_id(&format!("{name}-missing")), None);
    }
}
