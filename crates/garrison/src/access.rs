//! `garrison access ...`: manage the access policy (root only).
//!
//! There is deliberately no web endpoint that writes the policy. Every change
//! keeps the previous file as a timestamped backup, so a mistake can be undone
//! with `cp`. The files beside the policy are reached as `folder` says.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

use clap::Subcommand;
use garrison_authz::policy::{Policy, is_profile_name, parse_policy};
use garrison_authz::{Authority, Error, SUPPORTED};
use garrison_core::config::Config;
use garrison_stalwart::jmap::{JmapClient, Object};
use garrison_stalwart::oidc::is_subject;
use garrison_stalwart::permissions::native_rights;
use serde_json::{Value, json};

use crate::{complain, credentials, say};

mod defaults;
mod folder;

use defaults::{administrator_roles, default_profiles};
use folder::{Current, Folder};

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
        /// Replace an existing policy (a backup of it is kept).
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
    let ids: BTreeSet<&str> = config
        .broker
        .actions
        .iter()
        .map(|action| action.id.as_str())
        .collect();
    // Never write an invalid policy.
    parse_policy(&document, &ids).map_err(|error| error.to_string())?;
    let path = &config.broker.policy;
    let kept = match folder.current()? {
        Current::File(previous) => Some(folder.back_up(&previous)?),
        Current::Missing => None,
        Current::Other => return Err(not_a_file(path)),
    };
    let text = format!("{}\n", pretty(&document));
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

fn load(config: &Config) -> Result<Policy, String> {
    let path = &config.broker.policy;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(folder::missing(path)),
        Ok(kind) if !kind.is_file() => return Err(not_a_file(path)),
        _ => {}
    }
    authority(config).policy().map_err(said)
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
    let roles = locked(config, true, |folder| {
        if !force && matches!(folder.current()?, Current::File(_)) {
            return Ok(None);
        }
        let roles = administrator_roles(config)?;
        if roles.is_empty() {
            return Ok(Some(roles));
        }
        let policy = Policy {
            profiles: default_profiles(config),
            role_bindings: roles
                .keys()
                .map(|role| (role.clone(), "administrator".to_owned()))
                .collect(),
            ..Policy::default()
        };
        save(config, folder, &policy)?;
        Ok(Some(roles))
    })?;
    let Some(roles) = roles else {
        return exists();
    };
    if roles.is_empty() {
        say("No native administrator role with full administrative rights was found.");
        return Ok(1);
    }
    for (identifier, description) in &roles {
        say(&format!(
            "Bound native role {identifier} ({description}) to profile administrator."
        ));
    }
    Ok(0)
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
            // The role must exist.
            native(config)?
                .get::<Object>("Role", Some(&[role.as_str()]), &["id"])
                .map_err(said)?;
            policy.role_bindings.insert(role.clone(), profile.clone());
            save(config, folder, &policy).map(|()| 0)
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
