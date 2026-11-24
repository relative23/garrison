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
use garrison_authz::{Authority, Error};
use garrison_core::config::Config;
use garrison_core::files::{ProtectedFileError, read_protected};
use garrison_stalwart::jmap::JmapClient;
use garrison_stalwart::oidc::is_subject;
use garrison_stalwart::permissions::native_rights;
use serde_json::{Value, json};

use crate::state::State;
use crate::states::access as states;
use crate::{complain, credentials, say};

mod defaults;
mod folder;

#[cfg(test)]
pub(crate) use defaults::Fit;
pub(crate) use defaults::{ADMIN_PERMISSIONS, Candidate};
use defaults::{administrator_roles, default_profiles};
use folder::{Current, Folder};
pub(crate) use folder::{MAX_POLICY, way_out};

const POLICY_GROUP: &str = "garrison-broker";

/// clap's parser of `--profile`, which takes the error as a sentence.
fn profile_name(value: &str) -> Result<String, String> {
    if is_profile_name(value) {
        Ok(value.to_owned())
    } else {
        Err(states::invalid_profile(value).to_string())
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
fn save(config: &Config, folder: &Folder, policy: &Policy) -> Result<(), State> {
    let document = policy.to_document();
    // Never write an invalid policy.
    parse_policy(&document, &action_ids(config)).map_err(states::invalid_policy)?;
    let path = &config.broker.policy;
    let text = format!("{}\n", pretty(&document));
    // Nor one larger than the broker reads, which would be none.
    if text.len() > MAX_POLICY {
        return Err(states::save_too_large(path));
    }
    let kept = match folder.current()? {
        Current::File => Some(folder.back_up(&folder.content()?)?),
        Current::Missing => None,
        Current::Other => return Err(states::not_a_file(path)),
    };
    let group = group_id(POLICY_GROUP).map(rustix::fs::Gid::from_raw);
    if let Some(note) = folder.replace(text.as_bytes(), group)? {
        say(&note.to_string());
    }
    say(&states::saved(path, kept.as_deref()).to_string());
    Ok(())
}

/// Hold `<policy>.lock` while the policy is read and written; with `make`,
/// in a folder made where it is missing.
fn locked<T>(
    config: &Config,
    make: bool,
    work: impl FnOnce(&Folder) -> Result<T, State>,
) -> Result<T, State> {
    let folder = Folder::open(&config.broker.policy, make)?;
    let _held = folder.lock()?;
    work(&folder)
}

fn authority(config: &Config) -> Authority {
    Authority::new(config, credentials(config))
}

/// What the command says where it got no answer it can use, by its kind:
/// an answer this release does not read with where the supported Stalwart
/// releases are named, any other as the error says it.
fn said(error: Error) -> State {
    match error {
        Error::Unreadable(why) => states::unread_answer(&why),
        Error::Unavailable(why) => states::unavailable(why),
        Error::Limited(why) => states::limited(why),
        Error::InvalidToken(why) => states::invalid_token(why),
        Error::Denied(why) => states::denied(why),
        Error::Misconfigured(why) => states::misconfigured(why),
    }
}

/// Whether there is a file at the policy's name to read.
fn there(path: &Path) -> Result<(), State> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(states::missing(path)),
        Ok(kind) if !kind.is_file() => Err(states::not_a_file(path)),
        _ => Ok(()),
    }
}

fn load(config: &Config) -> Result<Policy, State> {
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
        states::actions_gone(path, &gone)
    })
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
fn written(config: &Config) -> Result<Policy, State> {
    let path = &config.broker.policy;
    there(path)?;
    let raw = read_protected(path, MAX_POLICY).map_err(|error| match error {
        ProtectedFileError::TooLarge(_) => states::too_large(path),
        error => states::unread_policy(error),
    })?;
    let named = named(config);
    let mut known = action_ids(config);
    known.extend(named.iter().map(String::as_str));
    parse_policy(&raw, &known).map_err(states::invalid_policy)
}

/// The profiles get the actions of garrison.toml, as `defaults::follow`
/// gives them.
fn update(config: &Config) -> Result<u8, State> {
    locked(config, false, |folder| {
        let mut policy = written(config)?;
        let changes = defaults::follow(config, &mut policy);
        if changes.is_empty() {
            say(&states::actions_held().to_string());
            return Ok(0);
        }
        save(config, folder, &policy)?;
        for change in &changes {
            say(&change.to_string());
        }
        say(&states::run_installer().to_string());
        Ok(0)
    })
}

fn native(config: &Config) -> Result<JmapClient, State> {
    Ok(authority(config)
        .native_client()
        .map_err(said)?
        .with_timeout(std::time::Duration::from_secs(10)))
}

fn init(config: &Config, force: bool) -> Result<u8, State> {
    let path = &config.broker.policy;
    let exists = || {
        complain(&states::exists(path).to_string());
        Ok(1)
    };
    match fs::symlink_metadata(path) {
        Ok(kind) if !kind.is_file() => return Err(states::not_a_file(path)),
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
        complain(
            &match kept {
                None => states::unbound(&candidates),
                Some(policy) => kept_said(config, &policy, &candidates),
            }
            .to_string(),
        );
        return Ok(1);
    }
    for role in &bound {
        let description = candidates
            .get(role)
            .and_then(|candidate| candidate.description.as_deref());
        say(&states::bound(role, description).to_string());
    }
    Ok(0)
}

/// What `init --force` says where it keeps `policy`, since no role
/// qualifies: what keeps that policy from working, if anything, and what to
/// do then.
fn kept_said(config: &Config, policy: &Policy, candidates: &BTreeMap<String, Candidate>) -> State {
    let path = &config.broker.policy;
    let gone = gone(config);
    let gone = (!gone.is_empty()).then(|| states::actions_gone(path, &gone));
    let nobody = policy.role_bindings.is_empty() && policy.subjects.is_empty();
    states::kept(path, gone.as_ref(), nobody, candidates)
}

/// What the broker would grant `subject` now, as it decides it.
fn check(config: &Config, subject: &str) -> Result<u8, State> {
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

fn execute(config: &Config, command: &Command) -> Result<u8, State> {
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
                complain(&states::unknown_profile(profile, &known).to_string());
                return Ok(1);
            }
            // The role must exist; what it lacks for the profile is said.
            let client = native(config)?;
            let authentication = defaults::authentication(&client)?;
            let Some(judged) = defaults::judged(&client, &authentication, role)? else {
                return Err(states::no_role(role));
            };
            policy.role_bindings.insert(role.clone(), profile.clone());
            save(config, folder, &policy)?;
            if let Some(note) = defaults::fit(&policy, profile, role, judged.rights.as_ref()) {
                say(&note.to_string());
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
                complain(&states::no_subject(subject).to_string());
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
    execute(config, command).unwrap_or_else(|refusal| {
        complain(&refusal.to_string());
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
