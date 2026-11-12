//! `garrison access ...`: manage the access policy (root only).
//!
//! There is deliberately no web endpoint that writes the policy. Every change
//! keeps the previous file as a timestamped backup, so a mistake can be undone
//! with `cp`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use clap::Subcommand;
use garrison_authz::policy::{Policy, Profile, is_profile_name, parse_policy};
use garrison_authz::{Authority, Error};
use garrison_core::config::Config;
use garrison_core::files::atomic_write;
use garrison_core::modules::ModuleId;
use garrison_core::time;
use garrison_stalwart::jmap::{JmapClient, Object};
use garrison_stalwart::oidc::is_subject;
use garrison_stalwart::permissions::{
    AUTHENTICATION_PROPERTIES, Account, AccountRoles, Authentication, Permissions, ROLE_PROPERTIES,
    Role, RoleIds, evaluate, native_rights,
};
use serde_json::{Value, json};

use crate::{complain, credentials, say};

const VIEWER_PERMISSIONS: [&str; 3] = ["authenticate", "sysAccountGet", "sysDomainGet"];
const ADMIN_PERMISSIONS: [&str; 5] = [
    "authenticate",
    "sysAccountUpdate",
    "sysDomainUpdate",
    "sysRoleUpdate",
    "sysActionCreate",
];
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

fn strings(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

fn default_profiles(config: &Config) -> BTreeMap<String, Profile> {
    let all: BTreeSet<ModuleId> = ModuleId::all().collect();
    let mut viewer_modules = all.clone();
    viewer_modules.remove(&ModuleId::Actions);
    let every: BTreeSet<String> = config
        .broker
        .actions
        .iter()
        .map(|action| action.id.clone())
        .collect();
    let operator: BTreeSet<String> = config
        .broker
        .actions
        .iter()
        .filter(|action| action.operator)
        .map(|action| action.id.clone())
        .collect();
    let mut operator_rights = strings(&VIEWER_PERMISSIONS);
    operator_rights.insert("sysActionCreate".into());
    BTreeMap::from([
        (
            "viewer".to_owned(),
            Profile {
                modules: viewer_modules,
                actions: BTreeSet::new(),
                required: strings(&VIEWER_PERMISSIONS),
            },
        ),
        (
            "operator".to_owned(),
            Profile {
                modules: all.clone(),
                actions: operator,
                required: operator_rights,
            },
        ),
        (
            "administrator".to_owned(),
            Profile {
                modules: all,
                actions: every,
                required: strings(&ADMIN_PERMISSIONS),
            },
        ),
    ])
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

/// Validate, back up the previous file and replace it atomically.
fn save(config: &Config, policy: &Policy) -> Result<(), String> {
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
    if path.exists() {
        let stamp = time::now().strftime("%Y%m%dT%H%M%S");
        let backup = path.with_file_name(format!(
            "{}.{stamp}.bak",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
        fs::copy(path, &backup).map_err(|error| error.to_string())?;
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    let text = format!("{}\n", pretty(&document));
    atomic_write(path, text.as_bytes(), 0o640).map_err(|error| error.to_string())?;
    let owned = group_id(POLICY_GROUP).is_some_and(|gid| {
        let (root, group) = (rustix::fs::Uid::ROOT, rustix::fs::Gid::from_raw(gid));
        rustix::fs::chown(path, Some(root), Some(group)).is_ok()
    });
    if !owned {
        say(&format!(
            "Note: could not set group {POLICY_GROUP} on the policy file."
        ));
    }
    say(&format!("Saved {}", path.display()));
    Ok(())
}

/// Hold `<policy>.lock` while the policy is read and written.
fn locked<T>(config: &Config, work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let policy = &config.broker.policy;
    let path: PathBuf = policy.with_file_name(format!(
        "{}.lock",
        policy.file_name().unwrap_or_default().to_string_lossy()
    ));
    let file = fs::File::create(&path).map_err(|error| error.to_string())?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|error| error.to_string())?;
    work()
}

fn authority(config: &Config) -> Authority {
    Authority::new(config, credentials(config))
}

fn load(config: &Config) -> Result<Policy, String> {
    authority(config)
        .policy()
        .map_err(|error| error.to_string())
}

fn native(config: &Config) -> Result<JmapClient, String> {
    Ok(authority(config)
        .native_client()
        .map_err(|error| error.to_string())?
        .with_timeout(std::time::Duration::from_secs(10)))
}

/// Roles that are default *administrator* roles and hold all admin rights.
fn administrator_roles(config: &Config) -> Result<BTreeMap<String, String>, String> {
    let client = native(config)?;
    let failed = |error: Error| error.to_string();
    let authentication: Authentication = client
        .get(
            "Authentication",
            Some(&["singleton"]),
            &AUTHENTICATION_PROPERTIES,
        )
        .map_err(failed)?
        .into_iter()
        .next()
        .ok_or("Stalwart returned no object")?;
    let admin = &authentication.default_admin_role_ids.0;
    let user = &authentication.default_user_role_ids.0;
    let mut properties: Vec<&str> = ROLE_PROPERTIES.to_vec();
    properties.push("description");
    // Every role of the server, also those of tenants and of other software.
    // One this release cannot read is left out, and an administrator role
    // that inherits from it is then not evaluated as one.
    let (mut roles, mut descriptions) = (BTreeMap::new(), BTreeMap::new());
    for object in client
        .get::<Object>("Role", None, &properties)
        .map_err(failed)?
    {
        let description = object.get("description").and_then(Value::as_str);
        let description = description.map(str::to_owned);
        if let Ok(role) = serde_json::from_value::<Role>(Value::Object(object)) {
            descriptions.insert(role.id.clone(), description);
            roles.insert(role.id.clone(), role);
        }
    }
    let mut result = BTreeMap::new();
    for identifier in admin.difference(user) {
        // A user who has this role and nothing else.
        let account = Account {
            kind: "User".to_owned(),
            roles: AccountRoles::Custom {
                role_ids: RoleIds(BTreeSet::from([identifier.clone()])),
            },
            permissions: Permissions::Inherit {},
            member_tenant_id: None,
        };
        let rights = evaluate(&account, &roles, &authentication).map_err(failed)?;
        if ADMIN_PERMISSIONS
            .iter()
            .all(|name| rights.permissions.contains(*name))
        {
            let description = descriptions.get(identifier).cloned().flatten();
            result.insert(
                identifier.clone(),
                description.unwrap_or_else(|| identifier.clone()),
            );
        }
    }
    Ok(result)
}

fn init(config: &Config, force: bool) -> Result<u8, String> {
    if config.broker.policy.exists() && !force {
        say(&format!(
            "{} exists; use --force to replace it (a backup is kept).",
            config.broker.policy.display()
        ));
        return Ok(1);
    }
    let roles = administrator_roles(config)?;
    if roles.is_empty() {
        say("No native administrator role with full administrative rights was found.");
        return Ok(1);
    }
    let policy = Policy {
        profiles: default_profiles(config),
        role_bindings: roles
            .keys()
            .map(|role| (role.clone(), "administrator".to_owned()))
            .collect(),
        ..Policy::default()
    };
    locked(config, || save(config, &policy))?;
    for (identifier, description) in &roles {
        say(&format!(
            "Bound native role {identifier} ({description}) to profile administrator."
        ));
    }
    Ok(0)
}

fn check(config: &Config, subject: &str) -> Result<u8, String> {
    let policy = load(config)?;
    let account = policy
        .account_for(subject)
        .map_err(|error| error.to_string())?;
    let rights = native_rights(&native(config)?, &account).map_err(|error| error.to_string())?;
    let result = policy
        .capabilities(subject, &rights.permissions, &rights.roles)
        .map_err(|error| error.to_string())?;
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
        Command::BindRole { role, profile } => locked(config, || {
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
                .map_err(|error| error.to_string())?;
            policy.role_bindings.insert(role.clone(), profile.clone());
            save(config, &policy).map(|()| 0)
        }),
        Command::UnbindRole { role } => locked(config, || {
            let mut policy = load(config)?;
            policy.role_bindings.remove(role);
            save(config, &policy).map(|()| 0)
        }),
        Command::Deny { subject, undo } => {
            if !is_subject(subject) {
                say("Invalid subject");
                return Ok(1);
            }
            locked(config, || {
                let mut policy = load(config)?;
                if *undo {
                    policy.denied.remove(subject);
                } else {
                    policy.denied.insert(subject.clone());
                }
                save(config, &policy).map(|()| 0)
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
