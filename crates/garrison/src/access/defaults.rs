//! The policy that `garrison access init` writes: the default profiles,
//! from the configuration's actions, and the native roles it binds to the
//! administrator profile, from Stalwart's.

use std::collections::{BTreeMap, BTreeSet};

use garrison_authz::policy::{ACTION_PERMISSIONS, Policy, Profile};
use garrison_core::config::Config;
use garrison_core::modules::ModuleId;
use garrison_stalwart::jmap::Object;
use garrison_stalwart::permissions::{
    AUTHENTICATION_PROPERTIES, Account, AccountRoles, Authentication, Permissions, ROLE_PROPERTIES,
    Role, RoleIds, evaluate,
};
use serde_json::Value;

use super::{native, said};

const VIEWER_PERMISSIONS: [&str; 3] = ["authenticate", "sysAccountGet", "sysDomainGet"];
const ADMIN_PERMISSIONS: [&str; 5] = [
    "authenticate",
    "sysAccountUpdate",
    "sysDomainUpdate",
    "sysRoleUpdate",
    "sysActionCreate",
];

fn strings(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

pub(super) fn default_profiles(config: &Config) -> BTreeMap<String, Profile> {
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

/// Stalwart's roles as this release reads them.
pub(super) struct Roles {
    authentication: Authentication,
    readable: BTreeMap<String, Role>,
    descriptions: BTreeMap<String, String>,
    /// Every role's ID, those this release cannot read among them.
    ids: BTreeSet<String>,
}

impl Roles {
    /// Every role of the server, also those of tenants and of other
    /// software. One this release cannot read is left out, and a role that
    /// inherits from it is then not evaluated as one.
    pub(super) fn read(config: &Config) -> Result<Roles, String> {
        let client = native(config)?;
        let authentication: Authentication = client
            .get(
                "Authentication",
                Some(&["singleton"]),
                &AUTHENTICATION_PROPERTIES,
            )
            .map_err(said)?
            .into_iter()
            .next()
            .ok_or("Stalwart returned no object")?;
        let mut properties: Vec<&str> = ROLE_PROPERTIES.to_vec();
        properties.push("description");
        let mut roles = Roles {
            authentication,
            readable: BTreeMap::new(),
            descriptions: BTreeMap::new(),
            ids: BTreeSet::new(),
        };
        for object in client
            .get::<Object>("Role", None, &properties)
            .map_err(said)?
        {
            let id = object.get("id").and_then(Value::as_str).map(str::to_owned);
            let description = object.get("description").and_then(Value::as_str);
            let description = description.map(str::to_owned);
            roles.ids.extend(id);
            if let Ok(role) = serde_json::from_value::<Role>(Value::Object(object)) {
                if let Some(description) = description {
                    roles.descriptions.insert(role.id.clone(), description);
                }
                roles.readable.insert(role.id.clone(), role);
            }
        }
        Ok(roles)
    }

    pub(super) fn exists(&self, role: &str) -> bool {
        self.ids.contains(role)
    }

    /// The rights of a user who has `role` and nothing else; none where
    /// this release cannot read the role.
    pub(super) fn rights(&self, role: &str) -> Result<Option<BTreeSet<String>>, String> {
        if !self.readable.contains_key(role) {
            return Ok(None);
        }
        let account = Account {
            kind: "User".to_owned(),
            roles: AccountRoles::Custom {
                role_ids: RoleIds(BTreeSet::from([role.to_owned()])),
            },
            permissions: Permissions::Inherit {},
            member_tenant_id: None,
        };
        let rights = evaluate(&account, &self.readable, &self.authentication).map_err(said)?;
        Ok(Some(rights.permissions))
    }
}

/// One of Stalwart's default administrator roles as it is: what it lacks of
/// the administrator profile's rights, and the default profiles it meets.
pub(super) struct Candidate {
    pub(super) description: String,
    pub(super) lacks: Vec<String>,
    pub(super) meets: Vec<String>,
}

/// Stalwart's default *administrator* roles (not also default user roles),
/// each as it is; `init` binds those that lack nothing.
pub(super) fn administrator_roles(config: &Config) -> Result<BTreeMap<String, Candidate>, String> {
    let roles = Roles::read(config)?;
    let profiles = default_profiles(config);
    let admin = &roles.authentication.default_admin_role_ids.0;
    let user = &roles.authentication.default_user_role_ids.0;
    let mut result = BTreeMap::new();
    for identifier in admin.difference(user) {
        let Some(rights) = roles.rights(identifier)? else {
            continue;
        };
        let description = roles.descriptions.get(identifier);
        result.insert(
            identifier.clone(),
            Candidate {
                description: description.unwrap_or(identifier).clone(),
                lacks: lacking(&strings(&ADMIN_PERMISSIONS), &rights),
                meets: meets(&profiles, &rights),
            },
        );
    }
    Ok(result)
}

/// What of `required` `rights` does not hold, in order.
fn lacking(required: &BTreeSet<String>, rights: &BTreeSet<String>) -> Vec<String> {
    ADMIN_PERMISSIONS
        .iter()
        .map(|name| (*name).to_owned())
        .chain(required.iter().cloned())
        .filter(|name| required.contains(name) && !rights.contains(name))
        .fold(Vec::new(), |mut names, name| {
            if !names.contains(&name) {
                names.push(name);
            }
            names
        })
}

/// The profiles whose required rights `rights` holds.
fn meets(profiles: &BTreeMap<String, Profile>, rights: &BTreeSet<String>) -> Vec<String> {
    profiles
        .iter()
        .filter(|(_, profile)| profile.required.is_subset(rights))
        .map(|(name, _)| name.clone())
        .collect()
}

/// `a`, `a and b`, `a, b and c`.
fn listed(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [first @ .., last] => format!("{} and {last}", first.join(", ")),
    }
}

/// What a role meets as it is, as a sentence ends.
fn as_it_is(meets: &[String]) -> String {
    match meets {
        [] => "As it is, it meets none of the profiles.".to_owned(),
        [one] => format!("As it is, it meets the profile {one}."),
        more => format!("As it is, it meets the profiles {}.", listed(more)),
    }
}

/// What `init` says where it bound no role: what the administrator profile
/// requires, and for each of Stalwart's default administrator roles what
/// it lacks of that, where to give it, and what it meets as it is.
pub(super) fn unbound(candidates: &BTreeMap<String, Candidate>) -> String {
    let required: Vec<String> = ADMIN_PERMISSIONS.map(str::to_owned).to_vec();
    let mut lines = vec![format!(
        "No native administrator role with full administrative rights was found, so the policy \
         binds no role and nobody can sign in yet. The administrator profile requires {}.",
        listed(&required)
    )];
    if candidates.is_empty() {
        lines.push(
            "Stalwart names no default administrator role: once the role of your \
             administrators holds these rights, bind it with garrison access bind-role \
             <role-id> --profile administrator."
                .to_owned(),
        );
    }
    for (identifier, candidate) in candidates {
        lines.push(format!(
            "Stalwart's default administrator role {identifier} ({}) lacks {}: give the role {} \
             in the native administration (Roles), then run garrison access bind-role \
             {identifier} --profile administrator. {}",
            candidate.description,
            listed(&candidate.lacks),
            if candidate.lacks.len() == 1 {
                "that right"
            } else {
                "those rights"
            },
            as_it_is(&candidate.meets)
        ));
    }
    lines.join("\n")
}

/// What `bind-role` says where `role` lacks a right that `profile` of
/// `policy` requires, or where its rights could not be read: its users get
/// nothing of the profile until Stalwart gives the role those rights.
pub(super) fn fit(
    policy: &Policy,
    profile: &str,
    role: &str,
    rights: Option<&BTreeSet<String>>,
) -> Option<String> {
    let required = &policy.profiles.get(profile)?.required;
    let Some(rights) = rights else {
        return Some(format!(
            "Note: this release cannot read the rights of role {role}, so whether its users get \
             the profile {profile} is not known; `garrison access check <subject>` shows what a \
             user gets."
        ));
    };
    let lacks = lacking(required, rights);
    (!lacks.is_empty()).then(|| {
        format!(
            "Note: role {role} lacks {}, which the profile {profile} requires, so its users get \
             nothing of it until Stalwart's administrator gives the role {} in the native \
             administration (Roles). {}",
            listed(&lacks),
            if lacks.len() == 1 {
                "that right"
            } else {
                "those rights"
            },
            as_it_is(&meets(&policy.profiles, rights))
        )
    })
}

/// The default profiles whose actions follow garrison.toml: `init` gives
/// them every action and those marked `operator = true`.
const FOLLOWING: [&str; 2] = ["administrator", "operator"];

/// Whether `profile` may hold actions at all: the policy refuses actions in
/// a profile without the maintenance module or without the right to start
/// them.
fn holds_actions(profile: &Profile) -> bool {
    profile.modules.contains(&ModuleId::Actions)
        && ACTION_PERMISSIONS
            .iter()
            .all(|name| profile.required.contains(*name))
}

/// Give the default profiles the actions `init` gives them, as
/// garrison.toml has them now, where they may hold actions, and take from
/// every profile the actions garrison.toml no longer has. What changed,
/// one line for each profile.
pub(super) fn follow(config: &Config, policy: &mut Policy) -> Vec<String> {
    let configured: BTreeSet<String> = config
        .broker
        .actions
        .iter()
        .map(|action| action.id.clone())
        .collect();
    let defaults = default_profiles(config);
    let mut changes = Vec::new();
    for (name, profile) in &mut policy.profiles {
        let wanted = match defaults.get(name) {
            Some(default) if FOLLOWING.contains(&name.as_str()) && holds_actions(profile) => {
                default.actions.clone()
            }
            _ => profile.actions.intersection(&configured).cloned().collect(),
        };
        let added: Vec<&str> = wanted
            .difference(&profile.actions)
            .map(String::as_str)
            .collect();
        let taken: Vec<&str> = profile
            .actions
            .difference(&wanted)
            .map(String::as_str)
            .collect();
        let said: Vec<String> = [(added, "added"), (taken, "taken out")]
            .into_iter()
            .filter(|(actions, _)| !actions.is_empty())
            .map(|(actions, what)| format!("{} {what}", actions.join(", ")))
            .collect();
        if !said.is_empty() {
            changes.push(format!("Profile {name}: {}.", said.join(", ")));
        }
        profile.actions = wanted;
    }
    changes
}
