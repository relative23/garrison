//! The policy that `garrison access init` writes: the default profiles,
//! from the configuration's actions, and the native roles it binds to the
//! administrator profile, from Stalwart's.

use std::collections::{BTreeMap, BTreeSet};

use garrison_authz::Error;
use garrison_authz::policy::{ACTION_PERMISSIONS, Policy, Profile};
use garrison_core::config::Config;
use garrison_core::json;
use garrison_core::modules::ModuleId;
use garrison_stalwart::ids::decode_native_id;
use garrison_stalwart::jmap::{Get, Got, JmapClient, Object};
use garrison_stalwart::permissions::{
    AUTHENTICATION_PROPERTIES, Account, AccountRoles, Authentication, MAX_ROLES, Permissions,
    ROLE_PROPERTIES, Role, RoleIds, evaluate,
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

/// The server's authentication settings, which name its default roles.
pub(super) fn authentication(client: &JmapClient) -> Result<Authentication, String> {
    client
        .get(
            "Authentication",
            Some(&["singleton"]),
            &AUTHENTICATION_PROPERTIES,
        )
        .map_err(said)?
        .into_iter()
        .next()
        .ok_or_else(|| "Stalwart returned no object".to_owned())
}

/// The roles `ids` as Stalwart sends them, with their descriptions, and the
/// IDs it says it does not have; any other answer is one this release does
/// not read.
fn by_id(client: &JmapClient, ids: &[&str]) -> Result<(Vec<Object>, Vec<String>), String> {
    let method = "x:Role/get";
    let mut properties: Vec<&str> = ROLE_PROPERTIES.to_vec();
    properties.push("description");
    let asked = Get {
        ids: Some(ids),
        properties: Some(&properties),
    };
    let unread = || {
        said(Error::Unreadable(format!(
            "{method} did not return the objects asked for"
        )))
    };
    let got: Got<Value> = json::object(Value::Object(client.call(method, asked).map_err(said)?))
        .map_err(|_| unread())?;
    let missing: Vec<String> = got
        .not_found
        .unwrap_or_default()
        .iter()
        .filter_map(|id| id.as_str().map(str::to_owned))
        .collect();
    let objects: Vec<Object> = got
        .list
        .into_iter()
        .filter_map(|item| match item {
            Value::Object(object) => Some(object),
            _ => None,
        })
        .collect();
    let mut answered: Vec<&str> = objects
        .iter()
        .filter_map(|object| object.get("id").and_then(Value::as_str))
        .chain(missing.iter().map(String::as_str))
        .collect();
    answered.sort_unstable();
    let mut wanted = ids.to_vec();
    wanted.sort_unstable();
    if answered != wanted {
        return Err(unread());
    }
    Ok((objects, missing))
}

/// One of Stalwart's roles as `garrison access` judges it: its description,
/// and what a user who has it and nothing else may do, or why that cannot
/// be evaluated.
pub(super) struct Judged {
    pub(super) description: Option<String>,
    pub(super) rights: Result<BTreeSet<String>, String>,
}

/// `role` judged as the broker judges an account's roles: the role and those
/// it inherits from are read, eight at a time and no more than an evaluation
/// takes, and never the server's other roles. `None` where Stalwart has no
/// such role.
pub(super) fn judged(
    client: &JmapClient,
    authentication: &Authentication,
    role: &str,
) -> Result<Option<Judged>, String> {
    // A role's ID is a numeral of Stalwart's: any other is none of its
    // roles', and Stalwart is not asked.
    if decode_native_id(role).is_none() {
        return Ok(None);
    }
    let mut roles = BTreeMap::new();
    let mut description = None;
    let mut pending = BTreeSet::from([role.to_owned()]);
    let not = |description: Option<String>, why: String| {
        Ok(Some(Judged {
            description,
            rights: Err(why),
        }))
    };
    while !pending.is_empty() {
        let batch: Vec<&str> = pending.iter().take(8).map(String::as_str).collect();
        if roles.len() + batch.len() > MAX_ROLES {
            let why = format!(
                "it inherits from more than {MAX_ROLES} roles, more than Garrison evaluates"
            );
            return not(description, why);
        }
        let (objects, missing) = by_id(client, &batch)?;
        if missing.iter().any(|id| id == role) {
            return Ok(None);
        }
        if let Some(gone) = missing.first() {
            return not(
                description,
                format!("it inherits from role {gone}, which Stalwart does not have"),
            );
        }
        for object in objects {
            let id = object
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if id == role {
                description = object
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            let Ok(read) = serde_json::from_value::<Role>(Value::Object(object)) else {
                return not(description, format!("this release cannot read role {id}"));
            };
            // A tenant's role grants nothing the broker evaluates.
            if read.member_tenant_id.is_some() {
                let why = if id == role {
                    "it belongs to a tenant".to_owned()
                } else {
                    format!("role {id}, from which it inherits, belongs to a tenant")
                };
                return not(description, why);
            }
            pending.extend(read.role_ids.0.iter().cloned());
            roles.insert(read.id.clone(), read);
        }
        pending.retain(|id| !roles.contains_key(id));
    }
    let account = Account {
        kind: "User".to_owned(),
        roles: AccountRoles::Custom {
            role_ids: RoleIds(BTreeSet::from([role.to_owned()])),
        },
        permissions: Permissions::Inherit {},
        member_tenant_id: None,
    };
    let rights = evaluate(&account, &roles, authentication)
        .map(|rights| rights.permissions)
        .map_err(|error| error.to_string());
    Ok(Some(Judged {
        description,
        rights,
    }))
}

/// One of Stalwart's default administrator roles as it is: what it lacks of
/// the administrator profile's rights and the default profiles it meets, or
/// why `init` leaves it out.
pub(super) struct Candidate {
    pub(super) description: Option<String>,
    pub(super) fit: Result<Fit, String>,
}

pub(super) struct Fit {
    pub(super) lacks: Vec<String>,
    pub(super) meets: Vec<String>,
}

/// Stalwart's default administrator roles, each as it is. `init` binds those
/// that lack nothing, and leaves out one that is every user's default role
/// too, which would make every user an administrator.
pub(super) fn administrator_roles(config: &Config) -> Result<BTreeMap<String, Candidate>, String> {
    let client = native(config)?;
    let authentication = authentication(&client)?;
    let profiles = default_profiles(config);
    let user = &authentication.default_user_role_ids.0;
    let mut result = BTreeMap::new();
    for identifier in &authentication.default_admin_role_ids.0 {
        let left = |why: &str| Candidate {
            description: None,
            fit: Err(why.to_owned()),
        };
        let candidate = if user.contains(identifier) {
            left(
                "it is every user's default role too, and binding it would make every user an \
                 administrator",
            )
        } else {
            match judged(&client, &authentication, identifier)? {
                None => left("Stalwart has no role of that ID"),
                Some(Judged {
                    description,
                    rights,
                }) => Candidate {
                    description,
                    fit: rights
                        .map(|rights| Fit {
                            lacks: lacking(&strings(&ADMIN_PERMISSIONS), &rights),
                            meets: meets(&profiles, &rights),
                        })
                        .map_err(|why| format!("its rights cannot be evaluated ({why})")),
                },
            }
        };
        result.insert(identifier.clone(), candidate);
    }
    Ok(result)
}

/// The candidates that lack nothing of the administrator profile's rights.
pub(super) fn qualified(candidates: &BTreeMap<String, Candidate>) -> Vec<String> {
    candidates
        .iter()
        .filter(|(_, candidate)| candidate.fit.as_ref().is_ok_and(|fit| fit.lacks.is_empty()))
        .map(|(identifier, _)| identifier.clone())
        .collect()
}

/// A role as messages name it: its ID, with its description where it has one.
pub(super) fn named(identifier: &str, candidate: &Candidate) -> String {
    match &candidate.description {
        Some(description) => format!("{identifier} ({description})"),
        None => identifier.to_owned(),
    }
}

/// What of `required` `rights` does not hold.
fn lacking(required: &BTreeSet<String>, rights: &BTreeSet<String>) -> Vec<String> {
    required.difference(rights).cloned().collect()
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

/// The rights the administrator profile requires, as a sentence.
pub(super) fn requires() -> String {
    let required: Vec<String> = strings(&ADMIN_PERMISSIONS).into_iter().collect();
    format!("The administrator profile requires {}.", listed(&required))
}

/// For each of Stalwart's default administrator roles what it lacks of the
/// administrator profile's rights, where to give them and what it meets as
/// it is, or why `init` leaves it out; and how to bind a role of one's own
/// where none is left that only lacks rights. One line each.
pub(super) fn candidates_said(candidates: &BTreeMap<String, Candidate>) -> Vec<String> {
    let mut lines = Vec::new();
    for (identifier, candidate) in candidates {
        let role = named(identifier, candidate);
        lines.push(match &candidate.fit {
            Ok(fit) => format!(
                "Stalwart's default administrator role {role} lacks {}: give the role {} in the \
                 native administration (Roles), then run garrison access bind-role {identifier} \
                 --profile administrator. {}",
                listed(&fit.lacks),
                if fit.lacks.len() == 1 {
                    "that right"
                } else {
                    "those rights"
                },
                as_it_is(&fit.meets)
            ),
            Err(why) => format!("Stalwart's default administrator role {role} is left out: {why}."),
        });
    }
    let bind = "bind it with garrison access bind-role <role-id> --profile administrator.";
    if candidates.is_empty() {
        lines.push(format!(
            "Stalwart names no default administrator role: once the role of your \
             administrators holds these rights, {bind}"
        ));
    } else if candidates.values().all(|candidate| candidate.fit.is_err()) {
        lines.push(format!(
            "Once the role of your administrators holds these rights, {bind}"
        ));
    }
    lines
}

/// What `init` says where it bound no role and wrote the policy anew.
pub(super) fn unbound(candidates: &BTreeMap<String, Candidate>) -> String {
    let mut lines = vec![format!(
        "No native administrator role with full administrative rights was found, so the policy \
         binds no role and nobody can sign in yet. {}",
        requires()
    )];
    lines.extend(candidates_said(candidates));
    lines.join("\n")
}

/// What `bind-role` says where `role` lacks a right that `profile` of
/// `policy` requires, or where its rights cannot be evaluated: its users get
/// nothing of the profile until Stalwart gives the role those rights.
pub(super) fn fit(
    policy: &Policy,
    profile: &str,
    role: &str,
    rights: Result<&BTreeSet<String>, &String>,
) -> Option<String> {
    let required = &policy.profiles.get(profile)?.required;
    let rights = match rights {
        Ok(rights) => rights,
        Err(why) => {
            return Some(format!(
                "Note: the rights of role {role} cannot be evaluated ({why}), so whether its \
                 users get the profile {profile} is not known; `garrison access check \
                 <subject>` shows what a user gets."
            ));
        }
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
