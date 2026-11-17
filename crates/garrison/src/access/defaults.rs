//! The policy that `garrison access init` writes: the default profiles,
//! from the configuration's actions, and the native roles it binds to the
//! administrator profile, from Stalwart's.

use std::collections::{BTreeMap, BTreeSet};

use garrison_authz::policy::Profile;
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

/// Roles that are default *administrator* roles and hold all admin rights.
pub(super) fn administrator_roles(config: &Config) -> Result<BTreeMap<String, String>, String> {
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
        .map_err(said)?
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
        let rights = evaluate(&account, &roles, &authentication).map_err(said)?;
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
