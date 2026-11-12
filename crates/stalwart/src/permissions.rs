//! Evaluate Stalwart's native role model for one account.
//!
//! Stalwart 1.0 offers no API that returns another account's effective
//! permissions, so this module reproduces the documented rules: role
//! inheritance, Merge/Replace overrides and "disabled wins". The contract tests
//! compare the result with the server's own answer (`/api/account`) for several
//! account shapes, so a changed upstream rule fails a test instead of silently
//! granting access.
//!
//! Cycles, missing roles, tenant members and unrecognized shapes deny access.

use std::collections::{BTreeMap, BTreeSet};

use garrison_core::json;
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::Error;
use crate::jmap::JmapClient;

pub const MAX_ROLES: usize = 64;
const MAX_DEPTH: usize = 16;
const MAX_PERMISSIONS: usize = 2048;
/// The properties each type below reads; nothing else is requested.
pub const ROLE_PROPERTIES: [&str; 5] = [
    "id",
    "roleIds",
    "enabledPermissions",
    "disabledPermissions",
    "memberTenantId",
];
pub const ACCOUNT_PROPERTIES: [&str; 5] = ["id", "@type", "roles", "permissions", "memberTenantId"];
pub const AUTHENTICATION_PROPERTIES: [&str; 3] =
    ["id", "defaultAdminRoleIds", "defaultUserRoleIds"];
/// Stored in the System Administrator role, but withheld by the server once the
/// bootstrap is complete, as `/api/account` shows.
const RUNTIME_WITHHELD: [&str; 2] = ["sysBootstrapGet", "sysBootstrapUpdate"];

/// A role, account or tenant ID: `[A-Za-z0-9_-]{1,128}`.
pub fn is_identifier(text: &str) -> bool {
    (1..=128).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// A permission name: `[a-z][A-Za-z0-9]{0,127}`.
pub fn is_permission(text: &str) -> bool {
    text.len() <= 128
        && text
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && text.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// Permissions whose evaluation the contract tests check for exact equality.
///
/// The server applies further runtime filters to mail-client permissions (for
/// example it withholds jmapPrincipalQuery from ordinary users). Garrison
/// never relies on those: profiles may only require `authenticate` and `sys*`
/// rights.
pub fn is_verified_scope(permission: &str) -> bool {
    permission == "authenticate" || permission.starts_with("sys")
}

/// The names a native `{"name": true}` map switches on; false entries grant
/// nothing. A map with more than `limit` entries or with a name `valid`
/// refuses is malformed, as is one with a value that is no boolean.
fn switched_on<'de, D: Deserializer<'de>>(
    deserializer: D,
    limit: usize,
    valid: fn(&str) -> bool,
) -> Result<BTreeSet<String>, D::Error> {
    let map = BTreeMap::<String, bool>::deserialize(deserializer)?;
    if map.len() > limit || !map.keys().all(|name| valid(name)) {
        return Err(D::Error::custom("malformed native permission map"));
    }
    Ok(map
        .into_iter()
        .filter_map(|(name, on)| on.then_some(name))
        .collect())
}

/// The role IDs of a native `{"id": true}` map, at most [`MAX_ROLES`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoleIds(pub BTreeSet<String>);

impl<'de> Deserialize<'de> for RoleIds {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        switched_on(deserializer, MAX_ROLES, is_identifier).map(RoleIds)
    }
}

/// The permission names of a native `{"name": true}` map.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermissionNames(pub BTreeSet<String>);

impl<'de> Deserialize<'de> for PermissionNames {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        switched_on(deserializer, MAX_PERMISSIONS, is_permission).map(PermissionNames)
    }
}

/// A variant object such as `{"@type": "Custom", ...}`, and nothing serde
/// would read as one besides (see [`json::object`]).
fn variant<'de, D: Deserializer<'de>, T: DeserializeOwned>(deserializer: D) -> Result<T, D::Error> {
    json::object(Value::deserialize(deserializer)?).map_err(D::Error::custom)
}

/// Which roles an account has. A variant with a key that is not listed here
/// is not read as that variant: the braces make serde refuse the key.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "@type", deny_unknown_fields)]
pub enum AccountRoles {
    /// The server's default roles for administrators.
    Admin {},
    /// The server's default roles for users.
    User {},
    Custom {
        #[serde(rename = "roleIds")]
        role_ids: RoleIds,
    },
}

/// An account's own permission lists and how they combine with its roles'.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "@type", deny_unknown_fields)]
pub enum Permissions {
    /// Permissions come from the roles alone.
    Inherit {},
    /// The account's own lists are added to its roles' lists.
    #[serde(rename_all = "camelCase")]
    Merge {
        enabled_permissions: PermissionNames,
        disabled_permissions: PermissionNames,
    },
    /// The account's own lists replace its roles entirely.
    #[serde(rename_all = "camelCase")]
    Replace {
        enabled_permissions: PermissionNames,
        disabled_permissions: PermissionNames,
    },
}

/// A native account, as far as its rights depend on it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    #[serde(rename = "@type")]
    pub kind: String,
    #[serde(deserialize_with = "variant")]
    pub roles: AccountRoles,
    #[serde(deserialize_with = "variant")]
    pub permissions: Permissions,
    /// Set for a member of a tenant; Garrison evaluates no such account.
    #[serde(default)]
    pub member_tenant_id: Option<String>,
}

/// The server's authentication settings: the default roles.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authentication {
    pub id: String,
    pub default_admin_role_ids: RoleIds,
    pub default_user_role_ids: RoleIds,
}

/// A native role: its own permission lists and the roles it inherits from.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    pub id: String,
    pub role_ids: RoleIds,
    pub enabled_permissions: PermissionNames,
    pub disabled_permissions: PermissionNames,
    /// Set for a tenant's role, which no evaluation uses.
    #[serde(default)]
    pub member_tenant_id: Option<String>,
}

impl Account {
    /// The Admin/User/Custom role IDs assigned to a non-tenant user.
    pub fn role_ids<'a>(
        &'a self,
        authentication: &'a Authentication,
    ) -> Result<&'a BTreeSet<String>, Error> {
        if self.kind != "User" || self.member_tenant_id.is_some() {
            return Err(Error::denied(
                "A non-tenant native user account is required",
            ));
        }
        if authentication.id != "singleton" {
            return Err(Error::denied(
                "Native authentication configuration is unavailable",
            ));
        }
        Ok(match &self.roles {
            AccountRoles::Admin {} => &authentication.default_admin_role_ids.0,
            AccountRoles::User {} => &authentication.default_user_role_ids.0,
            AccountRoles::Custom { role_ids } => &role_ids.0,
        })
    }

    /// Whether the account's own lists replace its roles, and the lists.
    fn own_lists(&self) -> (bool, BTreeSet<String>, BTreeSet<String>) {
        match &self.permissions {
            Permissions::Inherit {} => (false, BTreeSet::new(), BTreeSet::new()),
            Permissions::Merge {
                enabled_permissions,
                disabled_permissions,
            } => (
                false,
                enabled_permissions.0.clone(),
                disabled_permissions.0.clone(),
            ),
            Permissions::Replace {
                enabled_permissions,
                disabled_permissions,
            } => (
                true,
                enabled_permissions.0.clone(),
                disabled_permissions.0.clone(),
            ),
        }
    }
}

/// The outcome of an evaluation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rights {
    /// Effective permissions.
    pub permissions: BTreeSet<String>,
    /// Every role that contributed, including inherited ones.
    pub roles: BTreeSet<String>,
}

pub fn evaluate(
    account: &Account,
    roles: &BTreeMap<String, Role>,
    authentication: &Authentication,
) -> Result<Rights, Error> {
    let assigned = account.role_ids(authentication)?;
    let (replaces, enabled, disabled) = account.own_lists();
    if roles.len() > MAX_ROLES {
        return Err(Error::denied("Native role graph is too large"));
    }
    let mut walk = Walk {
        roles,
        enabled,
        disabled,
        active: BTreeSet::new(),
        complete: BTreeSet::new(),
    };
    if !replaces {
        for identifier in assigned {
            walk.visit(identifier, 0)?;
        }
    }
    let permissions = walk
        .enabled
        .difference(&walk.disabled)
        .filter(|name| !RUNTIME_WITHHELD.contains(&name.as_str()))
        .cloned()
        .collect();
    Ok(Rights {
        permissions,
        roles: walk.complete,
    })
}

struct Walk<'a> {
    roles: &'a BTreeMap<String, Role>,
    enabled: BTreeSet<String>,
    disabled: BTreeSet<String>,
    /// Roles on the current inheritance path, to detect cycles.
    active: BTreeSet<String>,
    complete: BTreeSet<String>,
}

impl Walk<'_> {
    fn visit(&mut self, identifier: &str, depth: usize) -> Result<(), Error> {
        if depth > MAX_DEPTH || self.active.contains(identifier) {
            return Err(Error::denied(
                "Native role inheritance cycle or depth limit",
            ));
        }
        if self.complete.contains(identifier) {
            return Ok(());
        }
        let role = self
            .roles
            .get(identifier)
            .filter(|role| role.id == identifier && role.member_tenant_id.is_none())
            .ok_or_else(|| Error::denied("Required native role is unavailable"))?;
        self.active.insert(identifier.to_owned());
        self.enabled
            .extend(role.enabled_permissions.0.iter().cloned());
        self.disabled
            .extend(role.disabled_permissions.0.iter().cloned());
        for parent in &role.role_ids.0 {
            self.visit(parent, depth + 1)?;
        }
        self.active.remove(identifier);
        self.complete.insert(identifier.to_owned());
        Ok(())
    }
}

/// Read one account's role graph from Stalwart and evaluate it.
///
/// Roles are fetched in batches of eight, only as far as the account's roles
/// reach, and never more than [`MAX_ROLES`].
pub fn native_rights(client: &JmapClient, account_id: &str) -> Result<Rights, Error> {
    let account: Account =
        first(client.get("Account", Some(&[account_id]), &ACCOUNT_PROPERTIES)?)?;
    let authentication: Authentication = first(client.get(
        "Authentication",
        Some(&["singleton"]),
        &AUTHENTICATION_PROPERTIES,
    )?)?;
    let mut roles = BTreeMap::new();
    let mut pending = if account.own_lists().0 {
        BTreeSet::new()
    } else {
        account.role_ids(&authentication)?.clone()
    };
    while !pending.is_empty() {
        let batch: Vec<&str> = pending.iter().take(8).map(String::as_str).collect();
        if roles.len() + batch.len() > MAX_ROLES {
            return Err(Error::denied("Native role graph is too large"));
        }
        let mut parents = BTreeSet::new();
        for role in client.get::<Role>("Role", Some(&batch), &ROLE_PROPERTIES)? {
            parents.extend(role.role_ids.0.iter().cloned());
            roles.insert(role.id.clone(), role);
        }
        pending.extend(parents);
        pending.retain(|identifier| !roles.contains_key(identifier));
    }
    evaluate(&account, &roles, &authentication)
}

fn first<T>(objects: Vec<T>) -> Result<T, Error> {
    objects
        .into_iter()
        .next()
        .ok_or_else(|| Error::denied("Native API returned incomplete data"))
}

#[cfg(test)]
mod tests;
