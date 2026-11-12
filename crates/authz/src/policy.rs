//! The root-managed Garrison access policy.
//!
//! The policy is an authorization boundary: unknown modules, actions, keys or
//! permission names fail closed. Native role membership alone grants nothing; a
//! binding here names the profile, and the profile's required native permissions
//! remain an upper bound. An explicit denial always wins.
//!
//! ```json
//! {
//!   "schemaVersion": 1,
//!   "profiles": {"viewer": {"modules": [], "actions": [], "requiredNativePermissions": []}},
//!   "roleBindings": {"<native role id>": "viewer"},
//!   "subjects": {"<oidc subject>": {"accountId": "<jmap id>", "profile": "viewer"}},
//!   "deniedSubjects": ["<oidc subject>"]
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};

use garrison_core::json;
use garrison_core::modules::ModuleId;
use garrison_stalwart::ids::account_id_for_subject;
use garrison_stalwart::oidc::is_subject;
use garrison_stalwart::permissions::{is_identifier, is_permission, is_verified_scope};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Error;

pub const SCHEMA_VERSION: u64 = 1;
/// Rights a profile needs before it may start host maintenance jobs.
pub const ACTION_PERMISSIONS: [&str; 2] = ["authenticate", "sysActionCreate"];

/// The policy file is malformed; nobody receives access until it is fixed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("Garrison access policy: {0}")]
pub struct PolicyError(pub String);

impl From<PolicyError> for Error {
    fn from(error: PolicyError) -> Self {
        Error::Denied(error.to_string())
    }
}

/// A profile name: `[a-z][a-z0-9_-]{0,63}`.
pub fn is_profile_name(text: &str) -> bool {
    text.len() <= 64
        && text
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

/// The file as it is written. The types say which keys there are: one that
/// is missing or unknown is refused when the file is read. What a key may
/// hold, and that names refer to something, `parse_policy` checks.
///
/// Reading takes the profiles and subjects as they are (`P`, `S` = [`Value`]),
/// so that an error can name the one it is in; writing gives them as types.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document<P, S> {
    schema_version: u64,
    profiles: BTreeMap<String, P>,
    role_bindings: BTreeMap<String, String>,
    subjects: BTreeMap<String, S>,
    denied_subjects: Vec<String>,
}

/// A profile in the file: names as they were written, in their order.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileDocument {
    modules: Vec<String>,
    actions: Vec<String>,
    required_native_permissions: Vec<String>,
}

/// Only the version, read first: a file of another schema is told so, not
/// that a key of this one is missing.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Versioned {
    schema_version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub modules: BTreeSet<ModuleId>,
    pub actions: BTreeSet<String>,
    /// Native permissions the user must currently hold for this profile to apply.
    pub required: BTreeSet<String>,
}

/// An explicit subject entry: the account to evaluate and the profile it may use.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectEntry {
    pub account_id: String,
    pub profile: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub profiles: BTreeMap<String, Profile>,
    pub role_bindings: BTreeMap<String, String>,
    pub subjects: BTreeMap<String, SubjectEntry>,
    pub denied: BTreeSet<String>,
}

/// What a user may use: the union of their eligible profiles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub modules: BTreeSet<ModuleId>,
    pub actions: BTreeSet<String>,
    pub profiles: Vec<String>,
}

fn require(condition: bool, message: impl Into<String>) -> Result<(), PolicyError> {
    if condition {
        Ok(())
    } else {
        Err(PolicyError(message.into()))
    }
}

/// A list of at most 128 distinct known names; `what` names the list in
/// messages.
fn names(items: &[String], known: impl Fn(&str) -> bool, what: &str) -> Result<(), PolicyError> {
    require(items.len() <= 128, format!("{what} must be a list"))?;
    require(
        items.iter().all(|item| known(item)),
        format!("unknown {what}"),
    )?;
    let distinct: BTreeSet<&String> = items.iter().collect();
    require(distinct.len() == items.len(), format!("duplicate {what}"))
}

fn profile(
    name: &str,
    document: ProfileDocument,
    action_ids: &BTreeSet<&str>,
) -> Result<Profile, PolicyError> {
    let ProfileDocument {
        modules,
        actions,
        required_native_permissions: required,
    } = document;
    let distinct: BTreeSet<&String> = required.iter().collect();
    require(
        (1..=128).contains(&required.len())
            && required
                .iter()
                .all(|name| is_permission(name) && is_verified_scope(name))
            && distinct.len() == required.len()
            && required.iter().any(|name| name == "authenticate"),
        format!("profile {name} requiredNativePermissions must list authenticate and sys* rights"),
    )?;
    let required: BTreeSet<String> = required.into_iter().collect();
    names(&actions, |id| action_ids.contains(id), "actions")?;
    require(
        actions.is_empty()
            || ACTION_PERMISSIONS
                .iter()
                .all(|name| required.contains(*name)),
        format!("profile {name} grants actions without requiring sysActionCreate"),
    )?;
    names(&modules, |id| id.parse::<ModuleId>().is_ok(), "modules")?;
    let modules: BTreeSet<ModuleId> = modules.iter().filter_map(|id| id.parse().ok()).collect();
    require(
        actions.is_empty() || modules.contains(&ModuleId::Actions),
        format!("profile {name} grants actions without the actions module"),
    )?;
    Ok(Profile {
        modules,
        actions: actions.into_iter().collect(),
        required,
    })
}

/// Validate a policy document against the configured action IDs.
pub fn parse_policy(raw: &Value, action_ids: &BTreeSet<&str>) -> Result<Policy, PolicyError> {
    require(raw.is_object(), "the document must be an object")?;
    let version = Versioned::deserialize(raw).map(|versioned| versioned.schema_version);
    require(
        version.is_ok_and(|version| version == SCHEMA_VERSION),
        "schemaVersion must be 1",
    )?;
    let document: Document<Value, Value> =
        json::object(raw.clone()).map_err(|error| PolicyError(error.clone()))?;
    let mut policy = Policy::default();
    require((1..=32).contains(&document.profiles.len()), "profiles")?;
    for (name, body) in document.profiles {
        require(is_profile_name(&name), "profile name")?;
        let body =
            json::object(body).map_err(|error| PolicyError(format!("profile {name}: {error}")))?;
        let profile = profile(&name, body, action_ids)?;
        policy.profiles.insert(name, profile);
    }
    require(document.role_bindings.len() <= 64, "roleBindings")?;
    for (role, name) in document.role_bindings {
        require(is_identifier(&role), "role ID")?;
        require(
            policy.profiles.contains_key(&name),
            format!("role {role} names an unknown profile"),
        )?;
        policy.role_bindings.insert(role, name);
    }
    require(document.subjects.len() <= 128, "subjects")?;
    for (subject, entry) in document.subjects {
        require(is_subject(&subject), "subject")?;
        let entry: SubjectEntry = json::object(entry)
            .map_err(|error| PolicyError(format!("subject {subject}: {error}")))?;
        require(
            is_identifier(&entry.account_id),
            format!("subject {subject} accountId"),
        )?;
        require(
            policy.profiles.contains_key(&entry.profile),
            format!("subject {subject} names an unknown profile"),
        )?;
        policy.subjects.insert(subject, entry);
    }
    let denied = document.denied_subjects;
    require(
        denied.len() <= 128 && denied.iter().all(|subject| is_subject(subject)),
        "deniedSubjects",
    )?;
    policy.denied = denied.into_iter().collect();
    Ok(policy)
}

impl Policy {
    /// The native account to evaluate. An explicit denial applies before any
    /// native lookup or ID mapping.
    pub fn account_for(&self, subject: &str) -> Result<String, Error> {
        if self.denied.contains(subject) {
            return Err(Error::Denied(
                "This identity is explicitly denied Garrison access".into(),
            ));
        }
        if let Some(entry) = self.subjects.get(subject) {
            return Ok(entry.account_id.clone());
        }
        if self.role_bindings.is_empty() {
            return Err(Error::Denied("This identity has no Garrison grant".into()));
        }
        account_id_for_subject(subject)
    }

    /// Union the eligible profiles; current native permissions are an upper bound.
    pub fn capabilities(
        &self,
        subject: &str,
        permissions: &BTreeSet<String>,
        role_ids: &BTreeSet<String>,
    ) -> Result<Capabilities, Error> {
        let mut candidates: BTreeSet<&str> = role_ids
            .iter()
            .filter_map(|role| self.role_bindings.get(role))
            .map(String::as_str)
            .collect();
        if let Some(entry) = self.subjects.get(subject) {
            candidates.insert(&entry.profile);
        }
        let mut result = Capabilities {
            modules: BTreeSet::new(),
            actions: BTreeSet::new(),
            profiles: Vec::new(),
        };
        for name in candidates {
            let profile = &self.profiles[name];
            if profile.required.is_subset(permissions) {
                result.profiles.push(name.to_owned());
                result.modules.extend(&profile.modules);
                result.actions.extend(profile.actions.iter().cloned());
            }
        }
        if result.modules.is_empty() {
            return Err(Error::Denied(
                "This identity has no eligible Garrison profile".into(),
            ));
        }
        Ok(result)
    }

    /// The document form, with sorted keys and lists, for the access command.
    pub fn to_document(&self) -> Value {
        let profiles = self.profiles.iter().map(|(name, profile)| {
            let document = ProfileDocument {
                modules: profile
                    .modules
                    .iter()
                    .map(|id| id.as_str().to_owned())
                    .collect(),
                actions: profile.actions.iter().cloned().collect(),
                required_native_permissions: profile.required.iter().cloned().collect(),
            };
            (name.clone(), document)
        });
        let document = Document {
            schema_version: SCHEMA_VERSION,
            profiles: profiles.collect(),
            role_bindings: self.role_bindings.clone(),
            subjects: self.subjects.clone(),
            denied_subjects: self.denied.iter().cloned().collect(),
        };
        serde_json::to_value(document).unwrap_or(Value::Null)
    }
}

#[cfg(test)]
mod tests;
