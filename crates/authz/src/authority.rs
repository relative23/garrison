//! Turn a user's access token into a Garrison grant.
//!
//! Only the broker runs this. It derives the identity itself from the token
//! through UserInfo, so the web service cannot claim to be somebody else. It then
//! combines the root-managed policy with the account's current native
//! permissions, read with a dedicated read-only API key that the web service
//! never sees. Nothing is cached: every call reflects the current policy and
//! native roles.

use std::collections::BTreeSet;
use std::path::PathBuf;

use garrison_core::config::Config;
use garrison_core::credentials::{Credentials, SecretSource};
use garrison_core::modules::ModuleId;
use garrison_core::{files, time};
use garrison_stalwart::jmap::JmapClient;
use garrison_stalwart::oidc::Provider;
use garrison_stalwart::permissions::native_rights;

use crate::Error;
use crate::grant::Grant;
use crate::policy::{Policy, parse_policy};

/// The policy is small; anything larger is not a policy.
const MAX_POLICY: usize = 65536;

#[derive(Debug)]
pub struct Authority {
    provider: Provider,
    stalwart_url: String,
    credentials: Credentials,
    native_key: SecretSource,
    policy_path: PathBuf,
    action_ids: BTreeSet<String>,
    /// The installation's modules; nobody is granted another one.
    modules: BTreeSet<ModuleId>,
}

impl Authority {
    /// The broker's authority: its native key and policy from the configuration.
    pub fn new(config: &Config, credentials: Credentials) -> Self {
        let deployment = &config.deployment;
        Authority {
            provider: Provider::new(&deployment.stalwart_url, &deployment.issuer),
            stalwart_url: deployment.stalwart_url.clone(),
            credentials,
            native_key: config.broker.native_key.clone(),
            policy_path: config.broker.policy.clone(),
            action_ids: config
                .broker
                .actions
                .iter()
                .map(|action| action.id.clone())
                .collect(),
            modules: config.modules.clone(),
        }
    }

    pub fn action_ids(&self) -> BTreeSet<&str> {
        self.action_ids.iter().map(String::as_str).collect()
    }

    /// The current policy file, validated.
    pub fn policy(&self) -> Result<Policy, Error> {
        let raw = files::read_protected(&self.policy_path, MAX_POLICY)
            .map_err(|error| Error::Denied(error.to_string()))?;
        Ok(parse_policy(&raw, &self.action_ids())?)
    }

    /// A client for the management API with the broker's read-only key.
    pub fn native_client(&self) -> Result<JmapClient, Error> {
        let key = self
            .credentials
            .read_secret(&self.native_key)
            .map_err(|error| Error::Denied(error.to_string()))?;
        Ok(JmapClient::new(&self.stalwart_url, &key))
    }

    pub fn authorize(&self, token: &str) -> Result<Grant, Error> {
        self.evaluate(token).map_err(|error| match error {
            Error::Unavailable(_) => {
                Error::Unavailable("Native authorization is temporarily unavailable".into())
            }
            other => other,
        })
    }

    fn evaluate(&self, token: &str) -> Result<Grant, Error> {
        let identity = self.provider.userinfo(token, None)?;
        let policy = self.policy()?;
        let account_id = policy.account_for(&identity.subject)?;
        let rights = native_rights(&self.native_client()?, &account_id)?;
        let result = policy.capabilities(&identity.subject, &rights.permissions, &rights.roles)?;
        let modules: BTreeSet<ModuleId> = result
            .modules
            .intersection(&self.modules)
            .copied()
            .collect();
        // Actions belong to the maintenance module.
        let actions = if modules.contains(&ModuleId::Actions) {
            result.actions
        } else {
            BTreeSet::new()
        };
        Ok(Grant {
            subject: identity.subject,
            email: identity.email,
            modules,
            actions,
            profiles: result.profiles,
            checked_at: time::now_isoformat(),
        })
    }
}

#[cfg(test)]
mod tests;
