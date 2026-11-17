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
use garrison_core::credentials::{Credentials, SecretSource, made_by_setup};
use garrison_core::modules::ModuleId;
use garrison_core::{files, time};
use garrison_stalwart::jmap::JmapClient;
use garrison_stalwart::oidc::Provider;
use garrison_stalwart::permissions::native_rights;

use crate::Error;
use crate::grant::Grant;
use crate::policy::{Capabilities, Policy, parse_policy};

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
            .map_err(|error| Error::Misconfigured(format!("Garrison access policy: {error}")))?;
        Ok(parse_policy(&raw, &self.action_ids())?)
    }

    /// A client for the management API with the broker's read-only key. An
    /// empty key file is no key, as a missing one is not.
    pub fn native_client(&self) -> Result<JmapClient, Error> {
        let key = self
            .credentials
            .read_secret(&self.native_key)
            .map_err(|error| {
                let made = made_by_setup(&error);
                Error::Misconfigured(format!("the broker's API key: {error}{made}"))
            })?;
        Ok(JmapClient::new(&self.stalwart_url, &key))
    }

    /// What `capabilities` leave to grant on this installation: only the
    /// modules it offers, actions only with the maintenance module, and a
    /// refusal where no module is left. The broker grants this, and
    /// `garrison access check` shows it.
    pub fn offered(&self, capabilities: Capabilities) -> Result<Capabilities, Error> {
        let modules: BTreeSet<ModuleId> = capabilities
            .modules
            .intersection(&self.modules)
            .copied()
            .collect();
        // Profiles that name only modules this installation does not offer
        // leave nothing to grant. That is what the policy says of this user,
        // as a missing profile is, and no grant the web service must refuse.
        if modules.is_empty() {
            return Err(Error::Denied(
                "This identity's profiles grant no module this installation offers".into(),
            ));
        }
        // Actions belong to the maintenance module.
        let actions = if modules.contains(&ModuleId::Actions) {
            capabilities.actions
        } else {
            BTreeSet::new()
        };
        Ok(Capabilities {
            modules,
            actions,
            profiles: capabilities.profiles,
        })
    }

    /// The grant of the token's user, or why there is none. An error met at
    /// Stalwart names the request that met it where that tells something,
    /// so that the broker's journal can say it.
    pub fn authorize(&self, token: &str) -> Result<Grant, Error> {
        let identity = self
            .provider
            .userinfo(token, None)
            .map_err(|error| asked(error, "the user's token", "UserInfo"))?;
        let policy = self.policy()?;
        let account_id = policy.account_for(&identity.subject)?;
        // The broker asks with its own key. What Stalwart refuses here is
        // about that key, never about the user, who is refused only by the
        // policy; an answer this release does not read is that answer's.
        let rights =
            native_rights(&self.native_client()?, &account_id).map_err(|error| match error {
                Error::Denied(reason) | Error::InvalidToken(reason) => Error::Misconfigured(
                    format!("the account's rights could not be read from Stalwart: {reason}"),
                ),
                error @ (Error::Unavailable(_)
                | Error::Limited(_)
                | Error::Unreadable(_)
                | Error::Misconfigured(_)) => {
                    asked(error, "the broker's key", "the management API")
                }
            })?;
        let offered = self.offered(policy.capabilities(
            &identity.subject,
            &rights.permissions,
            &rights.roles,
        )?)?;
        Ok(Grant {
            subject: identity.subject,
            email: identity.email,
            modules: offered.modules,
            actions: offered.actions,
            profiles: offered.profiles,
            checked_at: time::now_isoformat(),
        })
    }
}

/// `error` with what met it, where that tells something: Stalwart's rate
/// limit as that of `whose` budget, since Stalwart counts each token and key
/// apart and says nothing of which it refused; Stalwart that could not be
/// reached or failed on its side, and an answer this release does not read,
/// by the `request` it met, which the journal names.
fn asked(error: Error, whose: &str, request: &str) -> Error {
    match error {
        Error::Limited(_) => Error::Limited(whose.to_owned()),
        Error::Unavailable(how) => Error::Unavailable(format!("{request}: {how}")),
        Error::Unreadable(reason) => Error::Unreadable(format!("{request}: {reason}")),
        error @ (Error::InvalidToken(_) | Error::Denied(_) | Error::Misconfigured(_)) => error,
    }
}

#[cfg(test)]
mod tests;
