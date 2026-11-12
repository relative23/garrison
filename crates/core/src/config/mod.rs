//! The single operator configuration file (TOML) shared by all components.
//!
//! Unknown keys are rejected so a typo cannot silently fall back to a default.
//! Secrets are never stored here; settings name files or systemd credentials.

mod notify;
mod parse;
mod values;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::credentials::SecretSource;
use crate::modules::ModuleId;

pub use parse::parse;
pub use values::{is_action_id, is_confirmation, is_unit_name, is_user_name};

pub const DEFAULT_PATH: &str = "/etc/garrison/garrison.toml";

/// The configuration file is invalid; the message names the setting.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deployment {
    /// The origin browsers use for Garrison, as they send it in `Origin`.
    pub public_origin: String,
    pub issuer: String,
    /// Stalwart's own HTTP listener on loopback.
    pub stalwart_url: String,
    pub admin_url: String,
    /// Named links to other interfaces, in the order the operator wrote them.
    pub links: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebConfig {
    pub port: u16,
    pub state_directory: PathBuf,
    pub session_minutes: u32,
    pub bind_client_ip: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestConfig {
    pub port: u16,
    pub state_directory: PathBuf,
    pub signature_key: SecretSource,
    pub retention_days: u32,
    pub max_events: u32,
    pub max_database_mib: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CollectorConfig {
    pub state_directory: PathBuf,
    pub native_key: SecretSource,
    pub metrics_credential: Option<SecretSource>,
    pub history_days: u32,
    /// Provider tables as written; each provider validates its own options.
    pub providers: Vec<toml::Table>,
}

/// Where the collector tells an operator that a check changed its state: any
/// of an ntfy topic, a webhook and a mailbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notifications {
    /// The address of an ntfy topic, `https://host/topic`.
    pub ntfy_url: Option<String>,
    /// The access token for that topic; an empty file means the topic needs none.
    pub token: SecretSource,
    /// An address every message is posted to as JSON.
    pub webhook_url: Option<String>,
    /// A token that goes with it as `Authorization: Bearer`; an empty file means none.
    pub webhook_token: SecretSource,
    pub mail: Option<MailSettings>,
    /// The password of the account that submits the mail.
    pub mail_password: SecretSource,
}

impl Notifications {
    /// Whether any channel is named.
    #[must_use]
    pub fn any(&self) -> bool {
        self.ntfy_url.is_some() || self.webhook_url.is_some() || self.mail.is_some()
    }
}

/// What the macro milter does with a message that carries macros.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacroAction {
    /// Refuse it while the sender's server is still connected.
    Reject,
    /// Take it, with a header that says what was found.
    Tag,
}

/// The macro milter, which Stalwart asks about each incoming message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MilterConfig {
    /// The loopback port it listens on.
    pub port: u16,
    pub action: MacroAction,
    /// A message larger than this is taken unscanned.
    pub max_message_bytes: u64,
    /// Whether Stalwart defers mail while the milter cannot be reached; if
    /// not, it takes mail unscanned then.
    pub defer_when_unreachable: bool,
}

/// Mail for notifications, submitted signed in over TLS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailSettings {
    /// The mail server's name, as its certificate names it.
    pub host: String,
    pub port: u16,
    /// The account that signs in; by default the sender's address.
    pub user: String,
    pub from: String,
    pub to: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Start,
    Restart,
}

impl Operation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Operation::Start => "start",
            Operation::Restart => "restart",
        }
    }
}

/// A reviewed maintenance operation: one verb on one systemd unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    pub id: String,
    pub title: String,
    pub description: String,
    pub confirmation: String,
    pub unit: String,
    pub operation: Operation,
    pub cooldown_seconds: u32,
    pub timeout_seconds: u32,
    /// Included in the default "operator" profile (low-risk, read-mostly jobs).
    pub operator: bool,
}

/// What the interface may learn about an action: no unit, no operation. The
/// broker sends it and the web service reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicAction {
    pub id: String,
    pub title: String,
    pub description: String,
    pub confirmation: String,
    pub cooldown_seconds: u32,
}

impl Action {
    pub fn public(&self) -> PublicAction {
        PublicAction {
            id: self.id.clone(),
            title: self.title.clone(),
            description: self.description.clone(),
            confirmation: self.confirmation.clone(),
            cooldown_seconds: self.cooldown_seconds,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerConfig {
    pub socket: PathBuf,
    pub state_directory: PathBuf,
    pub native_key: SecretSource,
    pub policy: PathBuf,
    pub allowed_peers: Vec<String>,
    /// Actions in the order the operator wrote them; IDs are unique.
    pub actions: Vec<Action>,
}

impl BrokerConfig {
    pub fn action(&self, id: &str) -> Option<&Action> {
        self.actions.iter().find(|action| action.id == id)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub deployment: Deployment,
    pub web: WebConfig,
    pub ingest: IngestConfig,
    pub collector: CollectorConfig,
    pub broker: BrokerConfig,
    pub notifications: Notifications,
    /// The macro milter; `None` where the section is absent and it does not run.
    pub milter: Option<MilterConfig>,
    /// The modules this installation offers, an upper bound for every grant.
    pub modules: BTreeSet<ModuleId>,
    /// Where systemd loads credentials from (`LoadCredential=` source files).
    pub credentials_directory: PathBuf,
}

/// The SQLite database of each service: one writer, one file, one mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Database {
    /// Sessions and preferences.
    Web,
    /// The recorded event history.
    Events,
    /// Status snapshots and metric history.
    Status,
    /// The maintenance job audit.
    Jobs,
}

impl Database {
    pub const ALL: [Database; 4] = [
        Database::Web,
        Database::Events,
        Database::Status,
        Database::Jobs,
    ];

    /// The service that writes the database; it also names its backup directory.
    pub const fn writer(self) -> &'static str {
        match self {
            Database::Web => "web",
            Database::Events => "ingest",
            Database::Status => "collector",
            Database::Jobs => "broker",
        }
    }

    pub const fn file_name(self) -> &'static str {
        match self {
            Database::Web => "web.sqlite",
            Database::Events => "events.sqlite",
            Database::Status => "status.sqlite",
            Database::Jobs => "jobs.sqlite",
        }
    }

    /// The web service reads the event history and the status snapshots.
    pub const fn has_readers(self) -> bool {
        matches!(self, Database::Events | Database::Status)
    }

    /// Readers get access through the writer's group; nobody else may read.
    pub const fn mode(self) -> u32 {
        if self.has_readers() { 0o640 } else { 0o600 }
    }
}

impl Config {
    pub fn database(&self, database: Database) -> PathBuf {
        let directory = match database {
            Database::Web => &self.web.state_directory,
            Database::Events => &self.ingest.state_directory,
            Database::Status => &self.collector.state_directory,
            Database::Jobs => &self.broker.state_directory,
        };
        directory.join(database.file_name())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("{0}")]
    Read(#[from] std::io::Error),
    #[error("{0}")]
    Syntax(#[from] toml::de::Error),
    #[error("{0}")]
    Invalid(#[from] ConfigError),
}

pub fn load(path: &Path) -> Result<Config, LoadError> {
    from_text(&std::fs::read_to_string(path)?)
}

/// A configuration from the text of its file.
pub fn from_text(text: &str) -> Result<Config, LoadError> {
    Ok(parse(&text.parse::<toml::Table>()?)?)
}

#[cfg(test)]
mod notification_tests;
#[cfg(test)]
mod tests;
