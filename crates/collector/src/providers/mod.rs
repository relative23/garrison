//! The provider registry: the `type` of each `[[providers]]` table selects one.
//! The checks live in the `garrison-checks-*` crates; their types and the
//! modules other crates use stay reachable here.

use garrison_core::config::ConfigError;

use crate::context::Provider;
use crate::options::{Checked, fail};

pub use garrison_checks_host::providers::{
    BackupCheck, Bulwark, Host, HostCare, Http, Receipt, Systemd, VersionCommand,
};
pub use garrison_checks_mail::providers::{Clamav, Flow, MailTest, Senders, directives};
pub use garrison_checks_network::providers::{Dns, Reputation, Tls, tls};
pub use garrison_checks_stalwart::providers::{
    Prometheus, Releases, Stalwart, mailboxes, prometheus, stalwart,
};

type Factory = fn(&toml::Table) -> Result<Box<dyn Provider>, ConfigError>;

fn boxed<P: Provider + 'static>(provider: Checked<P>) -> Result<Box<dyn Provider>, ConfigError> {
    provider.map(|provider| Box::new(provider) as Box<dyn Provider>)
}

/// Every provider type, sorted by name.
const TYPES: [(&str, Factory); 18] = [
    ("backup-check", |raw| boxed(BackupCheck::new(raw))),
    ("bulwark", |raw| boxed(Bulwark::new(raw))),
    ("clamav", |raw| boxed(Clamav::new(raw))),
    ("dns", |raw| boxed(Dns::new(raw))),
    ("host", |raw| boxed(Host::new(raw))),
    ("host-care", |raw| boxed(HostCare::new(raw))),
    ("http", |raw| boxed(Http::new(raw))),
    ("mail-flow", |raw| boxed(Flow::new(raw))),
    ("mail-test", |raw| boxed(MailTest::new(raw))),
    ("prometheus", |raw| boxed(Prometheus::new(raw))),
    ("receipt", |raw| boxed(Receipt::new(raw))),
    ("releases", |raw| boxed(Releases::new(raw))),
    ("reputation", |raw| boxed(Reputation::new(raw))),
    ("senders", |raw| boxed(Senders::new(raw))),
    ("stalwart", |raw| boxed(Stalwart::new(raw))),
    ("systemd", |raw| boxed(Systemd::new(raw))),
    ("tls", |raw| boxed(Tls::new(raw))),
    ("version-command", |raw| boxed(VersionCommand::new(raw))),
];

/// Validate every provider table before anything is collected.
pub fn build(tables: &[toml::Table]) -> Checked<Vec<Box<dyn Provider>>> {
    let mut providers = Vec::new();
    for table in tables {
        let kind = table.get("type");
        let factory = kind
            .and_then(toml::Value::as_str)
            .and_then(|kind| TYPES.iter().find(|(name, _)| *name == kind));
        let Some((_, factory)) = factory else {
            let known: Vec<&str> = TYPES.iter().map(|(name, _)| *name).collect();
            let problem = match kind {
                None => "A provider has no type".to_owned(),
                Some(value) => format!("Unknown provider type {}", crate::values::from_toml(value)),
            };
            return fail(format!("{problem}; known: {}", known.join(", ")));
        };
        providers.push(factory(table)?);
    }
    Ok(providers)
}

#[cfg(test)]
mod tests;
