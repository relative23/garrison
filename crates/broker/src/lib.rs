//! The maintenance broker: an unprivileged service on a peer-checked Unix
//! socket that authorizes every request from the user's token and runs only
//! the configured systemd operations, which polkit allows it and nothing else.

pub mod client;
pub mod polkit;
pub mod protocol;
pub mod runner;
pub mod server;
pub mod service;
pub mod store;

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use garrison_authz::Authority;
use garrison_core::config::{Config, Database};
use garrison_core::credentials::Credentials;
use garrison_core::sqlite::SqliteError;

use crate::runner::SystemdRunner;
use crate::service::Broker;
use crate::store::JobStore;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Policy(garrison_authz::Error),
    #[error("job audit: {0}")]
    Store(#[from] SqliteError),
    #[error("broker.allowed_peers: no system user {0}")]
    UnknownUser(String),
    #[error("{0}")]
    Io(#[from] io::Error),
}

/// The UID of a system user from `/etc/passwd`, where systemd-sysusers puts
/// the service users.
pub fn user_id(passwd: &str, name: &str) -> Option<u32> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        fields.nth(1)?.parse().ok()
    })
}

fn peer_ids(names: &[String]) -> Result<BTreeSet<u32>, Error> {
    let passwd = std::fs::read_to_string(Path::new("/etc/passwd"))?;
    names
        .iter()
        .map(|name| user_id(&passwd, name).ok_or_else(|| Error::UnknownUser(name.clone())))
        .collect()
}

/// Serve on the systemd socket (or the configured path) until stopped.
pub fn run(config: &Config, credentials: Credentials) -> Result<(), Error> {
    let broker = &config.broker;
    // Take over systemd's socket first, before any thread exists.
    let listener = server::listener(&broker.socket)?;
    let authority = Authority::new(config, credentials);
    // Fail at start, not at the first request, if the policy is unusable.
    authority.policy().map_err(Error::Policy)?;
    let allowed = peer_ids(&broker.allowed_peers)?;
    let store = JobStore::open(&config.database(Database::Jobs))?;
    let service = Broker::new(
        Box::new(authority),
        broker.actions.clone(),
        store,
        Box::new(SystemdRunner::default()),
        service::threads(),
    );
    log::info!(
        "Maintenance broker listening on {}",
        broker.socket.display()
    );
    garrison_core::systemd::ready();
    server::serve_on(&listener, &service, &allowed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_are_found_by_name() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      garrison:x:991:991::/var/lib/garrison:/usr/sbin/nologin\n";
        assert_eq!(user_id(passwd, "garrison"), Some(991));
        assert_eq!(user_id(passwd, "root"), Some(0));
        // Neither a prefix nor a longer name is the same user.
        assert_eq!(user_id(passwd, "garr"), None);
        assert_eq!(user_id(passwd, "garrison-ingest"), None);
        assert_eq!(user_id("broken", "broken"), None);
    }

    #[test]
    fn allowed_peers_must_exist_on_this_host() {
        assert_eq!(peer_ids(&["root".into()]).unwrap(), BTreeSet::from([0]));
        let missing = peer_ids(&["root".into(), "no-such-user".into()]).unwrap_err();
        assert_eq!(
            missing.to_string(),
            "broker.allowed_peers: no system user no-such-user"
        );
    }
}
