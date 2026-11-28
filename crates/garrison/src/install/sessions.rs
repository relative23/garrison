//! The sessions that end with the web service's database.
//!
//! A restore and a rollback with the state replace web.sqlite by a copy
//! that holds no session, since a backup never holds one, and a purge
//! removes it. Every session ends there. The web service has Stalwart
//! revoke a session's token when the session ends, and these endings it
//! never sees. So the installer asks for the revocations itself before the
//! database goes, and says how that went: a token whose revocation Stalwart
//! did not take serves until it expires there.

use std::path::Path;

use garrison_core::config::{Config, Database};
use garrison_core::sqlite;
use garrison_stalwart::oidc::{Provider, client_id};
use rusqlite::OpenFlags;

use super::states;
use crate::state::State;

/// The tokens of the sessions in the web database at `path`.
fn tokens(path: &Path) -> Result<Vec<String>, String> {
    // Root reads a file that a service user writes and may have replaced.
    let db = sqlite::open_untrusted(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| error.to_string())?;
    garrison_web::store::tokens(&db).map_err(|error| error.to_string())
}

/// Have Stalwart revoke the token of every session in the web service's
/// database, which is about to go, and say how it went; nothing where the
/// database is not there or holds no session. The services are stopped, so
/// no session begins meanwhile.
pub(super) fn end(config: &Config) -> Option<State> {
    let path = config.database(Database::Web);
    if !path.exists() {
        return None;
    }
    let tokens = match tokens(&path) {
        Ok(tokens) => tokens,
        Err(why) => return Some(states::sessions_unread(&path, &why)),
    };
    let provider = Provider::new(&config.deployment.stalwart_url, &config.deployment.issuer);
    let client = client_id(&config.deployment.public_origin);
    for (done, token) in tokens.iter().enumerate() {
        // Stalwart is asked no further after one it did not take: each
        // would wait out its time like this one.
        if let Err(why) = provider.revoke(&client, token) {
            let left = tokens.len() - done;
            return Some(states::sessions_unrevoked(left, tokens.len(), &why));
        }
    }
    (!tokens.is_empty()).then(|| states::sessions_revoked(tokens.len()))
}

#[cfg(test)]
mod tests;
