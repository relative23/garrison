//! Sessions and interface preferences of the web service.
//!
//! Session identifiers are stored only as SHA-256 digests, so a copy of the
//! database cannot be replayed as a cookie. The stored access token carries only
//! the `openid` scope, and a session's row goes only once Stalwart answered
//! the revocation of its token (`App::end_ended_sessions`).

use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use garrison_core::config::Database;
use garrison_core::hex;
use garrison_core::modules::ModuleId;
use garrison_core::sqlite::{self, Migration, SqliteError};
use garrison_core::time;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::models::Preferences;

const MAX_IDENTIFIER: usize = 128;

/// The schema version this release writes; `self-check` accepts up to it.
pub const SCHEMA_VERSION: usize = MIGRATIONS.len();

// Sign-in state lives in the login cookie (see `routes::auth`), so nothing of
// it is stored here. Times are whole seconds, as in every other database.
const MIGRATIONS: [Migration; 1] = [&[
    "CREATE TABLE sessions(
        id_hash TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        email TEXT NOT NULL,
        token TEXT NOT NULL,
        csrf TEXT NOT NULL,
        client_ip TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    )",
    "CREATE INDEX sessions_expiry ON sessions(expires_at)",
    "CREATE TABLE preferences(
        subject_hash TEXT PRIMARY KEY,
        document TEXT NOT NULL
    )",
]];

/// The stored form of a session or subject: its SHA-256 in hex.
pub fn digest(value: &str) -> String {
    hex::encode(&Sha256::digest(value.as_bytes()))
}

/// `bytes` random bytes as base64url without padding, for cookies and tokens.
pub fn random_token(bytes: usize) -> Result<String, StoreError> {
    let mut data = vec![0; bytes];
    getrandom::fill(&mut data).map_err(|_| StoreError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(data))
}

/// Seconds since the epoch, as session times are stored.
fn now() -> i64 {
    time::now().as_second()
}

/// The end of a session that has ended: before every time a clock gives,
/// so that no step of the clock makes it a session again while its row
/// waits for its token's revocation.
const ENDED: i64 = i64::MIN;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("no random numbers available")]
    Random,
    #[error("{0}")]
    Sqlite(#[from] SqliteError),
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        StoreError::Sqlite(error.into())
    }
}

#[derive(Clone, PartialEq)]
pub struct Session {
    pub id_hash: String,
    pub subject: String,
    pub email: String,
    pub token: String,
    pub csrf: String,
    pub client_ip: Option<String>,
    /// The second the session ends, since the epoch.
    pub expires_at: i64,
}

impl std::fmt::Debug for NewSession<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewSession")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Token and CSRF value stay out of logs.
        formatter
            .debug_struct("Session")
            .field("subject", &self.subject)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// What a new session records.
pub struct NewSession<'a> {
    pub subject: &'a str,
    pub email: &'a str,
    pub token: &'a str,
    pub client_ip: Option<&'a str>,
    /// In seconds.
    pub lifetime: i64,
}

/// Stored preferences, as the interface shows them.
pub fn validated(value: Preferences) -> Option<Preferences> {
    let mut hidden = value.hidden_modules;
    let count = hidden.len();
    if hidden.iter().any(|name| name.parse::<ModuleId>().is_err())
        || count > ModuleId::all().count()
    {
        return None;
    }
    hidden.sort();
    hidden.dedup();
    (hidden.len() == count).then_some(Preferences {
        theme: value.theme,
        hidden_modules: hidden,
        show_switch: value.show_switch,
    })
}

#[derive(Debug)]
pub struct WebStore {
    db: Mutex<Connection>,
}

impl WebStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = sqlite::open_database(path, &MIGRATIONS, Database::Web)?;
        Ok(WebStore { db: Mutex::new(db) })
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        // Every write is one statement, so a panic leaves the store consistent.
        self.db.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn create(&self, new: &NewSession<'_>) -> Result<(String, Session), StoreError> {
        let identifier = random_token(32)?;
        let at = now();
        let session = Session {
            id_hash: digest(&identifier),
            subject: new.subject.to_owned(),
            email: new.email.to_owned(),
            token: new.token.to_owned(),
            csrf: random_token(32)?,
            client_ip: new.client_ip.map(str::to_owned),
            expires_at: at + new.lifetime,
        };
        self.db().execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?)",
            params![
                session.id_hash,
                session.subject,
                session.email,
                session.token,
                session.csrf,
                session.client_ip,
                at,
                session.expires_at,
            ],
        )?;
        Ok((identifier, session))
    }

    /// The session of a cookie. One whose time is over, or that is dated
    /// ahead of the clock, has ended, and is kept so from now on.
    pub fn get(&self, identifier: &str) -> Result<Option<Session>, StoreError> {
        if identifier.is_empty() || identifier.chars().count() > MAX_IDENTIFIER {
            return Ok(None);
        }
        let db = self.db();
        let id_hash = digest(identifier);
        // A time stored as another kind of value than whole seconds is no
        // time, and its row no session.
        let found = db
            .query_row(
                "SELECT typeof(created_at) = 'integer' AND typeof(expires_at) = 'integer' \
                 AND expires_at > ?2 AND created_at <= ?2, expires_at IS ?3, \
                 id_hash,subject,email,token,csrf,client_ip,expires_at \
                 FROM sessions WHERE id_hash=?1",
                params![id_hash, now(), ENDED],
                |row| {
                    let session = if row.get::<_, bool>(0)? {
                        Some(Session {
                            id_hash: row.get(2)?,
                            subject: row.get(3)?,
                            email: row.get(4)?,
                            token: row.get(5)?,
                            csrf: row.get(6)?,
                            client_ip: row.get(7)?,
                            expires_at: row.get(8)?,
                        })
                    } else {
                        None
                    };
                    Ok((session, row.get::<_, bool>(1)?))
                },
            )
            .optional()?;
        match found {
            Some((Some(session), _)) => Ok(Some(session)),
            Some((None, false)) => {
                db.execute(
                    "UPDATE sessions SET expires_at=? WHERE id_hash=?",
                    params![ENDED, id_hash],
                )?;
                Ok(None)
            }
            Some((None, true)) | None => Ok(None),
        }
    }

    /// End a session; its token, to revoke it.
    pub fn delete(&self, id_hash: &str) -> Result<Option<String>, StoreError> {
        let db = self.db();
        Ok(db
            .query_row(
                "DELETE FROM sessions WHERE id_hash=? RETURNING token",
                [id_hash],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// End a session now but keep its row, whose token is still to be
    /// revoked: no cookie finds it any more, whatever the clock says.
    pub fn end(&self, id_hash: &str) -> Result<(), StoreError> {
        self.db().execute(
            "UPDATE sessions SET expires_at=? WHERE id_hash=?",
            params![ENDED, id_hash],
        )?;
        Ok(())
    }

    /// The digest and token of at most `limit` sessions that have ended,
    /// those signed in first first. Every session whose time is over is
    /// ended here for good, and so is one dated ahead of the clock, as one
    /// signed in while it ran ahead, which began at a time not known, and
    /// one stored at no time.
    pub fn ended(&self, limit: u16) -> Result<Vec<(String, String)>, StoreError> {
        let db = self.db();
        db.execute(
            "UPDATE sessions SET expires_at=?1 WHERE expires_at IS NOT ?1 \
             AND NOT (typeof(created_at) = 'integer' AND typeof(expires_at) = 'integer' \
             AND expires_at > ?2 AND created_at <= ?2)",
            params![ENDED, now()],
        )?;
        let mut statement = db.prepare(
            "SELECT id_hash,token FROM sessions WHERE expires_at = ? \
             ORDER BY created_at, id_hash LIMIT ?",
        )?;
        let rows =
            statement.query_map(params![ENDED, limit], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn preferences(&self, subject: &str) -> Result<Preferences, StoreError> {
        let text: Option<String> = self
            .db()
            .query_row(
                "SELECT document FROM preferences WHERE subject_hash=?",
                [digest(subject)],
                |row| row.get(0),
            )
            .optional()?;
        let stored = text.and_then(|text| serde_json::from_str::<Preferences>(&text).ok());
        Ok(stored
            .map(|mut stored| {
                // A module removed in a later release must not reset the other settings.
                stored
                    .hidden_modules
                    .retain(|name| name.parse::<ModuleId>().is_ok());
                stored
            })
            .and_then(validated)
            .unwrap_or_default())
    }

    /// Save validated preferences; `None` if they are not valid.
    pub fn save_preferences(
        &self,
        subject: &str,
        value: Preferences,
    ) -> Result<Option<Preferences>, StoreError> {
        let Some(clean) = validated(value) else {
            return Ok(None);
        };
        let document = serde_json::to_string(&clean).unwrap_or_default();
        self.db().execute(
            "INSERT INTO preferences VALUES(?,?) \
             ON CONFLICT(subject_hash) DO UPDATE SET document=excluded.document",
            params![digest(subject), document],
        )?;
        Ok(Some(clean))
    }
}

#[cfg(test)]
mod tests;
