//! Calls to the local Stalwart server and its role model.
//!
//! Every target URL comes from configuration, never from a request. Only the
//! broker (identity, rights) and the collector (status) use the management API;
//! the web service only signs users in.

pub mod http;
pub mod ids;
pub mod jmap;
pub mod oidc;
pub mod permissions;
pub mod sign_in_page;

/// Why a call to Stalwart did not produce a usable answer.
///
/// The variants keep three outcomes apart that callers treat differently: try
/// again later, sign in again, or no access.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Stalwart could not be reached or failed on its side. This grants nothing
    /// and may be retried.
    #[error("{0}")]
    Unavailable(String),
    /// Stalwart refused the request for its rate limit (HTTP 429), with whose
    /// budget it was where the caller can tell. This grants nothing and may
    /// be retried once Stalwart's window is over.
    #[error("{0}")]
    Limited(String),
    /// The access token is malformed, expired or revoked: the user must sign in again.
    #[error("{0}")]
    InvalidToken(String),
    /// Stalwart refused the request or answered with something unusable.
    #[error("{0}")]
    Denied(String),
    /// Garrison's own side cannot decide: its policy does not read, its key
    /// is missing or is not taken, or an answer about rights cannot be used.
    /// This grants nothing and refuses nobody: it needs the operator, and a
    /// signed-in user stays signed in meanwhile.
    #[error("{0}")]
    Misconfigured(String),
}

impl Error {
    pub(crate) fn denied(message: impl Into<String>) -> Self {
        Error::Denied(message.into())
    }
}
