//! What the broker answers where the authority grants nothing: the answer
//! for each kind of its error, and what the journal says of it.

use std::sync::PoisonError;
use std::time::Instant;

use super::Broker;
use crate::protocol::{BrokerError, refuse};
use garrison_authz::{Error, Grant};

impl Broker {
    pub fn authorize(&self, token: &str) -> Result<Grant, BrokerError> {
        self.authority
            .authorize(token)
            .map_err(|error| match error {
                Error::InvalidToken(_) => refuse(401, "Sign-in required again"),
                Error::Unavailable(_) => refuse(503, "Authorization is temporarily unavailable"),
                Error::Limited(whose) => {
                    self.limited(&whose);
                    refuse(503, "Authorization is temporarily unavailable")
                }
                Error::Denied(reason) => {
                    log::info!("Garrison access denied: {reason}");
                    refuse(403, "Garrison access is not authorized")
                }
                // No refusal: a 403 would end the session of everyone who
                // is signed in, for a typo in the policy.
                Error::Misconfigured(reason) => {
                    log::error!("Access rights cannot be checked: {reason}");
                    refuse(
                        503,
                        "Garrison is not set up to check access rights; the broker's journal says why",
                    )
                }
            })
    }

    /// Say that Stalwart's rate limit refused a check of `whose` budget, at
    /// most once a minute.
    fn limited(&self, whose: &str) {
        let line = self
            .limited
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .refused(whose, Instant::now());
        if let Some(line) = line {
            log::warn!("{line}");
        }
    }
}
