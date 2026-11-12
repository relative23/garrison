//! Request authentication and authorization for the web service.
//!
//! Every API request needs a valid session cookie. The session's rights come
//! from the broker, which re-derives them from the user's token and the current
//! native roles. They are cached for at most five seconds per session so that
//! one page load does not trigger a dozen identical checks; actions are always
//! re-checked by the broker itself, uncached.
//!
//! Write requests additionally need the exact public Origin and the session's
//! CSRF token. Menu visibility never grants anything: every route names its
//! module.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use garrison_authz::Grant;
use garrison_authz::grant::parse_grant;
use garrison_broker::client::{BrokerClient, CallError};
use garrison_broker::protocol::Request;
use garrison_core::constant_time;
use garrison_core::modules::ModuleId;
use serde_json::Value;

use crate::error::{ApiError, ApiResult};
use crate::store::{Session, WebStore};

/// `__Host-` cookies belong to Garrison's own host name alone: no other
/// host of the domain, Stalwart's included, can set or replace them.
pub const SESSION_COOKIE: &str = "__Host-garrison_session";
pub const STATE_COOKIE: &str = "__Host-garrison_login";
const MAX_CACHED: usize = 1024;

/// What the broker answers; tests use their own.
pub trait Broker: Send + Sync {
    fn call(&self, request: &Request) -> Result<Value, CallError>;
}

impl Broker for BrokerClient {
    fn call(&self, request: &Request) -> Result<Value, CallError> {
        BrokerClient::call(self, request)
    }
}

/// The parts of a request the gate looks at.
#[derive(Clone, Debug, Default)]
pub struct Visitor {
    pub cookies: HashMap<String, String>,
    pub peer: Option<IpAddr>,
    pub headers: HeaderMap,
}

impl Visitor {
    pub fn cookie(&self, name: &str) -> &str {
        self.cookies.get(name).map_or("", String::as_str)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// nginx passes the client address; only a loopback peer may assert it.
    pub fn client_ip(&self) -> Option<String> {
        let value = self
            .header("x-garrison-client-ip")
            .filter(|value| !value.is_empty())?;
        if !self.peer?.is_loopback() {
            return None;
        }
        value
            .parse::<IpAddr>()
            .ok()
            .map(|address| address.to_string())
    }
}

fn cookies(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            Some((
                name.trim().to_owned(),
                value.trim().trim_matches('"').to_owned(),
            ))
        })
        .collect()
}

impl<S: Send + Sync> FromRequestParts<S> for Visitor {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let visitor = Visitor {
            cookies: cookies(&parts.headers),
            peer: parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(address)| address.ip()),
            headers: parts.headers.clone(),
        };
        std::future::ready(Ok(visitor))
    }
}

/// A signed-in user and the rights the broker confirmed.
#[derive(Clone, Debug)]
pub struct Caller {
    pub session: Session,
    pub grant: Grant,
}

pub struct Gate {
    store: Arc<WebStore>,
    broker: Arc<dyn Broker>,
    origin: String,
    action_ids: BTreeSet<String>,
    bind_client_ip: bool,
    cache_time: Duration,
    cache: Mutex<HashMap<String, (Instant, Grant)>>,
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Gate")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl Gate {
    pub fn new(
        store: Arc<WebStore>,
        broker: Arc<dyn Broker>,
        origin: String,
        action_ids: BTreeSet<String>,
        bind_client_ip: bool,
    ) -> Self {
        Gate {
            store,
            broker,
            origin,
            action_ids,
            bind_client_ip,
            cache_time: Duration::from_secs(5),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// For tests: how long a confirmed grant is reused.
    #[must_use]
    pub fn with_cache_time(mut self, time: Duration) -> Self {
        self.cache_time = time;
        self
    }

    pub fn broker(&self) -> &dyn Broker {
        self.broker.as_ref()
    }

    /// Ask the broker; translate its answer into HTTP semantics.
    pub fn grant_for(&self, token: &str) -> ApiResult<Grant> {
        let ids: BTreeSet<&str> = self.action_ids.iter().map(String::as_str).collect();
        let request = Request::Authorize {
            token: token.to_owned(),
        };
        match self.broker.call(&request) {
            Err(CallError::Unavailable(_)) => Err(ApiError::new(
                503,
                "Authorization is temporarily unavailable",
            )),
            Err(CallError::Refused(error)) => Err(ApiError::new(error.status, error.message)),
            Ok(answer) => parse_grant(answer, &ids)
                .map_err(|_| ApiError::new(502, "The broker returned an invalid authorization")),
        }
    }

    fn cached(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Instant, Grant)>> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// End a session here; the token is returned for revocation.
    pub fn forget(&self, session: &Session) -> Option<String> {
        self.cached().remove(&session.id_hash);
        self.store.delete(&session.id_hash).ok().flatten()
    }

    pub fn session(&self, visitor: &Visitor) -> ApiResult<Option<Session>> {
        self.store
            .get(visitor.cookie(SESSION_COOKIE))
            .map_err(ApiError::from)
    }

    pub fn caller(&self, visitor: &Visitor) -> ApiResult<Caller> {
        let unknown = || ApiError::new(401, "Sign-in required");
        let session = self.session(visitor)?.ok_or_else(unknown)?;
        if self.bind_client_ip && session.client_ip != visitor.client_ip() {
            return Err(unknown());
        }
        let now = Instant::now();
        let cached = self.cached().get(&session.id_hash).cloned();
        if let Some((at, grant)) = cached
            && now.duration_since(at) < self.cache_time
        {
            return Ok(Caller { session, grant });
        }
        let grant = match self.grant_for(&session.token) {
            Ok(grant) => grant,
            Err(error) => {
                // Revoked or expired rights end the session; 503 keeps it.
                if matches!(error.status.as_u16(), 401 | 403) {
                    self.forget(&session);
                }
                return Err(error);
            }
        };
        if grant.subject != session.subject {
            self.forget(&session);
            return Err(unknown());
        }
        let mut cache = self.cached();
        if cache.len() > MAX_CACHED {
            cache.clear();
        }
        cache.insert(session.id_hash.clone(), (now, grant.clone()));
        Ok(Caller { session, grant })
    }

    /// A session with at least one of the named modules.
    pub fn require(&self, visitor: &Visitor, modules: &[ModuleId]) -> ApiResult<Caller> {
        let caller = self.caller(visitor)?;
        if !modules
            .iter()
            .any(|module| caller.grant.allows_module(*module))
        {
            return Err(ApiError::new(403, "This Garrison module is not authorized"));
        }
        Ok(caller)
    }

    /// For state-changing requests: Origin and CSRF are mandatory.
    pub fn writer(&self, visitor: &Visitor) -> ApiResult<Caller> {
        let caller = self.caller(visitor)?;
        self.check_write(visitor, &caller.session)?;
        Ok(caller)
    }

    pub fn check_write(&self, visitor: &Visitor, session: &Session) -> ApiResult<()> {
        let provided = visitor.header("x-csrf-token").unwrap_or_default();
        let origin = visitor.header("origin") == Some(self.origin.as_str());
        if !origin || !constant_time::eq(provided, &session.csrf) {
            return Err(ApiError::new(403, "Origin or CSRF validation failed"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
