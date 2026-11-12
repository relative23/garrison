//! The web service: API, sign-in and the compiled single-page interface.
//!
//! It listens on loopback behind nginx, at the root of Garrison's own host
//! name. It holds no native administrator key, no Docker socket and no shell;
//! maintenance requests go to the broker, which authorizes them itself.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use garrison_core::config::Config;
use garrison_core::hex;
use garrison_stalwart::oidc::{CodeExchange, Provider, Token};
use tokio::sync::Semaphore;

use crate::attempts::Attempts;
use crate::error::{ApiError, Cause};
use crate::routes;
use crate::security::Gate;
use crate::store::WebStore;

/// Where the interface lives, as the Stalwart WebUI lives under `/admin/` on
/// its host; the API, sign-in and client metadata stay at the root.
pub const INTERFACE: &str = "/admin";
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; \
                   frame-ancestors 'none'";

/// The hash (`sha256-…`) of the stylesheet a drawn page carries inline, set by
/// the page's handler: the policy of that answer allows this one stylesheet as
/// well, and still no inline style otherwise.
#[derive(Clone, Debug)]
pub(crate) struct InlineStyle(pub(crate) String);

fn policy(style: Option<&InlineStyle>) -> HeaderValue {
    style
        .and_then(|InlineStyle(hash)| {
            let allowed = format!("style-src 'self' '{hash}'");
            HeaderValue::from_str(&CSP.replacen("style-src 'self'", &allowed, 1)).ok()
        })
        .unwrap_or(HeaderValue::from_static(CSP))
}
/// At most two concurrent history and event queries per process; more get 429.
const QUERY_SLOTS: usize = 2;

/// The identity provider's token endpoints; tests use their own.
pub trait Identity: Send + Sync {
    fn exchange_code(&self, exchange: &CodeExchange<'_>)
    -> Result<Token, garrison_stalwart::Error>;
    fn revoke(&self, client_id: &str, token: &str) -> Result<(), garrison_stalwart::Error>;
}

impl Identity for Provider {
    fn exchange_code(
        &self,
        exchange: &CodeExchange<'_>,
    ) -> Result<Token, garrison_stalwart::Error> {
        Provider::exchange_code(self, exchange)
    }

    fn revoke(&self, client_id: &str, token: &str) -> Result<(), garrison_stalwart::Error> {
        Provider::revoke(self, client_id, token)
    }
}

/// Shared objects of one web-service process.
pub struct App {
    pub config: Config,
    pub store: Arc<WebStore>,
    pub gate: Gate,
    pub identity: Box<dyn Identity>,
    /// The built interface: index.html, assets/, favicon.svg, the switch script.
    pub static_directory: PathBuf,
    pub query_slots: Semaphore,
    /// Code exchanges per client network (see `attempts`).
    pub sign_ins: Attempts,
}

impl std::fmt::Debug for App {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("App")
            .field("static_directory", &self.static_directory)
            .finish_non_exhaustive()
    }
}

impl App {
    pub fn new(
        config: Config,
        store: Arc<WebStore>,
        gate: Gate,
        identity: Box<dyn Identity>,
        static_directory: PathBuf,
    ) -> Arc<Self> {
        Arc::new(App {
            config,
            store,
            gate,
            identity,
            static_directory,
            query_slots: Semaphore::new(QUERY_SLOTS),
            sign_ins: Attempts::default(),
        })
    }

    pub fn client_id(&self) -> String {
        client_id(&self.config.deployment.public_origin)
    }

    pub fn redirect_uri(&self) -> String {
        redirect_uri(&self.config.deployment.public_origin)
    }
}

/// Garrison's OAuth client ID is its Client ID Metadata Document URL;
/// `stalwart setup` registers the same ID with Stalwart.
pub fn client_id(public_origin: &str) -> String {
    format!("{public_origin}/oauth-client.json")
}

/// The only address Stalwart may send a sign-in back to.
pub fn redirect_uri(public_origin: &str) -> String {
    format!("{public_origin}/auth/callback")
}

async fn headers(request: Request, next: Next) -> Response {
    let assets = request
        .uri()
        .path()
        .strip_prefix(INTERFACE)
        .is_some_and(|rest| rest.starts_with("/assets/"));
    let mut response = next.run(request).await;
    let style = response.extensions_mut().remove::<InlineStyle>();
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert("content-security-policy", policy(style.as_ref()));
    let cache = if assets && response.status() == StatusCode::OK {
        // Asset names contain a content hash; they never change in place.
        "public, max-age=31536000, immutable"
    } else {
        "no-store"
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    response
}

/// Every answer carries a reference, and an internal error is logged with
/// it: the reference the interface shows finds the journal line.
async fn reference(request: Request, next: Next) -> Response {
    let mut bytes = [0; 6];
    let reference = if getrandom::fill(&mut bytes).is_ok() {
        hex::encode(&bytes)
    } else {
        "unavailable".to_owned()
    };
    let mut response = next.run(request).await;
    if let Some(Cause(cause)) = response.extensions_mut().remove::<Cause>() {
        log::error!("Request {reference} failed: {cause}");
    }
    if let Ok(value) = HeaderValue::from_str(&reference) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

/// The answer outside the routes.
fn detail(status: StatusCode, text: &'static str) -> Response {
    (status, axum::Json(serde_json::json!({"detail": text}))).into_response()
}

/// Every route of the web service on Garrison's own host name: the interface
/// under [`INTERFACE`], the API under /api, sign-in under /auth.
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .merge(routes::auth::routes())
        .merge(routes::api::routes())
        .merge(routes::events::routes())
        .merge(routes::attacks::routes())
        .merge(routes::destinations::routes())
        .merge(routes::actions::routes())
        .merge(routes::files::routes())
        // An unknown path is as unknown as an unknown record.
        .fallback(|| async { ApiError::not_found().into_response() })
        .method_not_allowed_fallback(|| async {
            detail(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
        })
        .layer(middleware::from_fn(crate::coding::compress))
        .layer(middleware::from_fn_with_state(Arc::clone(&app), own_host))
        .layer(middleware::from_fn(headers))
        .layer(middleware::from_fn(reference))
        .with_state(app)
}

/// Garrison answers only under its own host name. A request that came in
/// under another one goes to the same path on Garrison's origin, so its pages
/// never load in another origin. Local checks may use a loopback name.
async fn own_host(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let origin = app.config.deployment.public_origin.as_str();
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    if host.is_none_or(|host| is_own_host(host, origin)) {
        return next.run(request).await;
    }
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str());
    let mut response = StatusCode::PERMANENT_REDIRECT.into_response();
    if let Ok(location) = HeaderValue::from_str(&format!("{origin}{path}")) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

/// Whether a `Host` header names `origin` or a loopback address.
fn is_own_host(host: &str, origin: &str) -> bool {
    let own = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    if host
        .strip_suffix(":443")
        .unwrap_or(host)
        .eq_ignore_ascii_case(own)
    {
        return true;
    }
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or(rest, |(inside, _)| inside),
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    };
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use garrison_broker::client::CallError;
    use garrison_broker::protocol::Request;
    use garrison_testing::http::{answer, serve};
    use serde_json::Value;

    use super::*;
    use crate::security::Broker;

    struct Silent;

    impl Broker for Silent {
        fn call(&self, _: &Request) -> Result<Value, CallError> {
            Err(CallError::Unavailable("no broker in this test"))
        }
    }

    #[test]
    fn stalwart_hears_of_a_revoked_token_and_debug_output_names_no_secret() {
        let server = serve(vec![answer(200, "")]);
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), &server.url);
        let provider = Provider::new(&server.url, &config.deployment.issuer);
        Identity::revoke(&provider, "garrison", "token-0123456789abcdef").unwrap();
        let request = server.requests().remove(0);
        assert!(request.starts_with("POST /auth/revoke "), "{request}");
        let store = Arc::new(WebStore::open(&directory.path().join("web.sqlite")).unwrap());
        let gate = Gate::new(
            Arc::clone(&store),
            Arc::new(Silent),
            config.deployment.public_origin.clone(),
            BTreeSet::new(),
            false,
        );
        let app = App::new(
            config,
            store,
            gate,
            Box::new(provider),
            "/srv/static".into(),
        );
        assert_eq!(
            format!("{app:?}"),
            r#"App { static_directory: "/srv/static", .. }"#
        );
    }
}
