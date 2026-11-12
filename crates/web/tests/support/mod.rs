//! The web service on its production path, with a fake broker and identity
//! provider: the same gate, store and routes as in production.

// Each test file uses a different part of this module.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use garrison_broker::client::CallError;
use garrison_broker::protocol::{self, BrokerError};
use garrison_core::config::Config;
use garrison_core::modules::ModuleId;
use garrison_stalwart::Error;
use garrison_stalwart::oidc::{CodeExchange, Token};
use garrison_web::security::{Broker, Gate};
use garrison_web::store::WebStore;
use garrison_web::{App, Identity, router};
use serde_json::{Value, json};
use tower::ServiceExt;

pub(crate) const ORIGIN: &str = "https://admin.example.test";

pub(crate) fn grant(subject: &str, modules: &[&str], actions: &[&str]) -> Value {
    json!({
        "subject": subject,
        "email": format!("{subject}@example.test"),
        "modules": modules,
        "actions": actions,
        "profiles": ["p"],
        "checkedAt": "2026-10-29T00:00:00+00:00",
    })
}

pub(crate) fn refused(status: u16, message: &str) -> Result<Value, CallError> {
    Err(CallError::Refused(BrokerError {
        status,
        message: message.into(),
    }))
}

#[derive(Default)]
pub(crate) struct FakeBroker {
    pub(crate) grants: Mutex<HashMap<String, Result<Value, CallError>>>,
    pub(crate) calls: Mutex<Vec<Value>>,
}

impl FakeBroker {
    pub(crate) fn standard() -> Self {
        let all: Vec<&str> = ModuleId::all().map(ModuleId::as_str).collect();
        let broker = FakeBroker::default();
        broker.set("admin-token", Ok(grant("1", &all, &["run_monitor"])));
        broker.set("viewer-token", Ok(grant("2", &["dashboard", "logs"], &[])));
        broker
    }

    pub(crate) fn set(&self, token: &str, value: Result<Value, CallError>) {
        self.grants.lock().unwrap().insert(token.into(), value);
    }
}

impl Broker for FakeBroker {
    fn call(&self, request: &protocol::Request) -> Result<Value, CallError> {
        // The line as it goes to the broker's socket.
        let token = request.token();
        let request = serde_json::to_value(request).unwrap();
        self.calls.lock().unwrap().push(request.clone());
        let value = self
            .grants
            .lock()
            .unwrap()
            .get(token)
            .cloned()
            .unwrap_or_else(|| refused(401, "Sign-in required again"))?;
        Ok(match request["op"].as_str() {
            Some("authorize") => value,
            Some("catalog") => json!({"actions": [], "jobs": []}),
            Some("submit") => json!({
                "job": {
                    "id": "a".repeat(32),
                    "actionId": request["action"],
                    "actor": value["subject"],
                    "actorEmail": value["email"],
                    "requestId": request["requestId"],
                    "status": "queued",
                    "createdAt": null,
                    "startedAt": null,
                    "finishedAt": null,
                    "message": "Accepted.",
                },
                "replayed": false,
            }),
            Some("job") => json!({
                "id": request["id"],
                "actionId": "run_monitor",
                "actor": value["subject"],
                "actorEmail": value["email"],
                "requestId": "0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b",
                "status": "succeeded",
                "createdAt": "2026-10-29T00:00:00+00:00",
                "startedAt": null,
                "finishedAt": null,
                "message": "Done.",
            }),
            other => panic!("unexpected {other:?}"),
        })
    }
}

#[derive(Default)]
pub(crate) struct FakeProvider {
    pub(crate) revoked: Mutex<Vec<String>>,
    pub(crate) verifiers: Mutex<Vec<String>>,
}

/// The provider as the application holds it; the test keeps the other handle.
pub(crate) struct Shared(pub Arc<FakeProvider>);

impl Identity for Shared {
    fn exchange_code(&self, exchange: &CodeExchange<'_>) -> Result<Token, Error> {
        self.0
            .verifiers
            .lock()
            .unwrap()
            .push(exchange.verifier.to_owned());
        let token = match exchange.code {
            "code-admin" => "admin-token",
            "code-viewer" => "viewer-token",
            "code-expired" => return Err(Error::Denied("invalid_grant".into())),
            "code-outage" => return Err(Error::Unavailable("connection refused".into())),
            _ => "bad-token",
        };
        Ok(Token {
            access_token: token.into(),
            expires_in: 3600,
        })
    }

    fn revoke(&self, _: &str, token: &str) -> Result<(), Error> {
        self.0.revoked.lock().unwrap().push(token.into());
        Ok(())
    }
}

pub(crate) struct Setup {
    pub(crate) client: Client,
    /// The application behind the client, for its limits.
    pub(crate) app: Arc<App>,
    pub(crate) broker: Arc<FakeBroker>,
    pub(crate) provider: Arc<FakeProvider>,
    pub(crate) config: Config,
    pub(crate) directory: tempfile::TempDir,
}

pub(crate) fn application(
    config: &Config,
    broker: &Arc<FakeBroker>,
    provider: &Arc<FakeProvider>,
    cache: Duration,
) -> Router {
    application_parts(config, broker, provider, cache).0
}

fn application_parts(
    config: &Config,
    broker: &Arc<FakeBroker>,
    provider: &Arc<FakeProvider>,
    cache: Duration,
) -> (Router, Arc<App>) {
    let store = Arc::new(WebStore::open(&config.web.state_directory.join("web.sqlite")).unwrap());
    let ids: BTreeSet<String> = config
        .broker
        .actions
        .iter()
        .map(|action| action.id.clone())
        .collect();
    let broker: Arc<dyn Broker> = Arc::clone(broker) as Arc<dyn Broker>;
    let gate =
        Gate::new(Arc::clone(&store), broker, ORIGIN.into(), ids, false).with_cache_time(cache);
    let static_directory = config.web.state_directory.parent().unwrap().join("static");
    let app = App::new(
        config.clone(),
        store,
        gate,
        Box::new(Shared(Arc::clone(provider))),
        static_directory,
    );
    (router(Arc::clone(&app)), app)
}

pub(crate) fn setup_with_cache(cache: Duration) -> Setup {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let static_directory = directory.path().join("static");
    std::fs::create_dir_all(static_directory.join("assets")).unwrap();
    std::fs::write(
        static_directory.join("index.html"),
        "<!doctype html><title>garrison</title>",
    )
    .unwrap();
    std::fs::write(static_directory.join("assets/app-abc.js"), "console.log(1)").unwrap();
    std::fs::write(static_directory.join("stalwart-switch.js"), "(() => {})();").unwrap();
    let (broker, provider) = (
        Arc::new(FakeBroker::standard()),
        Arc::new(FakeProvider::default()),
    );
    let (router, app) = application_parts(&config, &broker, &provider, cache);
    Setup {
        client: Client::new(router),
        app,
        broker,
        provider,
        config,
        directory,
    }
}

pub(crate) fn setup() -> Setup {
    setup_with_cache(Duration::from_secs(5))
}

pub(crate) struct Answer {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

impl Answer {
    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    pub(crate) fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }
}

/// Sends requests to the router and keeps the cookies it sets, like a browser.
pub(crate) struct Client {
    app: Router,
    pub(crate) cookies: HashMap<String, String>,
}

impl Client {
    pub(crate) fn new(app: Router) -> Self {
        Client {
            app,
            cookies: HashMap::new(),
        }
    }

    pub(crate) async fn send(
        &mut self,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> Answer {
        let mut builder = Request::builder().method(method).uri(uri);
        let cookie: Vec<String> = self
            .cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        if !cookie.is_empty() {
            builder = builder.header("cookie", cookie.join("; "));
        }
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        for value in parts.headers.get_all("set-cookie") {
            let text = value.to_str().unwrap();
            let (pair, attributes) = text.split_once(';').unwrap_or((text, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attributes.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.into(), value.into());
            }
        }
        Answer {
            status: parts.status,
            headers: parts.headers,
            body: to_bytes(body, 1 << 24).await.unwrap().to_vec(),
        }
    }

    pub(crate) async fn get(&mut self, uri: &str) -> Answer {
        self.send(Method::GET, uri, &[], None).await
    }

    /// Sign in through the provider; the CSRF token of the new session.
    pub(crate) async fn sign_in(&mut self, code: &str) -> String {
        let login = self.get("/auth/login").await;
        assert_eq!(login.status, StatusCode::SEE_OTHER);
        let location = url::Url::parse(login.header("location")).unwrap();
        let query: HashMap<String, String> = location.query_pairs().into_owned().collect();
        assert_eq!(
            (
                query["scope"].as_str(),
                query["code_challenge_method"].as_str()
            ),
            ("openid", "S256")
        );
        let callback = format!(
            "/auth/callback?state={}&code={code}&iss=https%3A%2F%2Fmail.example.test",
            query["state"]
        );
        let answer = self.get(&callback).await;
        assert_eq!(answer.header("location"), "/admin/");
        self.get("/api/session").await.json()["session"]["csrf"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

/// Store a snapshot with these observations, as one collection run does.
pub(crate) fn write_status(path: &Path, observations: &Value, provider_errors: &Value) {
    let snapshot = serde_json::from_value(json!({
        "schemaVersion": 1,
        "collectedAt": "2000-01-01T00:00:00+00:00",
        "observations": observations,
        "providerErrors": provider_errors,
    }))
    .unwrap();
    let mut store = garrison_collector::store::StatusStore::open(path, 90).unwrap();
    store
        .write(1000, &snapshot, &BTreeMap::default(), &BTreeMap::default())
        .unwrap();
}
