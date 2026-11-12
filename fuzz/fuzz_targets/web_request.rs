//! Any request to the web service, signed in or not, on the production
//! routes with a fake broker and identity provider and with real databases
//! behind the history. The service must answer every one of them, and never
//! with an internal error: a path, a query, a header or a body that makes it
//! fail inside is a defect, whoever sent it.
//!
//! The input is text: a first line `<flags><method letter> <path and query>`,
//! then header lines, an empty line and the body. Flag `s` signs the request
//! in, flag `w` adds what a write needs (origin and CSRF token).
#![no_main]

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use garrison_broker::client::CallError;
use garrison_broker::protocol;
use garrison_collector::snapshot::{SCHEMA, Snapshot};
use garrison_collector::store::StatusStore;
use garrison_core::config::Database;
use garrison_ingest::store::{EventStore, Limits};
use garrison_stalwart::Error;
use garrison_stalwart::oidc::{CodeExchange, Token};
use garrison_web::security::{Broker, Gate, SESSION_COOKIE};
use garrison_web::store::{NewSession, WebStore};
use garrison_web::{App, Identity, router};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use tower::ServiceExt;

const ORIGIN: &str = "https://admin.example.test";
/// Seconds since the epoch of the recorded history.
const NOW: i64 = 1_794_000_000;

/// A broker that grants the one token every module and action.
struct Granting;

impl Broker for Granting {
    fn call(&self, request: &protocol::Request) -> Result<Value, CallError> {
        let modules: Vec<&str> = garrison_core::modules::ModuleId::all()
            .map(garrison_core::modules::ModuleId::as_str)
            .collect();
        let job = |action: &str, request_id: &str, id: &str| {
            json!({
                "id": id, "actionId": action, "actor": "1", "actorEmail": "1@example.test",
                "requestId": request_id, "status": "queued", "createdAt": null,
                "startedAt": null, "finishedAt": null, "message": "Accepted.",
            })
        };
        Ok(match request {
            protocol::Request::Authorize { .. } => json!({
                "subject": "1", "email": "1@example.test", "modules": modules,
                "actions": ["run_monitor"], "profiles": ["p"],
                "checkedAt": "2026-10-29T00:00:00+00:00",
            }),
            protocol::Request::Catalog { .. } => json!({"actions": [], "jobs": []}),
            protocol::Request::Job { id, .. } => {
                job("run_monitor", "0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b", id)
            }
            protocol::Request::Submit {
                action, request_id, ..
            } => json!({"job": job(action, request_id, &"a".repeat(32)), "replayed": false}),
        })
    }
}

/// An identity provider that knows no code.
struct NoProvider;

impl Identity for NoProvider {
    fn exchange_code(&self, _: &CodeExchange<'_>) -> Result<Token, Error> {
        Err(Error::Denied("invalid_grant".into()))
    }

    fn revoke(&self, _: &str, _: &str) -> Result<(), Error> {
        Ok(())
    }
}

struct Setup {
    router: Router,
    runtime: tokio::runtime::Runtime,
    cookie: String,
    csrf: String,
    _directory: tempfile::TempDir,
}

fn setup() -> &'static Setup {
    static SETUP: OnceLock<Setup> = OnceLock::new();
    SETUP.get_or_init(|| {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let interface = directory.path().join("static");
        std::fs::create_dir_all(interface.join("assets")).expect("a directory");
        std::fs::write(
            interface.join("index.html"),
            "<!doctype html><title>g</title>",
        )
        .expect("a page");
        std::fs::write(interface.join("assets/app-abc.js"), "console.log(1)").expect("a script");
        std::fs::write(interface.join("stalwart-switch.js"), "(() => {})();").expect("a script");
        // A recorded history and a status with samples, so that the routes
        // that read them run their queries.
        let events = config.database(Database::Events);
        std::fs::create_dir_all(events.parent().expect("a directory")).expect("a directory");
        let history =
            EventStore::open(&events, Limits::new(30, 10_000, 64 << 20)).expect("a store");
        history.start(NOW).expect("a started store");
        let batch: Value = serde_json::from_str(include_str!(
            "../../crates/ingest/tests/fixtures/batch.json"
        ))
        .expect("the fixture batch");
        let recorded = batch["events"].as_array().expect("events");
        history.ingest(recorded, NOW).expect("a stored batch");
        let status = config.database(Database::Status);
        std::fs::create_dir_all(status.parent().expect("a directory")).expect("a directory");
        let mut samples = StatusStore::open(&status, 90).expect("a status store");
        let snapshot = Snapshot {
            schema_version: SCHEMA,
            collected_at: "2026-11-06T10:40:00+00:00".to_owned(),
            observations: Vec::new(),
            provider_errors: Vec::new(),
        };
        let gauges = [("queue_count".to_owned(), 3.0)].into();
        let counters = [("messages_received".to_owned(), 7.0)].into();
        samples
            .write(NOW, &snapshot, &gauges, &counters)
            .expect("a stored snapshot");

        let store = Arc::new(
            WebStore::open(&config.web.state_directory.join("web.sqlite")).expect("a web store"),
        );
        let session = NewSession {
            subject: "1",
            email: "1@example.test",
            token: "admin-token",
            client_ip: None,
            lifetime: 365 * 86400,
        };
        let (identifier, session) = store.create(&session).expect("a session");
        let actions: BTreeSet<String> = (config.broker.actions.iter())
            .map(|action| action.id.clone())
            .collect();
        let gate = Gate::new(
            Arc::clone(&store),
            Arc::new(Granting),
            ORIGIN.into(),
            actions,
            false,
        )
        .with_cache_time(Duration::from_secs(3600));
        let app = App::new(config, store, gate, Box::new(NoProvider), interface);
        Setup {
            router: router(app),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime"),
            cookie: format!("{SESSION_COOKIE}={identifier}"),
            csrf: session.csrf,
            _directory: directory,
        }
    })
}

/// The request a fuzz input spells, or `None` if it spells none.
fn request(setup: &Setup, data: &[u8]) -> Option<Request<Body>> {
    let text = String::from_utf8_lossy(data);
    let (head, body) = text.split_once("\n\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let (flags, target) = lines.next()?.split_once(' ')?;
    let method = match flags.bytes().last()? {
        b'G' => Method::GET,
        b'P' => Method::POST,
        b'U' => Method::PUT,
        b'D' => Method::DELETE,
        b'A' => Method::PATCH,
        b'H' => Method::HEAD,
        b'O' => Method::OPTIONS,
        _ => return None,
    };
    let mut request = Request::builder().method(method).uri(target);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = HeaderName::from_bytes(name.trim().as_bytes());
        let value = HeaderValue::from_str(value.trim());
        if let (Ok(name), Ok(value)) = (name, value) {
            request = request.header(name, value);
        }
    }
    if flags.contains('s') {
        request = request.header("cookie", &setup.cookie);
    }
    if flags.contains('w') {
        request = request
            .header("origin", ORIGIN)
            .header("x-csrf-token", &setup.csrf);
    }
    request.body(Body::from(body.to_owned())).ok()
}

fuzz_target!(|data: &[u8]| {
    let setup = setup();
    let Some(request) = request(setup, data) else {
        return;
    };
    let shown = format!("{} {}", request.method(), request.uri());
    let answer = setup.runtime.block_on(async {
        let answer = setup
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = answer.status();
        // Reading the body runs what the handler streams.
        to_bytes(answer.into_body(), 64 << 20)
            .await
            .expect("the answer has a body");
        status
    });
    assert_ne!(answer, StatusCode::INTERNAL_SERVER_ERROR, "{shown}");
});
