//! Garrison's own broker and authority behind the web service, against a
//! stand-in for Stalwart, and a journal of what both services write: for the
//! tests that follow a failure from Stalwart or the broker to the web
//! service's answer and to the journals.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use garrison_authz::Authority;
use garrison_broker::client::CallError;
use garrison_broker::protocol::{BrokerError, Request};
use garrison_broker::runner::{Outcome, Runner};
use garrison_broker::server::dispatch;
use garrison_broker::service::Broker as Service;
use garrison_broker::store::{JobStatus, JobStore};
use garrison_core::config::{Action, Config, Database};
use garrison_stalwart::Error;
use garrison_stalwart::oidc::{CodeExchange, Token};
use garrison_testing::http::{json, serve};
use garrison_testing::{config, credentials, policy_document, write_policy};
use garrison_web::security::{Broker, Gate};
use garrison_web::store::WebStore;
use garrison_web::{App, Identity, router};
use serde_json::{Value, json as value};

use super::{Client, ORIGIN, grant};

pub(crate) const TOKEN: &str = "token-0123456789abcdef";

/// The lines both services write in this test binary.
pub(crate) struct Journal(Mutex<Vec<String>>);

impl log::Log for Journal {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        if record.target().starts_with("garrison_") {
            let line = format!("{} {}", record.level(), record.args());
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(line);
        }
    }

    fn flush(&self) {}
}

static JOURNAL: Journal = Journal(Mutex::new(Vec::new()));

/// One test at a time looks at the journal.
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The journal for the calling test alone while it holds the guard: what
/// both services write from now on is kept, and no other test of its file
/// writes meanwhile.
pub(crate) async fn journal() -> tokio::sync::MutexGuard<'static, ()> {
    // The first test of the binary sets it; the others find it set.
    let _ = log::set_logger(&JOURNAL);
    log::set_max_level(log::LevelFilter::Info);
    let turn = TURN.lock().await;
    written();
    turn
}

/// The journal's lines since the last call.
pub(crate) fn written() -> Vec<String> {
    std::mem::take(&mut *JOURNAL.0.lock().unwrap())
}

/// Garrison's own broker, asked as the web service asks it over its socket.
pub(crate) struct Asked(pub(crate) Arc<Service>);

impl Broker for Asked {
    fn call(&self, request: &Request) -> Result<Value, CallError> {
        dispatch(&self.0, request).map_err(CallError::Refused)
    }
}

/// A broker the test changes while the web service runs.
pub(crate) struct Switch(pub(crate) Mutex<Arc<dyn Broker>>);

impl Broker for Switch {
    fn call(&self, request: &Request) -> Result<Value, CallError> {
        let broker = Arc::clone(&self.0.lock().unwrap());
        broker.call(request)
    }
}

/// A broker that answers every request with `answer`.
pub(crate) struct Fixed(pub(crate) Result<Value, CallError>);

impl Broker for Fixed {
    fn call(&self, _: &Request) -> Result<Value, CallError> {
        self.0.clone()
    }
}

/// The code exchange gives the one token.
struct Exchange;

impl Identity for Exchange {
    fn exchange_code(&self, _: &CodeExchange<'_>) -> Result<Token, Error> {
        Ok(Token {
            access_token: TOKEN.into(),
            expires_in: 3600,
        })
    }

    fn revoke(&self, _: &str, _: &str) -> Result<(), Error> {
        Ok(())
    }
}

struct Never;

impl Runner for Never {
    fn preflight(&self, _: &Action) -> Result<(), BrokerError> {
        Ok(())
    }

    fn still_running(&self, _: &Action) -> bool {
        false
    }

    fn run(&self, _: &Action) -> Outcome {
        Outcome {
            status: JobStatus::Failed,
            message: "never",
            may_still_run: false,
        }
    }
}

/// The web service before `broker`, which it asks at every request.
pub(crate) fn web(config: &Config, broker: Arc<dyn Broker>) -> (Client, Arc<App>) {
    let path = config.database(Database::Web);
    let store = Arc::new(WebStore::open(&path).unwrap());
    let ids: BTreeSet<String> = config
        .broker
        .actions
        .iter()
        .map(|action| action.id.clone())
        .collect();
    let gate = Gate::new(Arc::clone(&store), broker, ORIGIN.into(), ids, false)
        .with_cache_time(Duration::ZERO);
    let interface = config.web.state_directory.join("static");
    let app = App::new(config.clone(), store, gate, Box::new(Exchange), interface);
    (Client::new(router(Arc::clone(&app))), app)
}

/// Garrison's own broker for `config`, which names the Stalwart it asks.
pub(crate) fn service(config: &Config) -> Arc<Service> {
    let store = JobStore::open(&config.database(Database::Jobs)).unwrap();
    Service::new(
        Box::new(Authority::new(config, credentials(config))),
        config.broker.actions.clone(),
        store,
        Box::new(Never),
        Box::new(|work| {
            work();
            Ok(())
        }),
    )
}

/// A configuration in `directory` for Stalwart at `url`, with the test policy.
pub(crate) fn configured(directory: &Path, url: &str) -> Config {
    let config = config(directory, url);
    write_policy(&config, &policy_document());
    config
}

/// A JMAP answer with one method's list.
pub(crate) fn listed(method: &str, list: &Value) -> String {
    json(&value!({"methodResponses": [[method, {"list": list, "notFound": []}, "0"]]}))
}

pub(crate) fn identity() -> String {
    json(&value!({"sub": "1", "email": "ann@example.test"}))
}

/// Stalwart's answers to a check that grants subject 1 the administrator's
/// profile: UserInfo, the account, the settings and its role.
pub(crate) fn granting() -> Vec<String> {
    vec![
        identity(),
        listed(
            "x:Account/get",
            &value!([{"id": "b", "@type": "User",
            "roles": {"@type": "Custom", "roleIds": {"e": true}}, "permissions": {"@type": "Inherit"}}]),
        ),
        listed(
            "x:Authentication/get",
            &value!([{"id": "singleton", "defaultAdminRoleIds": {},
            "defaultUserRoleIds": {}}]),
        ),
        listed(
            "x:Role/get",
            &value!([{"id": "e", "roleIds": {}, "disabledPermissions": {},
            "enabledPermissions": {"authenticate": true, "sysActionCreate": true,
                "sysRoleUpdate": true}}]),
        ),
    ]
}

/// What a case ends in: the web service's answer to a request of a signed-in
/// user (status and detail), whether that ends the session, the reason the
/// sign-in page gets (`None` where the case is no sign-in's), and words of
/// the one line in a journal that names the cause.
pub(crate) struct Expected {
    pub(crate) status: u16,
    pub(crate) detail: &'static str,
    pub(crate) ended: bool,
    pub(crate) reason: Option<&'static str>,
    pub(crate) line: String,
}

/// A case that keeps the session and says at sign-in that access could not
/// be checked.
pub(crate) fn kept(status: u16, detail: &'static str, line: &str) -> Expected {
    Expected {
        status,
        detail,
        ended: false,
        reason: Some("unchecked"),
        line: line.to_owned(),
    }
}

/// A case that ends the session and fails the sign-in.
pub(crate) fn ended(status: u16, detail: &'static str, line: &str) -> Expected {
    Expected {
        status,
        detail,
        ended: true,
        reason: Some("1"),
        line: line.to_owned(),
    }
}

/// How often a line holds `words`.
fn found(lines: &[String], words: &str) -> usize {
    lines.iter().filter(|line| line.contains(words)).count()
}

/// The reason a sign-in ended on the sign-in page with, or "" where it
/// made a session.
pub(crate) async fn signed_in(client: &mut Client) -> String {
    let login = client.get("/auth/login").await;
    let location = url::Url::parse(login.header("location")).unwrap();
    let (_, state) = location
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap();
    let callback =
        format!("/auth/callback?state={state}&code=code&iss=https%3A%2F%2Fmail.example.test");
    let back = client.get(&callback).await.header("location").to_owned();
    back.split_once("login_error=")
        .map(|(_, reason)| reason.to_owned())
        .unwrap_or_default()
}

/// What differs from `expected` at a request of the signed-in user of
/// `client` and in the lines it wrote.
async fn requested(client: &mut Client, app: &App, expected: &Expected) -> Vec<String> {
    written();
    let answer = client.get("/api/status").await;
    let lines = written();
    let mut wrong = Vec::new();
    let got = (
        answer.status.as_u16(),
        answer.json()["detail"].as_str().unwrap_or("").to_owned(),
    );
    if got != (expected.status, expected.detail.to_owned()) {
        wrong.push(format!("answered {got:?}"));
    }
    let cookie = client.cookies.get("__Host-garrison_session").cloned();
    let ended = app
        .store
        .get(&cookie.unwrap_or_default())
        .unwrap()
        .is_none();
    if ended != expected.ended {
        wrong.push(format!("session ended: {ended}"));
    }
    if found(&lines, &expected.line) != 1 {
        wrong.push(format!("lines {lines:?}"));
    }
    wrong
}

/// What differs from `expected` at a sign-in through `client`.
async fn at_sign_in(client: &mut Client, expected: &Expected) -> Vec<String> {
    let Some(reason) = expected.reason else {
        return Vec::new();
    };
    written();
    let got = signed_in(client).await;
    let lines = written();
    let mut wrong = Vec::new();
    if got != reason {
        wrong.push(format!("at sign-in the reason {got:?}"));
    }
    let rejected = format!(
        "WARN Sign-in rejected by authorization (HTTP {}: ",
        expected.status
    );
    if found(&lines, &expected.line) != 1 || found(&lines, &rejected) != 1 {
        wrong.push(format!("at sign-in lines {lines:?}"));
    }
    wrong
}

/// One kind of failure at Stalwart, which Stalwart's `answers` to one check
/// make, or which `before` makes of Garrison's own setup: what differs from
/// `expected` at a request of a user whose sign-in Stalwart granted, and at
/// a sign-in.
pub(crate) async fn at_stalwart(
    answers: &[String],
    before: fn(&Config),
    expected: &Expected,
) -> Vec<String> {
    let directory = tempfile::tempdir().unwrap();
    let server = serve([granting(), answers.to_vec()].concat());
    let config = configured(directory.path(), &server.url);
    let (mut client, app) = web(&config, Arc::new(Asked(service(&config))));
    assert_eq!(signed_in(&mut client).await, "", "the sign-in before");
    before(&config);
    let mut wrong = requested(&mut client, &app, expected).await;
    drop(server);
    let directory = tempfile::tempdir().unwrap();
    let server = serve(answers.to_vec());
    let config = configured(directory.path(), &server.url);
    let (mut client, _app) = web(&config, Arc::new(Asked(service(&config))));
    before(&config);
    wrong.extend(at_sign_in(&mut client, expected).await);
    drop(server);
    wrong
}

/// One kind of failure of the broker's own, which `failing` stands for: what
/// differs from `expected` at a request of a user whose sign-in the broker
/// granted, and at a sign-in.
pub(crate) async fn at_the_broker(
    failing: fn(&Path) -> Arc<dyn Broker>,
    expected: &Expected,
) -> Vec<String> {
    let directory = tempfile::tempdir().unwrap();
    let config = configured(directory.path(), "http://127.0.0.1:9");
    let granting: Arc<dyn Broker> = Arc::new(Fixed(Ok(grant("1", &["dashboard"], &[]))));
    let switch = Arc::new(Switch(Mutex::new(granting)));
    let (mut client, app) = web(&config, Arc::clone(&switch) as Arc<dyn Broker>);
    assert_eq!(signed_in(&mut client).await, "", "the sign-in before");
    *switch.0.lock().unwrap() = failing(directory.path());
    let mut wrong = requested(&mut client, &app, expected).await;
    let (mut client, _app) = web(&config, failing(directory.path()));
    wrong.extend(at_sign_in(&mut client, expected).await);
    wrong
}
