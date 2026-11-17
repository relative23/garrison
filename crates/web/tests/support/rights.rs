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
use garrison_testing::http::json;
use garrison_testing::{config, credentials, policy_document, write_policy};
use garrison_web::security::{Broker, Gate};
use garrison_web::store::WebStore;
use garrison_web::{App, Identity, router};
use serde_json::{Value, json as value};

use super::{Client, ORIGIN};

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
