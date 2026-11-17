//! `garrison stalwart setup`: configure Stalwart for Garrison.
//!
//! Creates or updates, idempotently:
//!   * the signed webhook that delivers selected events to the ingest service,
//!   * a read-only API key for the broker (account and role metadata),
//!   * a read-only API key for the collector (status observations),
//!   * the Prometheus exporter with a dedicated scrape credential (if not in use).
//!   * Garrison's OAuth client, for sign-in only.
//!
//! API keys use Replace permissions, may be used only from loopback and are
//! tried once from this host at the end (see `keys`). Secrets
//! are written to the credentials directory (mode 0600) and printed nowhere. The
//! administrator is asked at the terminal or read from standard input or a
//! root-only file (see `administrator`), never from the command line.
//! Existing objects are matched by their description (the OAuth client by its
//! client ID); foreign objects are not touched.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Subcommand;
use garrison_collector::providers::stalwart::REQUIRED_PERMISSIONS as COLLECTOR_PERMISSIONS;
use garrison_core::config::Config;
use garrison_core::files::atomic_write;
use garrison_core::json;
use garrison_stalwart::http::Request;
use garrison_stalwart::jmap::{Answers, Calls, Get, Got, Problem};
use garrison_stalwart::{Error, SUPPORTED};
use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Serialize};

use crate::say;
use administrator::Source;
use exporter::ensure_metrics;
use objects::{Action, Enabled, OAuthClient, Refused, Set, StoredClient};
use restart::restart;
use webhook::ensure_webhook;

mod administrator;
mod exporter;
mod keys;
mod milter;
mod objects;
mod restart;
mod webhook;

const BROKER_PERMISSIONS: [&str; 4] = [
    "authenticate",
    "sysAccountGet",
    "sysRoleGet",
    "sysAuthenticationGet",
];
const LOOPBACK: [&str; 2] = ["127.0.0.1/32", "::1/128"];
const MAX_ANSWER: usize = 4 * 1024 * 1024;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Create webhook, API keys and metrics access.
    Setup {
        /// The Stalwart administrator: a 0600 JSON file with {"username","secret"}
        /// or {"apiKey"}, or `-` for that JSON on standard input. Without it, the
        /// administrator is asked at the terminal.
        #[arg(long)]
        admin_credential: Option<PathBuf>,
        /// Leave the Prometheus exporter and its credential as they are.
        #[arg(long)]
        skip_metrics: bool,
        /// Where Stalwart delivers events instead of the ingest on 127.0.0.1;
        /// the ingest accepts loopback only, so this is for test setups.
        #[arg(long)]
        webhook_url: Option<String>,
        /// A further network the API keys may be used from, such as a test
        /// lab's Docker bridge; repeatable.
        #[arg(long)]
        allow_network: Vec<String>,
        /// Replace the API keys, the webhook signature key and the metrics
        /// credential with new secrets, then restart the services that hold them.
        #[arg(long)]
        rotate: bool,
    },
}

/// Management-API calls with the operator-supplied administrator credential.
struct Admin {
    url: String,
    authorization: String,
}

fn random(bytes: usize) -> Result<String, String> {
    let mut data = vec![0; bytes];
    getrandom::fill(&mut data).map_err(|error| error.to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(data))
}

impl Admin {
    fn new(config: &Config, authorization: String) -> Self {
        Admin {
            url: format!("{}/jmap/", config.deployment.stalwart_url),
            authorization,
        }
    }

    /// One method call, its answer read as a `T`.
    ///
    /// An answer that is no `T` is reported without its text: answers hold
    /// secrets, and serde quotes what it could not read.
    fn call<A: Serialize, T: DeserializeOwned>(
        &self,
        method: &str,
        arguments: &A,
    ) -> Result<T, String> {
        let body = serde_json::to_string(&Calls::new([(method, arguments)]))
            .map_err(|error| format!("{method}: {error}"))?;
        let answer = Request::post(&self.url, body.as_bytes())
            .header("Authorization", &self.authorization)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(30))
            .limit(MAX_ANSWER)
            .send()
            .map_err(|error| match error {
                Error::Unreadable(why) => unreadable(method, &why),
                Error::Unavailable(why)
                | Error::Limited(why)
                | Error::InvalidToken(why)
                | Error::Denied(why)
                | Error::Misconfigured(why) => format!("{method}: {why}"),
            })?;
        match answer.status {
            200 => {}
            // A wrong password, an unknown user and an API key Stalwart does
            // not know (measured on Stalwart 1.1.0).
            401 => {
                return Err(
                    "Stalwart refused the administrator (HTTP 401): check the user name \
                            and the password, or the API key."
                        .into(),
                );
            }
            // A credential Stalwart knows, from an address it does not take
            // it from: an API key's networks, or a block of the address.
            403 => {
                return Err(
                    "Stalwart refused the administrator from this host's address (HTTP \
                            403): its API key may not allow that address, or Stalwart blocked \
                            the address after failed sign-ins, which operations.md (\"Sign-in \
                            fails\") says how to lift."
                        .into(),
                );
            }
            status => return Err(format!("{method}: HTTP {status}")),
        }
        let document = json::parse(&answer.body, MAX_ANSWER)
            .map_err(|error| unreadable(method, &error.to_string()))?;
        let malformed = || unreadable(method, "malformed answer");
        let answers: Answers = json::object(document).map_err(|_| malformed())?;
        let first = answers.method_responses.into_iter().next();
        let (name, payload, _) = first.ok_or_else(malformed)?;
        if name == "error" {
            let problem: Problem = json::object(payload).unwrap_or_default();
            return Err(format!(
                "{method}: {} {}",
                problem.kind.unwrap_or_default(),
                problem.description.unwrap_or_default()
            ));
        }
        if !payload.is_object() {
            return Err(malformed());
        }
        let refused = Refused::deserialize(&payload).map_err(|_| malformed())?;
        if let Some(refusal) = refused.first() {
            return Err(format!("{method}: {refusal}"));
        }
        json::object(payload).map_err(|_| unreadable(method, "unexpected answer"))
    }

    /// A `/set` method whose answer says nothing setup needs.
    fn set<T: Serialize>(&self, method: &str, arguments: &Set<'_, T>) -> Result<(), String> {
        self.call::<_, IgnoredAny>(method, arguments).map(drop)
    }

    /// Every object of a kind, read as far as `T` names its fields.
    fn list<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>, String> {
        let all = Get {
            ids: None,
            properties: None,
        };
        let got: Got<T> = self.call(&format!("x:{kind}/get"), &all)?;
        Ok(got.list)
    }
}

/// What setup says of an answer of Stalwart's that this release does not
/// read: the method, what was wrong with it, and where the supported
/// Stalwart releases are named, since no run of setup mends it.
fn unreadable(method: &str, what: &str) -> String {
    format!("{method}: {what}, which this release of Garrison does not read; {SUPPORTED}")
}

fn write_secret(path: &Path, value: &str) -> Result<(), String> {
    atomic_write(path, format!("{value}\n").as_bytes(), 0o600).map_err(|error| error.to_string())
}

/// Register Garrison as an OAuth client of Stalwart.
///
/// Sign-in uses a client ID URL. Stalwart accepts such IDs from any website
/// only through its `clientMetadataDocuments` policy, which can stay off: a
/// registered client needs none and is shown under its own name as verified.
/// It may only return to the callback, gets no service such as mail (sign-in
/// only) and no grant but the authorization code: Stalwart allows a client a
/// refresh token unless told otherwise, and Garrison never asks for one.
fn ensure_oauth_client(admin: &Admin, config: &Config) -> Result<String, String> {
    let origin = &config.deployment.public_origin;
    let client_id = garrison_web::app::client_id(origin);
    let mut wanted = OAuthClient {
        client_id: None,
        description: "Garrison",
        redirect_uris: Enabled::of([garrison_web::app::redirect_uri(origin)]),
        post_logout_redirect_uris: Enabled::none(),
        scopes: Enabled::none(),
        grant_types: Enabled::of(["authorizationCode"]),
    };
    let existing = admin
        .list::<StoredClient>("OAuthClient")?
        .into_iter()
        .find(|item| item.client_id.as_deref() == Some(client_id.as_str()));
    if let Some(item) = existing {
        admin.set("x:OAuthClient/set", &Set::update(&item.id, wanted))?;
        return Ok(format!("updated OAuth client {client_id}"));
    }
    wanted.client_id = Some(&client_id);
    admin.set("x:OAuthClient/set", &Set::create(wanted))?;
    Ok(format!("registered OAuth client {client_id}"))
}

/// What the operator asked of `stalwart setup` besides the administrator.
struct Asked<'a> {
    skip_metrics: bool,
    webhook_url: Option<&'a str>,
    allowed: &'a [String],
    rotate: bool,
}

fn setup(config: &Config, source: &Source, asked: &Asked<'_>) -> Result<u8, String> {
    milter::prepare(config)?;
    let admin = Admin::new(config, source.authorization()?);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&config.credentials_directory)
        .map_err(|error| error.to_string())?;
    // Keys work only from these networks: loopback, and for test setups such as
    // the contract lab's Docker bridge whatever --allow-network adds.
    let mut networks = Enabled::of(LOOPBACK);
    for text in asked.allowed {
        networks.insert(keys::network(text)?);
    }
    let mut replaced = Vec::new();
    let configured = configure(&admin, config, asked, &networks, &mut replaced);
    // The keys that new ones replaced go last: the services that held them
    // have restarted with the new ones by now. After a failure they go all
    // the same, since keys are replaced because someone may have seen them.
    let removed = keys::remove(&admin, &replaced);
    match (configured, removed) {
        (Ok(()), Ok(())) => {}
        (Ok(()), Err(also)) => {
            return Err(format!(
                "The API keys that new ones replaced could not be removed: {also}. Run this \
                 again with --rotate."
            ));
        }
        (Err(error), Ok(())) if replaced.is_empty() => return Err(error),
        (Err(error), Ok(())) => {
            return Err(format!(
                "{error}. The API keys that new ones replaced were removed: restart \
                 garrison-ingest and garrison-broker once this is mended."
            ));
        }
        (Err(error), Err(also)) => {
            return Err(format!(
                "{error}. The API keys that new ones replaced could not be removed either: {also}"
            ));
        }
    }
    source.finish();
    Ok(0)
}

/// Everything setup makes in Stalwart and here but the removal of the keys
/// that new ones replace, whose ids go to `replaced`: the keys, the
/// webhook, the sign-in client, the exporter and the macro filter's entry,
/// then the new keys tried from this host and the services that hold
/// secrets restarted.
fn configure(
    admin: &Admin,
    config: &Config,
    asked: &Asked<'_>,
    networks: &Enabled,
    replaced: &mut Vec<String>,
) -> Result<(), String> {
    let (directory, rotate) = (&config.credentials_directory, asked.rotate);
    let fresh = rotate || restart::unheld(directory);
    let broker = keys::ensure(
        admin,
        directory,
        "broker-native-key",
        "garrison broker",
        &BROKER_PERMISSIONS,
        networks,
        rotate,
    )?;
    replaced.extend(broker.replaced);
    let collector = keys::ensure(
        admin,
        directory,
        "collector-native-key",
        "garrison collector",
        &COLLECTOR_PERMISSIONS,
        networks,
        rotate,
    )?;
    replaced.extend(collector.replaced);
    let mut steps = vec![
        broker.step,
        collector.step,
        ensure_webhook(admin, config, directory, asked.webhook_url, rotate)?,
        ensure_oauth_client(admin, config)?,
    ];
    if !asked.skip_metrics {
        steps.push(ensure_metrics(admin, directory, rotate)?);
    }
    steps.extend(milter::ensure(admin, config, directory)?);
    admin.set("x:Action/set", &Set::create(Action::ReloadSettings))?;
    for step in &steps {
        say(&format!("- {step}"));
    }
    if let Some(step) = milter::retire(config) {
        say(&format!("- {step}"));
    }
    say(&format!("- {}", keys::verify(config, directory)?));
    // Also a service that still holds what a rotation that failed, or a new
    // key for one Stalwart no longer had, replaced in its file.
    if fresh || restart::stale(directory) {
        restart();
    } else {
        say("Settings reloaded.");
    }
    Ok(())
}

pub(crate) fn run(config: &Config, command: &Command) -> u8 {
    let Command::Setup {
        admin_credential,
        skip_metrics,
        webhook_url,
        allow_network,
        rotate,
    } = command;
    let source = match Source::of(admin_credential.as_deref()) {
        Ok(source) => source,
        Err(message) => {
            crate::complain(&message);
            return 2;
        }
    };
    let asked = Asked {
        skip_metrics: *skip_metrics,
        webhook_url: webhook_url.as_deref(),
        allowed: allow_network,
        rotate: *rotate,
    };
    setup(config, &source, &asked).unwrap_or_else(|error| {
        crate::complain(&error);
        1
    })
}

#[cfg(test)]
mod call_tests;
