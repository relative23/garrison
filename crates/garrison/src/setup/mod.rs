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

use std::collections::BTreeMap;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Subcommand;
use garrison_collector::providers::stalwart::REQUIRED_PERMISSIONS as COLLECTOR_PERMISSIONS;
use garrison_collector::run::ScrapeCredential;
use garrison_core::config::Config;
use garrison_core::files::{Privacy, atomic_write, read_private};
use garrison_core::json;
use garrison_core::systemd::SYSTEMCTL;
use garrison_ingest::policy::{FORBIDDEN_EVENTS, event_types};
use garrison_stalwart::http::Request;
use garrison_stalwart::jmap::{Answers, Calls, Get, Got, Problem};
use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Serialize};

use crate::{say, units};
use administrator::Source;
use objects::{
    Action, Enabled, EventsPolicy, Exporter, HttpAuth, Level, Metrics, OAuthClient, Refused,
    Secret, Set, StoredClient, StoredMetrics, StoredWebHook, WebHook,
};

mod administrator;
mod keys;
mod milter;
mod objects;

const BROKER_PERMISSIONS: [&str; 4] = [
    "authenticate",
    "sysAccountGet",
    "sysRoleGet",
    "sysAuthenticationGet",
];
/// `WebHook` objects have no description; this header marks Garrison's own webhook.
const MARKER: (&str, &str) = ("X-Garrison", "events");
const LOOPBACK: [&str; 2] = ["127.0.0.1/32", "::1/128"];
/// The secrets a running service holds: the ingest's and the broker's.
const HELD: [&str; 2] = ["webhook-signature-key", "broker-native-key"];
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
            .map_err(|error| format!("{method}: {error}"))?;
        if answer.status != 200 {
            return Err(format!("{method}: HTTP {}", answer.status));
        }
        let document =
            json::parse(&answer.body, MAX_ANSWER).map_err(|error| format!("{method}: {error}"))?;
        let malformed = || format!("{method}: malformed answer");
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
        json::object(payload).map_err(|_| format!("{method}: unexpected answer"))
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

fn ensure_webhook(
    admin: &Admin,
    config: &Config,
    directory: &Path,
    url: Option<&str>,
    rotate: bool,
) -> Result<String, String> {
    let key_path = directory.join("webhook-signature-key");
    // Stalwart keeps a batch the ingest refuses during the switch and sends it again.
    if rotate || !key_path.exists() {
        write_secret(&key_path, &random(48)?)?;
    }
    let key = read_private(&key_path, 16384, Privacy::Owned).map_err(|error| error.to_string())?;
    let key = String::from_utf8_lossy(&key).trim().to_owned();
    let types = event_types();
    assert!(
        types.iter().all(|kind| !FORBIDDEN_EVENTS.contains(kind)),
        "policy invariant"
    );
    let url = url.map_or_else(
        || format!("http://127.0.0.1:{}/webhook", config.ingest.port),
        str::to_owned,
    );
    let webhook = WebHook {
        url: &url,
        events: Enabled::of(types.iter().copied()),
        events_policy: EventsPolicy::Include,
        level: Level::Trace,
        timeout: 5000,
        throttle: 1000,
        discard_after: 3_600_000,
        lossy: false,
        signature_key: Secret::Value { secret: &key },
        http_auth: HttpAuth::Unauthenticated,
        http_headers: BTreeMap::from([MARKER]),
        allow_invalid_certs: false,
        enable: true,
    };
    let marked = |item: &StoredWebHook| {
        let headers = item.http_headers.as_ref();
        headers.and_then(|headers| headers.get(MARKER.0)?.as_str()) == Some(MARKER.1)
    };
    let existing = admin
        .list::<StoredWebHook>("WebHook")?
        .into_iter()
        .find(marked);
    let result = if let Some(item) = existing {
        admin.set("x:WebHook/set", &Set::update(&item.id, webhook))?;
        "updated webhook"
    } else {
        admin.set("x:WebHook/set", &Set::create(webhook))?;
        "created webhook"
    };
    Ok(format!("{result} -> {url} ({} event types)", types.len()))
}

fn ensure_metrics(admin: &Admin, directory: &Path, rotate: bool) -> Result<String, String> {
    let target = directory.join("metrics-credential");
    let singleton = Get {
        ids: Some(&["singleton"]),
        properties: None,
    };
    let stored: Got<StoredMetrics> = admin.call("x:Metrics/get", &singleton)?;
    let current = stored.list.into_iter().next().unwrap_or_default();
    let current = current.prometheus.unwrap_or_default();
    let enabled = current.kind.as_deref() == Some("Enabled");
    let ours = enabled && current.auth_username.as_deref() == Some("garrison");
    if enabled && !ours {
        return Ok(
            "Prometheus exporter is enabled by someone else; not changed \
                   (configure metrics_credential manually)"
                .into(),
        );
    }
    if ours && target.exists() && !rotate {
        return Ok("Prometheus exporter already configured".into());
    }
    let secret = random(36)?;
    let exporter = Exporter::Enabled {
        auth_username: "garrison",
        auth_secret: Secret::Value { secret: &secret },
    };
    let metrics = Metrics {
        prometheus: exporter,
    };
    admin.set("x:Metrics/set", &Set::update("singleton", metrics))?;
    let credential = ScrapeCredential {
        username: "garrison".to_owned(),
        secret,
    };
    let document = serde_json::to_string(&credential).map_err(|error| error.to_string())?;
    atomic_write(&target, document.as_bytes(), 0o600).map_err(|error| error.to_string())?;
    Ok(format!(
        "enabled Prometheus exporter -> {}",
        target.display()
    ))
}

fn setup(
    config: &Config,
    source: &Source,
    skip_metrics: bool,
    webhook_url: Option<&str>,
    allowed: &[String],
    rotate: bool,
) -> Result<u8, String> {
    milter::prepare(config)?;
    let admin = Admin::new(config, source.authorization()?);
    let directory = &config.credentials_directory;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(|error| error.to_string())?;
    // Keys work only from these networks: loopback, and for test setups such as
    // the contract lab's Docker bridge whatever --allow-network adds.
    let mut networks = Enabled::of(LOOPBACK);
    for text in allowed {
        networks.insert(keys::network(text)?);
    }
    // A running service holds the secrets it read when it started.
    let fresh = rotate || HELD.iter().any(|name| !directory.join(name).exists());
    let mut steps = vec![
        keys::ensure(
            &admin,
            directory,
            "broker-native-key",
            "garrison broker",
            &BROKER_PERMISSIONS,
            &networks,
            rotate,
        )?,
        keys::ensure(
            &admin,
            directory,
            "collector-native-key",
            "garrison collector",
            &COLLECTOR_PERMISSIONS,
            &networks,
            rotate,
        )?,
        ensure_webhook(&admin, config, directory, webhook_url, rotate)?,
        ensure_oauth_client(&admin, config)?,
    ];
    if !skip_metrics {
        steps.push(ensure_metrics(&admin, directory, rotate)?);
    }
    steps.extend(milter::ensure(&admin, config, directory)?);
    admin.set("x:Action/set", &Set::create(Action::ReloadSettings))?;
    for step in &steps {
        say(&format!("- {step}"));
    }
    if let Some(step) = milter::retire(config) {
        say(&format!("- {step}"));
    }
    say(&format!("- {}", keys::verify(config, directory)?));
    if fresh {
        restart();
    } else {
        say("Settings reloaded.");
    }
    source.finish();
    Ok(0)
}

/// The services read their credentials when they start; the collector starts
/// anew for every run. Services that are not running read the new secrets
/// when they start, as on a first setup before Garrison runs.
fn restart() {
    let units = [units::INGEST, units::BROKER];
    let systemctl = |arguments: &[&str]| {
        std::process::Command::new(SYSTEMCTL)
            .args(arguments)
            .args(units)
            .stdout(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    if !rustix::process::geteuid().is_root() {
        say(
            "Settings reloaded. Restart garrison-ingest and garrison-broker so they read the new secrets.",
        );
    } else if !systemctl(&["is-active", "--quiet"]) {
        say("Settings reloaded; the services read the new secrets when they start.");
    } else if systemctl(&["try-restart"]) {
        say(
            "Settings reloaded; garrison-ingest and garrison-broker restarted with the new secrets.",
        );
    } else {
        say(
            "Settings reloaded. Restart garrison-ingest and garrison-broker so they read the new secrets.",
        );
    }
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
    setup(
        config,
        &source,
        *skip_metrics,
        webhook_url.as_deref(),
        allow_network,
        *rotate,
    )
    .unwrap_or_else(|error| {
        crate::complain(&error);
        1
    })
}
