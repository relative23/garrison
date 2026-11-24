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
//!
//! A secret's file holds what Stalwart uses: a new API key's at once, the
//! webhook's new key and a new scrape credential after Stalwart has
//! reloaded its settings, which is when it takes them. So the next run
//! brings both places together wherever a run stopped.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Subcommand;
use garrison_collector::providers::stalwart::REQUIRED_PERMISSIONS as COLLECTOR_PERMISSIONS;
use garrison_core::config::Config;

use crate::say;
use administrator::Source;
use api::{Admin, unreadable};
use client::ensure_oauth_client;
use exporter::ensure_metrics;
use folder::{writable, write_secret};
use keys::Key;
use objects::{Action, Enabled, Set};
use webhook::ensure_webhook;

mod administrator;
mod api;
mod client;
mod exporter;
mod folder;
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
const BROKER: Key = Key {
    file: "broker-native-key",
    description: "garrison broker",
    permissions: &BROKER_PERMISSIONS,
    held: true,
    without: "the broker checks no user's rights",
};
const COLLECTOR: Key = Key {
    file: "collector-native-key",
    description: "garrison collector",
    permissions: &COLLECTOR_PERMISSIONS,
    held: false,
    without: "the cards that need the collector's key cannot read Stalwart",
};
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

fn random(bytes: usize) -> Result<String, String> {
    let mut data = vec![0; bytes];
    getrandom::fill(&mut data).map_err(|error| error.to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(data))
}

/// What the operator asked of `stalwart setup` besides the administrator,
/// and the command that a failure names as the run that mends it.
struct Asked<'a> {
    skip_metrics: bool,
    webhook_url: Option<&'a str>,
    allowed: &'a [String],
    rotate: bool,
    again: &'a str,
}

/// What a run has done so far, kept also where it fails on the way: the
/// keys that new ones replace, and the files it wrote anew whose secret a
/// running service holds, which Stalwart uses by then.
#[derive(Default)]
struct Done {
    replaced: Vec<keys::Replaced>,
    renewed: BTreeSet<&'static str>,
}

fn setup(config: &Config, source: &Source, asked: &Asked<'_>) -> Result<(), String> {
    let again = format!("Run `{}` again once this is mended", asked.again);
    let mended = |error: String| format!("{}. {again}.", error.trim_end_matches('.'));
    milter::prepare(config).map_err(mended)?;
    let admin = Admin::new(config, source.authorization().map_err(mended)?);
    // Keys work only from these networks: loopback, and for test setups such as
    // the contract lab's Docker bridge whatever --allow-network adds.
    let mut networks = Enabled::of(LOOPBACK);
    for text in asked.allowed {
        networks.insert(keys::network(text).map_err(mended)?);
    }
    let mut done = Done::default();
    let configured = configure(&admin, config, asked, &networks, &mut done);
    // Before the replaced keys go, also after a failure: the broker would
    // otherwise be left with a key that is gone. Each service whose secret
    // the run wrote anew, and once it is done each that holds another one
    // than its file.
    let directory = &config.credentials_directory;
    if configured.is_ok() {
        done.renewed.extend(restart::stale(directory));
    }
    match (&configured, restart::restart(directory, &done.renewed)) {
        (Ok(()), None) => say("Settings reloaded."),
        (Ok(()), Some(line)) => say(&format!("Settings reloaded. {line}")),
        (Err(_), Some(line)) => say(&line),
        (Err(_), None) => {}
    }
    // After a failure they go all the same, since keys are replaced
    // because someone may have seen them.
    let removed = keys::remove(&admin, &done.replaced);
    match (configured, removed) {
        (Ok(()), Ok(())) => {
            source.finish();
            Ok(())
        }
        (Ok(()), Err(also)) => Err(format!(
            "The API keys that new ones replaced could not be removed: {also}. {again}, which \
             removes them."
        )),
        (Err(error), Err(_)) if !done.replaced.is_empty() => Err(format!(
            "{}. {again}, which also removes the API keys that new ones replaced.",
            error.trim_end_matches('.')
        )),
        (Err(error), _) => Err(mended(error)),
    }
}

/// Everything setup makes in Stalwart and here but the removal of the keys
/// that new ones replace, which go to `done` with what it wrote anew: the
/// keys, the webhook, the sign-in client, the exporter and the macro
/// filter's entry; then Stalwart reloads its settings, the files of the
/// secrets it takes then are written, and the keys are tried from this host.
fn configure(
    admin: &Admin,
    config: &Config,
    asked: &Asked<'_>,
    networks: &Enabled,
    done: &mut Done,
) -> Result<(), String> {
    let (directory, rotate) = (&config.credentials_directory, asked.rotate);
    let broker = keys::ensure(admin, directory, &BROKER, networks, rotate)?;
    done.replaced.extend(broker.replaced);
    if broker.made {
        done.renewed.insert(BROKER.file);
    }
    // Where its old key had to go first, the broker checks no rights until
    // it starts again with the new one, so it does at once.
    if broker.gone_first {
        restart_broker(directory, done);
    }
    let collector = match keys::ensure(admin, directory, &COLLECTOR, networks, rotate) {
        // No room beside the keys the broker's new one replaced: they go
        // first, once the broker holds the new one.
        Err(error) if keys::over_quota(&error) && !done.replaced.is_empty() => {
            restart_broker(directory, done);
            keys::remove(admin, &done.replaced)?;
            done.replaced.clear();
            keys::ensure(admin, directory, &COLLECTOR, networks, rotate)?
        }
        collector => collector?,
    };
    done.replaced.extend(collector.replaced);
    let webhook = ensure_webhook(admin, config, directory, asked.webhook_url, rotate)?;
    let mut steps = vec![
        broker.step,
        collector.step,
        webhook.step,
        ensure_oauth_client(admin, config)?,
    ];
    let mut credential = None;
    if !asked.skip_metrics {
        let exported = ensure_metrics(admin, directory, rotate)?;
        steps.push(exported.step);
        credential = exported.new_credential;
    }
    steps.extend(milter::ensure(admin, config, directory)?);
    admin.set("x:Action/set", &Set::create(Action::ReloadSettings))?;
    // Stalwart signs with the webhook's new key and takes the new scrape
    // credential from now on, so their files follow.
    if let Some(key) = &webhook.new_key {
        write_secret(&directory.join(webhook::KEY_FILE), key)?;
        done.renewed.insert(webhook::KEY_FILE);
    }
    if let Some(document) = &credential {
        exporter::keep(directory, document)?;
    }
    for step in &steps {
        say(&format!("- {step}"));
    }
    if let Some(step) = milter::retire(config) {
        say(&format!("- {step}"));
    }
    tried(admin, config, networks, done)
}

/// The broker started again at once with the new key this run made, so that
/// the keys it replaces may go before the run ends.
fn restart_broker(directory: &Path, done: &mut Done) {
    if done.renewed.remove(BROKER.file)
        && let Some(line) = restart::restart(directory, &BTreeSet::from([BROKER.file]))
    {
        say(&line);
    }
}

/// Both keys tried from this host, as the services will use them. A key
/// that Stalwart does not know, as after the credentials directory was put
/// back from a copy older than the last rotation, is made anew, once.
fn tried(
    admin: &Admin,
    config: &Config,
    networks: &Enabled,
    done: &mut Done,
) -> Result<(), String> {
    let directory = &config.credentials_directory;
    let unknown = keys::verify(config, directory, &[&BROKER, &COLLECTOR])?;
    for key in &unknown {
        let made = keys::ensure(admin, directory, key, networks, true)?;
        done.replaced.extend(made.replaced);
        if key.held {
            done.renewed.insert(key.file);
        }
        say(&format!(
            "- Stalwart did not know the API key in {}; made a new one",
            directory.join(key.file).display()
        ));
    }
    if let Some(key) = keys::verify(config, directory, &unknown)?.first() {
        return Err(format!(
            "Stalwart does not take the API key it just made in {} (HTTP 401)",
            key.file
        ));
    }
    say("- Stalwart accepts both API keys from this host");
    Ok(())
}

pub(crate) fn run(config: &Config, command: &Command) -> u8 {
    run_as(config, command, None)
}

/// `run` as a step of `garrison setup`, which is then the run that mends a
/// failure, since it also takes the steps after this one.
pub(crate) fn run_in_wizard(config: &Config, command: &Command) -> u8 {
    run_as(config, command, Some("garrison setup"))
}

fn run_as(config: &Config, command: &Command, again: Option<&str>) -> u8 {
    let Command::Setup {
        admin_credential,
        skip_metrics,
        webhook_url,
        allow_network,
        rotate,
    } = command;
    let again = again.unwrap_or(if *rotate {
        "garrison stalwart setup --rotate"
    } else {
        "garrison stalwart setup"
    });
    let source = match Source::of(admin_credential.as_deref()) {
        Ok(source) => source,
        Err(message) => {
            crate::complain(&message);
            return 2;
        }
    };
    if let Err((code, message)) = writable(&config.credentials_directory, again) {
        crate::complain(&message);
        return code;
    }
    folder::sweep(&config.credentials_directory);
    let asked = Asked {
        skip_metrics: *skip_metrics,
        webhook_url: webhook_url.as_deref(),
        allowed: allow_network,
        rotate: *rotate,
        again,
    };
    match setup(config, &source, &asked) {
        Ok(()) => 0,
        Err(error) => {
            crate::complain(&error);
            1
        }
    }
}

#[cfg(test)]
mod call_tests;
#[cfg(test)]
mod kept_tests;
