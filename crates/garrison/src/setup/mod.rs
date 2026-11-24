//! `garrison stalwart setup`: configure Stalwart for Garrison.
//!
//! Creates or updates, idempotently:
//!   * the signed webhook that delivers selected events to the ingest service,
//!   * a read-only API key for the broker (account and role metadata),
//!   * a read-only API key for the collector (status observations),
//!   * the Prometheus exporter with a dedicated scrape credential (if not in use).
//!   * Garrison's OAuth client, for sign-in only,
//!   * the macro filter's entry, where the configuration has `[milter]`.
//!
//! API keys use Replace permissions, may be used only from loopback and are
//! tried from this host as soon as they are made or updated (see `keys`).
//! Secrets are written to the credentials directory (mode 0600) and printed
//! nowhere. The administrator is asked at the terminal or read from standard
//! input or a root-only file (see `administrator`), never from the command
//! line. Existing objects are matched by their description (the OAuth client
//! by its client ID); foreign objects are not touched.
//!
//! Wherever a run stops, each service holds a secret that Stalwart takes, and
//! Stalwart holds no secret of Garrison's that no file holds: a new API key
//! is written and taken up by its service before the key it replaces goes,
//! and a new signature key or scrape credential is written to its file
//! before Stalwart is given it, which it takes when it reloads its settings.
//! So the next run finishes, from what Stalwart and the files hold, whatever
//! a run left.

use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Subcommand;
use garrison_collector::providers::stalwart::REQUIRED_PERMISSIONS as COLLECTOR_PERMISSIONS;
use garrison_core::config::Config;

use crate::say;
use crate::state::State;
use administrator::Source;
use api::Admin;
use folder::{writable, write_secret};
use keys::Key;
use objects::{Action, Enabled, Set};

mod administrator;
mod api;
mod client;
mod exporter;
mod folder;
mod keys;
mod milter;
mod objects;
mod restart;
mod states;
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
};
const COLLECTOR: Key = Key {
    file: "collector-native-key",
    description: "garrison collector",
    permissions: &COLLECTOR_PERMISSIONS,
    held: false,
};
const LOOPBACK: [&str; 2] = ["127.0.0.1/32", "::1/128"];
const MAX_ANSWER: usize = 4 * 1024 * 1024;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Connect Stalwart: the webhook, the API keys, the sign-in client, the
    /// metrics access and the macro filter's entry.
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

fn random(bytes: usize) -> Result<String, State> {
    let mut data = vec![0; bytes];
    getrandom::fill(&mut data).map_err(states::no_random)?;
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

fn setup(config: &Config, source: &Source, asked: &Asked<'_>) -> Result<(), State> {
    let again = |state| states::again(state, asked.again);
    let admin = Admin::new(config, source.authorization().map_err(again)?);
    // Keys work only from these networks: loopback, and for test setups such as
    // the contract lab's Docker bridge whatever --allow-network adds.
    let mut networks = Enabled::of(LOOPBACK);
    for text in asked.allowed {
        networks.insert(keys::network(text).map_err(again)?);
    }
    configure(&admin, config, asked, &networks).map_err(again)?;
    source.finish();
    Ok(())
}

/// Everything setup makes in Stalwart and here, each step said once it is
/// done. What Stalwart holds is read first, so that what refuses refuses
/// before anything changes, and only what differs from what was asked is
/// written. Then the keys, each taken up by its service before the keys it
/// replaces go; the sign-in client and the macro filter's entry; the webhook
/// and the exporter, each new secret in its file before Stalwart is given
/// it. Stalwart then reloads its settings, which is when it takes them, and
/// the receiver starts again with its new key, as each service does that
/// holds another secret than its file.
fn configure(
    admin: &Admin,
    config: &Config,
    asked: &Asked<'_>,
    networks: &Enabled,
) -> Result<(), State> {
    let (directory, rotate) = (&config.credentials_directory, asked.rotate);
    let started = milter::prepare(admin, config)?;
    if let Some(step) = &started {
        say(&format!("- {step}"));
    }
    let found = keys::find(admin, directory, &[&BROKER, &COLLECTOR], rotate)?;
    let hook = webhook::find(admin)?;
    let client = client::find(admin, config)?;
    let metrics = if asked.skip_metrics {
        None
    } else {
        Some(exporter::find(admin)?)
    };
    let mut keys_changed = false;
    for (key, found) in [&BROKER, &COLLECTOR].into_iter().zip(found) {
        keys_changed |= keys::settle(admin, config, key, found, networks, &keys::take_up)?;
    }
    if keys_changed {
        say("- Stalwart accepts both API keys from this host");
    }
    // What Stalwart takes only when it reads its settings again.
    let mut steps = vec![client::ensure(admin, config, client)?];
    steps.push(milter::ensure(admin, config)?);
    let signing = webhook::key(directory, rotate)?;
    let url = asked.webhook_url;
    let hooked = webhook::ensure(admin, config, url, hook.as_ref(), &signing);
    steps.push(hooked.map_err(|error| states::until(error, signing.new, false))?);
    let scraping = match &metrics {
        Some(found) => exporter::credential(directory, found, rotate)
            .map_err(|error| states::until(error, signing.new, false))?,
        None => None,
    };
    let new_scrape = scraping.as_ref().is_some_and(|scrape| scrape.new);
    match (&metrics, &scraping) {
        (Some(found), Some(scrape)) => steps.push(
            exporter::ensure(admin, config, found, scrape)
                .map_err(|error| states::until(error, signing.new, new_scrape))?,
        ),
        (Some(_), None) => say(&format!("- {}", exporter::theirs(directory))),
        (None, _) => {}
    }
    let steps: Vec<String> = steps.into_iter().flatten().collect();
    for step in &steps {
        say(&format!("- {step}"));
    }
    // Stalwart uses what it holds of these from its next reload of its
    // settings on (measured on Stalwart 1.2.0: a signature key and a scrape
    // credential), and shows no read of what it uses: after a run stopped
    // between a change and the reload, only a reload makes it take what it
    // holds, so every run asks for one.
    let reload = admin.set("x:Action/set", &Set::create(Action::ReloadSettings));
    reload.map_err(|error| states::until(error, signing.new, new_scrape))?;
    // Stalwart signs with the receiver's new key from now on, so the
    // receiver starts again to read it.
    let mut stale = restart::stale(directory);
    if signing.new {
        stale.insert(webhook::KEY_FILE);
    }
    let restarted = match restart::restart(&stale) {
        Ok(said) => said,
        Err(asked) => Some(asked),
    };
    let retired = milter::retire(config)?;
    let changed = started.is_some() || keys_changed || !steps.is_empty();
    // Where it finds everything as asked, the one line on standard output.
    if !changed && stale.is_empty() && retired.is_empty() {
        say(&states::as_asked().to_string());
        return Ok(());
    }
    say(&states::reloaded(restarted.as_ref()).to_string());
    for step in &retired {
        say(&format!("- {step}"));
    }
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
        Err(state) => {
            crate::complain(&state.to_string());
            return 2;
        }
    };
    if let Err((code, state)) = writable(&config.credentials_directory, again) {
        crate::complain(&state.to_string());
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
        Err(state) => {
            crate::complain(&state.to_string());
            1
        }
    }
}

#[cfg(test)]
mod call_tests;
#[cfg(test)]
mod kept_tests;
