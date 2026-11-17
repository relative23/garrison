//! Wherever `garrison stalwart setup` stops, the next run brings Stalwart and
//! the credentials directory together. The test stops it at each of its
//! requests to Stalwart in turn, in three ways (interrupted, the answer
//! lost, Stalwart unreachable from there on), in a first setup, a rotation,
//! and a plain run that makes the broker's and the receiver's keys anew
//! because their files hold none while the services still run with the old
//! ones. From each stop, the next plain run and, from the same stop again,
//! the next `--rotate` must succeed and leave both places agreeing
//! (`together`). A running service must never be left holding another
//! secret than its file without a run having named its restart, and a run
//! that fails must name the run that mends it.

use std::any::Any;
use std::fs;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use garrison_testing::config_text;
use garrison_testing::lab::Lab;
use serde_json::json;

use super::stopper::{Stop, Stopper};
use super::together::{Capture, assert_exporter_held, assert_keys_held, assert_webhook_held};
use super::{Setup, forget, lab, text};

/// What a stopped run is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// The first setup: nothing in Stalwart or the folder, no service runs.
    First,
    /// `--rotate` while the services run with the secrets of the files.
    Rotation,
    /// A plain run after the broker's key file and the signature key's file
    /// were emptied while the services run with systemd's copies of the
    /// keys they held.
    Emptied,
}

/// The files of the secrets the running services hold.
const HELD: [&str; 2] = ["broker-native-key", "webhook-signature-key"];

/// Whether a run restarted the services or said to restart them.
fn names_the_restart(output: &str) -> bool {
    output.contains("Restart garrison-ingest and garrison-broker")
        || output.contains("garrison-ingest and garrison-broker restarted")
}

/// The secrets of the held files as the folder holds them now.
fn holding(credentials: &Path) -> Vec<String> {
    HELD.iter()
        .map(|name| fs::read_to_string(credentials.join(name)).unwrap_or_default())
        .collect()
}

/// A setup run through a relay that stops it at request `at`: the request
/// it stopped at, if it got so far, what it said, and what it asked.
fn stopped(
    setup: &Setup,
    lab: &Lab,
    at: usize,
    stop: Stop,
    more: &[&str],
) -> (Option<String>, Output, Vec<String>) {
    let stopper = Stopper::new(&lab.url, at, stop);
    let settings = setup.directory.join("garrison.toml");
    fs::write(&settings, config_text(&setup.directory, &stopper.url)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_garrison"))
        .arg("--config")
        .arg(&settings)
        .args(setup.arguments(more))
        .env_remove("CREDENTIALS_DIRECTORY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    stopper.watch(child.id());
    let output = child.wait_with_output().unwrap();
    fs::write(&settings, config_text(&setup.directory, &lab.url)).unwrap();
    (stopper.stopped(), output, stopper.asked())
}

/// Bring the lab and the folder to where a stopped run of `kind` starts,
/// and say what the running services hold, where any run.
fn start(kind: Kind, setup: &Setup, lab: &Lab) -> Result<Option<Vec<String>>, String> {
    let credentials = setup.directory.join("credentials");
    if kind == Kind::First {
        forget(lab, &credentials);
        return Ok(None);
    }
    // The others start where both places agree.
    let ready = setup.run(&[]);
    if ready.status.code() != Some(0) {
        return Err(format!("the run before the stop failed: {}", text(&ready)));
    }
    let held = holding(&credentials);
    if kind == Kind::Emptied {
        for name in HELD {
            fs::write(credentials.join(name), "").unwrap();
        }
    }
    Ok(Some(held))
}

/// How a stop and the run after it went.
enum Outcome {
    /// Mended, or what was not.
    Done(Result<(), String>),
    /// The run ended before the request it was to be stopped at.
    Past,
    /// The state the stop starts from could not be made.
    Unready(String),
}

/// One stop and the run after it.
fn mended(
    setup: &Setup,
    lab: &Lab,
    capture: &Capture,
    scenario: (Kind, Stop, usize),
    next: &[&str],
) -> Outcome {
    let (kind, stop, at) = scenario;
    let credentials = setup.directory.join("credentials");
    let mut held = match start(kind, setup, lab) {
        Ok(held) => held,
        Err(why) => return Outcome::Unready(format!("{kind:?} at request {at}: {why}")),
    };
    let rotate: &[&str] = if kind == Kind::Rotation {
        &["--rotate"]
    } else {
        &[]
    };
    let (request, output, asked) = stopped(setup, lab, at, stop, rotate);
    let Some(request) = request else {
        return Outcome::Past;
    };
    let context = format!(
        "{kind:?} stopped {stop:?} at request {at} ({request}), then {}",
        if next.is_empty() {
            "a plain run"
        } else {
            "--rotate"
        }
    );
    let said = text(&output);
    let mut faults = Vec::new();
    // A run that fails names the run that mends it; one may go on past a
    // lost answer, as where it asks whose a file's key is.
    let failed = output.status.code() == Some(1);
    if failed && !said.contains("Run `garrison stalwart setup") {
        faults.push("the failed run names no run that mends it".to_owned());
    }
    if held.is_some() && names_the_restart(&said) {
        held = Some(holding(&credentials));
    }
    let next_run = setup.run(next);
    let said_next = text(&next_run);
    let shown = format!("stopped run: {said}\nasked: {asked:?}\nnext run: {said_next}");
    if next_run.status.code() != Some(0) {
        faults.push("the next run failed".to_owned());
        return Outcome::Done(Err(format!("{context}: {}\n{shown}", faults.join("; "))));
    }
    if held.is_some() && names_the_restart(&said_next) {
        held = Some(holding(&credentials));
    }
    // Each check on its own, so that every fault of a stop is named.
    let checks: [&dyn Fn(); 3] = [
        &|| assert_keys_held(lab, &credentials, &setup.gateway, &context),
        &|| assert_webhook_held(lab, &credentials, capture, &context),
        &|| assert_exporter_held(lab, &credentials, &context),
    ];
    for check in checks {
        if let Err(panic) = std::panic::catch_unwind(AssertUnwindSafe(check)) {
            faults.push(said_by(&*panic));
        }
    }
    if held.is_some_and(|held| held != holding(&credentials)) {
        faults.push(
            "a running service holds a replaced secret, and no run named its restart".to_owned(),
        );
    }
    if !faults.is_empty() {
        return Outcome::Done(Err(format!("{context}: {}\n{shown}", faults.join("; "))));
    }
    Outcome::Done(Ok(()))
}

/// What a panic said.
fn said_by(panic: &(dyn Any + Send)) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_default()
}

/// The lab's limits of requests and of failed sign-ins, raised: Stalwart
/// sees every request of this host at the lab's gateway, thousands a minute,
/// and counts each narrowed key's try as a failed sign-in. They stay raised
/// for the lab's run, since Stalwart's own limits, put back, would count
/// this test's requests against the tests after it.
fn raise_limits(lab: &Lab) {
    let many = json!({"count": 1_000_000, "period": 60_000});
    lab.call(
        "x:Http/set",
        &json!({"update": {"singleton": {
            "rateLimitAuthenticated": many, "rateLimitAnonymous": many}}}),
    );
    let failures = json!({"count": 1_000_000, "period": 86_400_000});
    lab.call(
        "x:Security/set",
        &json!({"update": {"singleton": {"authBanRate": failures}}}),
    );
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn every_stop_of_setup_is_mended_by_the_next_run() {
    let (_guard, lab) = lab();
    raise_limits(&lab);
    let now = lab.call("x:Http/get", &json!({"ids": ["singleton"]}))["list"][0].clone();
    println!(
        "the lab's limits while the stops run: {} authenticated, {} anonymous",
        now["rateLimitAuthenticated"], now["rateLimitAnonymous"]
    );
    let capture = Capture::start();
    let setup = Setup::new(&lab, &capture.url);
    let credentials = setup.directory.join("credentials");
    let began = Instant::now();
    let (mut stops, mut failures) = (0, Vec::new());
    for kind in [Kind::First, Kind::Rotation, Kind::Emptied] {
        for stop in [Stop::Interrupted, Stop::Lost, Stop::Unreachable] {
            // Setup asks Stalwart some fifteen times; far more is a fault.
            'requests: for at in 1..=64 {
                for next in [&[][..], &["--rotate"][..]] {
                    let scenario = (kind, stop, at);
                    let tried = std::panic::catch_unwind(AssertUnwindSafe(|| {
                        mended(&setup, &lab, &capture, scenario, next)
                    }));
                    let outcome = tried.unwrap_or_else(|panic| {
                        Outcome::Done(Err(format!("{scenario:?}: {}", said_by(&*panic))))
                    });
                    let failure = match outcome {
                        Outcome::Past => break 'requests,
                        Outcome::Done(Ok(())) => None,
                        Outcome::Done(Err(failure)) => Some(failure),
                        Outcome::Unready(failure) => {
                            failures.push(failure);
                            forget(&lab, &credentials);
                            break 'requests;
                        }
                    };
                    stops += 1;
                    if let Some(failure) = failure {
                        failures.push(failure);
                        // The next stop starts from nothing again.
                        forget(&lab, &credentials);
                    }
                    assert!(at < 64, "setup asked Stalwart more than 63 times");
                }
            }
        }
    }
    forget(&lab, &credentials);
    println!(
        "{stops} stops in {} s, {} not mended",
        began.elapsed().as_secs(),
        failures.len()
    );
    // Some 250 stops: fewer would mean the relay stopped too little.
    assert!(stops >= 200, "only {stops} stops");
    assert!(
        failures.is_empty(),
        "{} of {stops} stops not mended:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
