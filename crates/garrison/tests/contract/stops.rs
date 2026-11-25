//! Wherever `garrison stalwart setup` stops, each service holds a secret
//! that Stalwart takes, and the next run brings Stalwart and the
//! credentials directory together. The test stops setup at each of its
//! requests to Stalwart in turn, in three ways (interrupted, the answer
//! lost, Stalwart unreachable from there on), in each kind of run that
//! `scene::Kind` names: a first setup, a
//! rotation, also one after which Stalwart reloads its settings on its own
//! and one where the administrator's account holds as many API keys as
//! Stalwart takes, a plain run after the key files were emptied, and runs
//! as a second administrator, also one whose own account is full.
//!
//! The running services are the broker and the receiver (`held`). Right
//! after each stop, with the restarts the stopped run named made at the
//! point where it named them, the running broker must hold a key Stalwart
//! takes and the running receiver the key Stalwart signs with, but at the
//! reload, after which only a restart can give the receiver Stalwart's new
//! key. Where Stalwart reloads its settings on its own after the stop, it
//! signs with a key that a file or the running receiver holds. A run that
//! fails names the run that mends it. From each stop, the next plain run
//! and, from the same stop again, the next `--rotate` must succeed, but a
//! rotation in an account without room for another key, which must change
//! nothing and say which keys to remove; then both places agree
//! (`together`), with each service started again where root's look at the
//! copies systemd keeps finds it holding another secret than its file.
//!
//! Not held here: what root alone does (the restart itself, and how it
//! looks at the copies systemd keeps, which a user cannot read; a unit test
//! of `setup/restart.rs` holds the look); a configuration changed between a
//! stopped run and the next; and two installations of Garrison against one
//! Stalwart.

use std::any::Any;
use std::fs;
use std::panic::AssertUnwindSafe;
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use garrison_testing::lab::Lab;
use serde_json::json;

use super::held::{Stopped, apart, looked, reloaded, restarted};
use super::scene::{KINDS, Kind, Scene};
use super::stopper::{Stop, Stopper};
use super::together::{Capture, assert_exporter_held, assert_keys_held_in, assert_webhook_held};
use super::{Setup, lab, names_its_mend, support, text};

/// A setup run of `kind` through a relay that stops it at request `at`:
/// the request it stopped at, if it got so far, what it said, and what it
/// asked.
fn stopped(
    setup: &Setup,
    lab: &Lab,
    kind: Kind,
    at: usize,
    stop: Stop,
) -> (Option<String>, Output, Vec<String>) {
    let stopper = Stopper::new(&lab.url, at, stop);
    let settings = setup.directory.join("garrison.toml");
    let relayed = Scene::settings(&setup.directory, &stopper.url);
    fs::write(&settings, relayed).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_garrison"))
        .arg("--config")
        .arg(&settings)
        .args(setup.arguments(kind.arguments()))
        .env_remove("CREDENTIALS_DIRECTORY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    stopper.watch(child.id());
    let output = child.wait_with_output().unwrap();
    let direct = Scene::settings(&setup.directory, &lab.url);
    fs::write(&settings, direct).unwrap();
    (stopper.stopped(), output, stopper.asked())
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

/// What is wrong after the run that was to mend a stop of `kind`: both
/// places agree (`together`).
fn agree(
    scene: &Scene,
    setup: &Setup,
    lab: &Lab,
    capture: &Capture,
    kind: Kind,
    context: &str,
) -> Vec<String> {
    let credentials = setup.directory.join("credentials");
    let accounts = scene.accounts(kind);
    // Each check on its own, so that every fault of a stop is named.
    let checks: [&dyn Fn(); 3] = [
        &|| assert_keys_held_in(lab, &accounts, &credentials, &setup.gateway, context),
        &|| assert_webhook_held(lab, &credentials, capture, context),
        &|| assert_exporter_held(lab, &credentials, context),
    ];
    checks
        .into_iter()
        .filter_map(|check| std::panic::catch_unwind(AssertUnwindSafe(check)).err())
        .map(|panic| said_by(&*panic))
        .collect()
}

/// One stop and the run after it.
fn mended(
    scene: &Scene,
    setup: &Setup,
    lab: &Lab,
    capture: &Capture,
    scenario: (Kind, Stop, usize),
    next: &[&str],
) -> Outcome {
    let (kind, stop, at) = scenario;
    let credentials = setup.directory.join("credentials");
    let mut held = match scene.start(kind, setup, lab) {
        Ok(held) => held,
        Err(why) => return Outcome::Unready(format!("{kind:?} at request {at}: {why}")),
    };
    let (request, output, asked) = stopped(setup, lab, kind, at, stop);
    let Some(request) = request else {
        return Outcome::Past;
    };
    let then = if next.is_empty() {
        "a plain run"
    } else {
        "--rotate"
    };
    let context = format!("{kind:?} stopped {stop:?} at request {at} ({request}), then {then}");
    let said = text(&output);
    let mut faults = Vec::new();
    // A run that fails names the run that mends it; one may go on past a
    // lost answer.
    if output.status.code() == Some(1) && !names_its_mend(&said) {
        faults.push("the failed run names no run that mends it".to_owned());
    }
    faults.extend(restarted(
        lab,
        &credentials,
        capture,
        &said,
        &mut held,
        &context,
    ));
    let run = Stopped {
        request: &request,
        stop,
        asked: &asked,
        said: &said,
    };
    faults.extend(apart(lab, capture, held.as_ref(), &run));
    if kind == Kind::Reloaded {
        faults.extend(reloaded(lab, capture, &credentials, held.as_ref(), &said));
    }
    let next_run = setup.run(next);
    let said_next = text(&next_run);
    let shown = format!("stopped run: {said}\nasked: {asked:?}\nnext run: {said_next}");
    // A rotation in an account without room for another key changes
    // nothing and says which keys to remove.
    let refused = kind.full() && !next.is_empty();
    let code = next_run.status.code();
    let full = support::states(&next_run.stderr).contains(&"setup-account-full".to_owned());
    if refused && (code != Some(1) || !full) {
        faults.push("the next --rotate was not refused for the account's full quota".to_owned());
    } else if !refused && code != Some(0) {
        faults.push("the next run failed".to_owned());
        return Outcome::Done(Err(format!("{context}: {}\n{shown}", faults.join("; "))));
    }
    faults.extend(restarted(
        lab,
        &credentials,
        capture,
        &said_next,
        &mut held,
        &context,
    ));
    if code == Some(0) {
        faults.extend(looked(lab, &credentials, capture, &mut held, &context));
    }
    faults.extend(agree(scene, setup, lab, capture, kind, &context));
    if !faults.is_empty() {
        return Outcome::Done(Err(format!("{context}: {}\n{shown}", faults.join("; "))));
    }
    Outcome::Done(Ok(()))
}

/// Once the full account of `kind` has room for one more key, a rotation
/// goes through.
fn with_room(
    scene: &mut Scene,
    setup: &Setup,
    lab: &mut Lab,
    capture: &Capture,
    kind: Kind,
) -> Option<String> {
    if let Err(why) = scene.start(kind, setup, lab) {
        return Some(format!("{kind:?} with room: {why}"));
    }
    scene.make_room(lab, kind);
    let rotated = setup.run(&["--rotate"]);
    let context = format!("{kind:?} with room for one more key, then --rotate");
    if rotated.status.code() != Some(0) {
        return Some(format!("{context}: {}", text(&rotated)));
    }
    let faults = agree(scene, setup, lab, capture, kind, &context);
    (!faults.is_empty()).then(|| format!("{context}: {}", faults.join("; ")))
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
    let (_guard, mut lab) = lab();
    raise_limits(&lab);
    let now = lab.call("x:Http/get", &json!({"ids": ["singleton"]}))["list"][0].clone();
    println!(
        "the lab's limits while the stops run: {} authenticated, {} anonymous",
        now["rateLimitAuthenticated"], now["rateLimitAnonymous"]
    );
    let capture = Capture::start();
    let setup = Setup::new(&lab, &capture.url);
    let credentials = setup.directory.join("credentials");
    let mut scene = Scene::new(&mut lab);
    let began = Instant::now();
    let (mut stops, mut failures) = (0, Vec::new());
    for kind in KINDS {
        scene.enter(kind, &setup, &mut lab);
        let before = stops;
        for stop in [Stop::Interrupted, Stop::Lost, Stop::Unreachable] {
            // Setup asks Stalwart some twenty times; far more is a fault.
            'requests: for at in 1..=64 {
                for next in [&[][..], &["--rotate"][..]] {
                    let scenario = (kind, stop, at);
                    let tried = std::panic::catch_unwind(AssertUnwindSafe(|| {
                        mended(&scene, &setup, &lab, &capture, scenario, next)
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
                            scene.forget(&lab, &credentials);
                            break 'requests;
                        }
                    };
                    stops += 1;
                    if let Some(failure) = failure {
                        failures.push(failure);
                        // The next stop starts from nothing again.
                        scene.forget(&lab, &credentials);
                    }
                    assert!(at < 64, "setup asked Stalwart more than 63 times");
                }
            }
        }
        println!("{kind:?}: {} stops", stops - before);
        if kind.full() {
            failures.extend(with_room(&mut scene, &setup, &mut lab, &capture, kind));
        }
        scene.leave(&mut lab);
    }
    scene.forget(&lab, &credentials);
    println!(
        "{stops} stops in {} s, {} not mended",
        began.elapsed().as_secs(),
        failures.len()
    );
    // Some 500 stops: fewer would mean the relay stopped too little.
    assert!(stops >= 400, "only {stops} stops");
    assert!(
        failures.is_empty(),
        "{} of {stops} stops not mended:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
