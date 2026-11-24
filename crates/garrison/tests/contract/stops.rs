//! Wherever `garrison stalwart setup` stops, the next run brings Stalwart and
//! the credentials directory together. The test stops it at each of its
//! requests to Stalwart in turn, in three ways (interrupted, the answer
//! lost, Stalwart unreachable from there on), in each kind of run that
//! `scene::Kind` names: a first setup, also one with the macro filter, a
//! rotation, also one where the administrator's account holds as many API
//! keys as Stalwart takes, a plain run after the key files were emptied,
//! one as a second administrator, and one after the filter's section was
//! taken out. From each stop, the next plain run and, from the same stop
//! again, the next `--rotate` must succeed and leave both places agreeing
//! (`together`).
//!
//! The running services are the broker and the receiver, each holding what
//! its file held when it last started. A run that fails names the run that
//! mends it. A run names the restart of each service whose file it wrote
//! anew, and a service whose restart it names finds a secret in its file
//! that it can start with and that Stalwart takes. A run that ends by
//! itself leaves the broker with a key Stalwart takes, or says that the
//! broker goes without one until setup makes it; stopped at the reload,
//! which alone can part them, it leaves the receiver with the key Stalwart
//! signs with, or says that the receiver refuses Stalwart's batches until
//! setup runs again. A run that was interrupted restarts nothing: there the
//! next run's look at the copies systemd keeps, which only root makes,
//! restarts each service whose file it wrote anew, which the test takes as
//! done, for those files alone and onto a secret it can use as well.
//!
//! Not held here: what root alone does (the restart itself, and how it
//! looks at the copies systemd keeps, which a user cannot read; a unit test
//! of `setup/restart.rs` holds the look); a configuration changed between a
//! stopped run and the next, such as `[milter]` taken out after a stop that
//! entered the filter; and two installations of Garrison against one
//! Stalwart.

use std::any::Any;
use std::fs;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use garrison_testing::lab::Lab;
use serde_json::json;

use super::keys::key_status;
use super::scene::{HELD, KINDS, Kind, Scene, holding};
use super::stopper::{Stop, Stopper};
use super::together::{
    Capture, assert_exporter_held, assert_keys_held_in, assert_milter_held, assert_webhook_held,
};
use super::{Setup, lab, text};

/// The units of the services that hold the secrets of `HELD`, as setup
/// names their restarts.
const UNITS: [&str; 2] = ["garrison-broker", "garrison-ingest"];

/// Whether a run restarted `unit` or said to restart it.
fn names_the_restart(said: &str, unit: &str) -> bool {
    said.lines().any(|line| {
        (line.contains("Restart ") || line.contains(" restarted")) && line.contains(unit)
    })
}

/// The service at `index` of `HELD` started again: whether its file holds a
/// secret it can start with that Stalwart takes (the broker's key opens a
/// session, Stalwart signs with the receiver's key), what is wrong where
/// not; from then on it holds what its file holds.
fn restart_onto(
    lab: &Lab,
    credentials: &Path,
    capture: &Capture,
    index: usize,
    held: &mut Option<[String; 2]>,
    context: &str,
) -> Option<String> {
    let secret = fs::read_to_string(credentials.join(HELD[index])).unwrap_or_default();
    let usable = if secret.trim().len() < 16 {
        Err("a file that holds no key")
    } else if index == 0 {
        let taken = key_status(&lab.url, &secret) == 200;
        taken.then_some(()).ok_or("a key Stalwart does not take")
    } else {
        let signs = || assert_webhook_held(lab, credentials, capture, context);
        std::panic::catch_unwind(AssertUnwindSafe(signs))
            .map_err(|_| "a signature key Stalwart does not sign with")
    };
    if let Some(held) = held {
        held[index] = secret;
    }
    let unit = UNITS[index];
    usable
        .err()
        .map(|onto| format!("{unit} was restarted onto {onto}"))
}

/// Each service whose restart a run named, started again.
fn restarted(
    lab: &Lab,
    credentials: &Path,
    capture: &Capture,
    said: &str,
    held: &mut Option<[String; 2]>,
    context: &str,
) -> Vec<String> {
    (0..UNITS.len())
        .filter(|&index| names_the_restart(said, UNITS[index]))
        .filter_map(|index| restart_onto(lab, credentials, capture, index, held, context))
        .collect()
}

/// After a run that ended by itself: the running broker holds a key
/// Stalwart takes, or the run said that it goes without one.
fn broker_unsaid(lab: &Lab, held: Option<&[String; 2]>, said: &str) -> Option<String> {
    let held = held?;
    let told = said.contains("the broker checks no user's rights until setup makes its key");
    let taken = key_status(&lab.url, &held[0]) == 200;
    (!taken && !told).then(|| {
        "the broker holds a key Stalwart no longer takes, and the run did not say so".to_owned()
    })
}

/// After a run that ended by itself at the reload, which Stalwart may have
/// made without its answer coming back: Stalwart signs with the running
/// receiver's key, or the run said that the receiver refuses Stalwart's
/// batches until setup runs again. Only a delivery shows which key Stalwart
/// signs with, and only the reload can part the two.
fn receiver_unsaid(
    lab: &Lab,
    capture: &Capture,
    setup: &Setup,
    held: Option<&[String; 2]>,
    said: &str,
    context: &str,
) -> Option<String> {
    let held = held?;
    let copy = setup.directory.join("held");
    fs::create_dir_all(&copy).unwrap();
    fs::write(copy.join(HELD[1]), &held[1]).unwrap();
    let signs = || assert_webhook_held(lab, &copy, capture, context);
    let signed = std::panic::catch_unwind(AssertUnwindSafe(signs)).is_ok();
    let told = said.contains("the receiver refuses Stalwart's batches until setup runs again");
    (!signed && !told).then(|| {
        "Stalwart signs with another key than the running receiver's, and the run did not say so"
            .to_owned()
    })
}

/// A setup run of `kind` through a relay that stops it at request `at`:
/// the request it stopped at, if it got so far, what it said, and what it
/// asked.
fn stopped(
    scene: &Scene,
    setup: &Setup,
    lab: &Lab,
    kind: Kind,
    at: usize,
    stop: Stop,
) -> (Option<String>, Output, Vec<String>) {
    let stopper = Stopper::new(&lab.url, at, stop);
    let settings = setup.directory.join("garrison.toml");
    let relayed = scene.settings(&setup.directory, &stopper.url, kind.milter());
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
    let direct = scene.settings(&setup.directory, &lab.url, kind.milter());
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
/// places agree (`together`), and each running service holds what its file
/// holds.
fn agree(
    scene: &Scene,
    setup: &Setup,
    lab: &Lab,
    capture: &Capture,
    kind: Kind,
    held: Option<&[String; 2]>,
    context: &str,
) -> Vec<String> {
    let credentials = setup.directory.join("credentials");
    let accounts = scene.accounts(kind);
    let milter = || {
        if kind.milter() {
            assert_milter_held(lab, scene.port, context);
        }
    };
    // Each check on its own, so that every fault of a stop is named.
    let checks: [&dyn Fn(); 4] = [
        &|| assert_keys_held_in(lab, &accounts, &credentials, &setup.gateway, context),
        &|| assert_webhook_held(lab, &credentials, capture, context),
        &|| assert_exporter_held(lab, &credentials, context),
        &milter,
    ];
    let mut faults = Vec::new();
    for check in checks {
        if let Err(panic) = std::panic::catch_unwind(AssertUnwindSafe(check)) {
            faults.push(said_by(&*panic));
        }
    }
    let files = holding(&credentials);
    for (index, unit) in UNITS.iter().enumerate() {
        if held.is_some_and(|held| held[index] != files[index]) {
            faults.push(format!(
                "{unit} holds a replaced secret, and no run named its restart"
            ));
        }
    }
    faults
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
    let (request, output, asked) = stopped(scene, setup, lab, kind, at, stop);
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
    if output.status.code() == Some(1) && !said.contains("Run `garrison stalwart setup") {
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
    // An interrupted run says nothing more; the next run mends what it left,
    // where it wrote a file anew through root's look at systemd's copies.
    let written: Vec<usize> = match (&held, stop) {
        (Some(held), Stop::Interrupted) => {
            let files = holding(&credentials);
            (0..HELD.len())
                .filter(|&index| held[index] != files[index])
                .collect()
        }
        (_, Stop::Interrupted) => Vec::new(),
        _ => {
            faults.extend(broker_unsaid(lab, held.as_ref(), &said));
            if request == "x:Action/set create" {
                let unsaid = receiver_unsaid(lab, capture, setup, held.as_ref(), &said, &context);
                faults.extend(unsaid);
            }
            Vec::new()
        }
    };
    let next_run = setup.run(next);
    let said_next = text(&next_run);
    let shown = format!("stopped run: {said}\nasked: {asked:?}\nnext run: {said_next}");
    if next_run.status.code() != Some(0) {
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
    let files = holding(&credentials);
    for index in written {
        if held
            .as_ref()
            .is_some_and(|held| held[index] != files[index])
        {
            faults.extend(restart_onto(
                lab,
                &credentials,
                capture,
                index,
                &mut held,
                &context,
            ));
        }
    }
    faults.extend(agree(
        scene,
        setup,
        lab,
        capture,
        kind,
        held.as_ref(),
        &context,
    ));
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

/// The first request to stop a run of `kind` at: for the macro filter's
/// kind the last read of the filter's entries, before setup changes them,
/// since those before it are the requests of runs that the other kinds stop.
fn first_stop(scene: &Scene, setup: &Setup, lab: &Lab, kind: Kind) -> usize {
    if !kind.milter() {
        return 1;
    }
    scene.start(kind, setup, lab).unwrap();
    let (_, output, asked) = stopped(scene, setup, lab, kind, usize::MAX, Stop::Lost);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let last = asked
        .iter()
        .rposition(|asked| asked.starts_with("x:MtaMilter/get"));
    last.unwrap() + 1
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
        let from = first_stop(&scene, &setup, &lab, kind);
        let before = stops;
        for stop in [Stop::Interrupted, Stop::Lost, Stop::Unreachable] {
            // Setup asks Stalwart some twenty times; far more is a fault.
            'requests: for at in from..=64 {
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
        println!("{kind:?}: {} stops from request {from}", stops - before);
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
