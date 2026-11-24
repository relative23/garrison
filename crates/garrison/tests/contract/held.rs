//! What the running services hold while setup runs and after it stops: the
//! broker and the receiver, each with what its file held when it last
//! started. A service starts again where a run names its restart, and where
//! root's look at the copies systemd keeps finds that it holds another
//! secret than its file, which a successful run makes at its end.

use std::fs;
use std::panic::AssertUnwindSafe;
use std::path::Path;

use garrison_testing::lab::Lab;
use serde_json::json;

use super::keys::key_status;
use super::scene::{HELD, holding};
use super::stopper::Stop;
use super::together::{Capture, assert_webhook_held, exporter_takes, signed_with};

/// The units of the services that hold the secrets of `HELD`, as setup
/// names their restarts.
const UNITS: [&str; 2] = ["garrison-broker", "garrison-ingest"];
/// The request with which Stalwart reloads its settings, and takes a new
/// signature key and scrape credential.
pub(super) const RELOAD: &str = "x:Action/set create";
/// What a run that stops says where the receiver may refuse Stalwart's
/// batches, or the exporter the collector's scrape, until setup runs again.
const RECEIVER_TOLD: &str = "Stalwart's batches until setup runs again";
const EXPORTER_TOLD: &str = "the collector's scrape until setup runs again";

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
pub(super) fn restart_onto(
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
pub(super) fn restarted(
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

/// Root's look at the copies systemd keeps, at the end of a run that
/// succeeded: each service that holds another secret than its file starts
/// again with its file's.
pub(super) fn looked(
    lab: &Lab,
    credentials: &Path,
    capture: &Capture,
    held: &mut Option<[String; 2]>,
    context: &str,
) -> Vec<String> {
    let files = holding(credentials);
    let other: Vec<usize> = (0..HELD.len())
        .filter(|&index| {
            held.as_ref()
                .is_some_and(|held| held[index] != files[index])
        })
        .collect();
    other
        .into_iter()
        .filter_map(|index| restart_onto(lab, credentials, capture, index, held, context))
        .collect()
}

/// How a run was stopped and what it did: the request it was stopped at,
/// how, every request it sent, and what it said.
pub(super) struct Stopped<'a> {
    pub(super) request: &'a str,
    pub(super) stop: Stop,
    pub(super) asked: &'a [String],
    pub(super) said: &'a str,
}

/// Right after a stop, with the restarts the stopped run named made: the
/// running broker holds a key Stalwart takes, and the running receiver the
/// key Stalwart signs with. The one exception is a stop at the reload, where
/// Stalwart takes a new signature key while the receiver can start again
/// with it only after; a run that ends by itself says so there.
pub(super) fn apart(
    lab: &Lab,
    capture: &Capture,
    held: Option<&[String; 2]>,
    run: &Stopped<'_>,
) -> Vec<String> {
    let Some(held) = held else {
        return Vec::new();
    };
    let mut faults = Vec::new();
    if key_status(&lab.url, &held[0]) != 200 {
        faults.push("the running broker holds a key Stalwart no longer takes".to_owned());
    }
    // The key Stalwart signs with can change once it was given one, which
    // Stalwart 1.1.0 takes only at a reload, and the receiver's only when it
    // starts again.
    let given = |asked: &String| asked == RELOAD || asked.starts_with("x:WebHook/set");
    let changed = run.asked.iter().any(given) || names_the_restart(run.said, UNITS[1]);
    let window = run.request == RELOAD
        && (run.stop == Stop::Interrupted || run.said.contains(RECEIVER_TOLD));
    if changed && !window && signed_with(capture, &[&held[1]]) != Some(0) {
        faults.push("Stalwart signs with another key than the running receiver's".to_owned());
    }
    faults
}

/// After Stalwart reloaded its settings on its own, as after its restart,
/// before the next run: it signs with a key that the receiver's file or the
/// running receiver holds, and its exporter takes the file's credential or
/// the run said that it may not.
pub(super) fn reloaded(
    lab: &Lab,
    capture: &Capture,
    credentials: &Path,
    held: Option<&[String; 2]>,
    said: &str,
) -> Vec<String> {
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
    let file = fs::read_to_string(credentials.join(HELD[1])).unwrap_or_default();
    let mut keys = vec![file.as_str()];
    keys.extend(held.map(|held| held[1].as_str()));
    let mut faults = Vec::new();
    if signed_with(capture, &keys).is_none() {
        faults.push(
            "once Stalwart reloaded its settings, it signs with a key that no file holds"
                .to_owned(),
        );
    }
    if !exporter_takes(lab, credentials) && !said.contains(EXPORTER_TOLD) {
        faults.push(
            "once Stalwart reloaded its settings, its exporter refuses the file's credential, \
             and the run did not say so"
                .to_owned(),
        );
    }
    faults
}
