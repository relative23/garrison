//! The states of the checks of this host (`doctor/host.rs`).

use std::fmt::Display;
use std::path::Path;

use garrison_core::time;

use super::counted;
use crate::state::{State, states};
use crate::units;

/// `1 minute ago` for a number of seconds; less than a minute, or a time
/// ahead, is 0.
fn ago(seconds: i64) -> String {
    let minutes = usize::try_from(seconds / 60).unwrap_or(0);
    format!("{} ago", counted(minutes, "minute", "minutes"))
}

pub(in crate::doctor) fn release(current: &str, previous: Option<&str>) -> State {
    let text = match previous {
        Some(previous) => format!("release {current}, previous {previous}"),
        None => format!("release {current}, no previous release"),
    };
    State::new("doctor-release-installed", text)
}

pub(in crate::doctor) fn no_release(current: &Path) -> State {
    let text = format!("no installed release in {}", current.display());
    State::new("doctor-release-missing", text)
        .with_fix("Run the installer from the release archive.")
}

states! {
    pub(in crate::doctor) fn active(unit: &str) = "doctor-service-active":
        "{unit} is active";
    pub(in crate::doctor) fn inactive(unit: &str, state: &str) = "doctor-service-inactive":
        "{unit} is {state}"
        => "journalctl -u {unit} -n 50 shows why.";
    pub(in crate::doctor) fn synchronized() = "doctor-clock-synchronized":
        "the clock is synchronized";
    pub(in crate::doctor) fn unsynchronized() = "doctor-clock-unsynchronized":
        "the clock is not synchronized"
        => "Sign-in tokens and certificates depend on the time: enable a time service \
            (timedatectl set-ntp true).";
    pub(in crate::doctor) fn no_event() = "doctor-events-none":
        "no Stalwart event recorded yet"
        => "Stalwart sends events through the webhook that `garrison stalwart setup` creates.";
}

pub(in crate::doctor) fn unanswered_service(unit: &str) -> State {
    let text = format!("{unit}: systemctl gave no answer");
    State::new("doctor-service-unknown", text)
}

/// What says why the collector finishes no run.
fn why() -> String {
    format!(
        "`systemctl status {} {}` and `garrison check-config` say why.",
        units::COLLECT,
        units::COLLECT_TIMER
    )
}

pub(in crate::doctor) fn collection_unreadable(error: &str) -> State {
    let text = format!(
        "when the collector last finished a run: the status database cannot be read ({error})"
    );
    State::new("doctor-collection-unreadable", text)
}

pub(in crate::doctor) fn no_collection() -> State {
    let why = why();
    let text = "no collection run has finished yet";
    State::new("doctor-collection-none", text).with_fix(format!(
        "The collector runs every minute; if this stays, {why}"
    ))
}

pub(in crate::doctor) fn collection_undated(last: i64) -> State {
    let text = format!(
        "when the collector last finished a run: the newest status snapshot is dated \
         {last}, which is no time"
    );
    State::new("doctor-collection-undated", text)
}

/// The newest snapshot, written at `last`, is `seconds` old.
pub(in crate::doctor) fn collection_stopped(last: i64, seconds: i64) -> State {
    let why = why();
    let text = format!(
        "no collection run has finished since {}, {}",
        time::Timestamp::from_second(last).map_or_else(|_| last.to_string(), time::isoformat),
        ago(seconds)
    );
    State::new("doctor-collection-stopped", text).with_fix(format!(
        "Until one does, Garrison checks nothing and reports nothing: {why}"
    ))
}

/// The newest snapshot is dated `seconds` ahead of this host's clock.
pub(in crate::doctor) fn snapshot_ahead(seconds: i64) -> State {
    let text = format!(
        "the newest status snapshot is dated {} minutes ahead of this host's clock, so its \
         age is not known",
        seconds / 60
    );
    State::new("doctor-collection-ahead", text).with_fix(
        "The clock went back after it was written; `timedatectl` shows whether it is \
         synchronized.",
    )
}

pub(in crate::doctor) fn collection_recent(seconds: i64) -> State {
    let text = format!("the last collection run finished {}", ago(seconds));
    State::new("doctor-collection-recent", text)
}

pub(in crate::doctor) fn run_failed(result: &str) -> State {
    let text = format!("the last collection run ended with {result}");
    State::new("doctor-collection-run-failed", text)
        .with_fix(format!("journalctl -u {} -n 50 shows why.", units::COLLECT))
}

pub(in crate::doctor) fn run_unknown() -> State {
    let text = format!(
        "{}: systemctl gave no answer about its last run",
        units::COLLECT
    );
    State::new("doctor-collection-run-unknown", text)
}

pub(in crate::doctor) fn clock_unknown() -> State {
    let text = "clock synchronization: timedatectl gave no answer";
    State::new("doctor-clock-unknown", text)
}

pub(in crate::doctor) fn space_unknown(path: &str, error: impl Display) -> State {
    let text = format!("free space of {path}: {error}");
    State::new("doctor-space-unknown", text)
}

/// `path`, measured at `at`, the nearest folder of it that exists.
fn measured(path: &str, at: &Path) -> String {
    if at == Path::new(path) {
        path.to_owned()
    } else {
        format!(
            "{path} does not exist yet; {}, where it will be made,",
            at.display()
        )
    }
}

pub(in crate::doctor) fn room(path: &str, at: &Path, free: u64) -> State {
    let shown = measured(path, at);
    let text = format!("{shown} has {free} MiB free");
    State::new("doctor-space-enough", text)
}

pub(in crate::doctor) fn little_room(path: &str, at: &Path, free: u64) -> State {
    let shown = measured(path, at);
    let text = format!("{shown} has only {free} MiB free");
    State::new("doctor-space-low", text)
        .with_fix("Databases and backups grow; make room before the next upgrade.")
}

pub(in crate::doctor) fn events_unreadable(path: &Path, error: &str) -> State {
    let text = format!(
        "when the last Stalwart event arrived: the events database {} cannot be read \
         ({error})",
        path.display()
    );
    State::new("doctor-events-unreadable", text)
}

pub(in crate::doctor) fn event_undated(seconds: i64) -> State {
    let text = format!(
        "when the last Stalwart event arrived: the newest event is recorded at \
         {seconds}, which is no time"
    );
    State::new("doctor-events-undated", text)
}

/// The last event is recorded `seconds` ahead of this host's clock.
pub(in crate::doctor) fn event_ahead(seconds: i64) -> State {
    let text = format!(
        "the last Stalwart event is recorded {} minutes ahead of this host's clock, so \
         when it arrived is not known",
        seconds / 60
    );
    State::new("doctor-events-ahead", text).with_fix(
        "The clock went back after it arrived; `timedatectl` shows whether it is \
         synchronized.",
    )
}

pub(in crate::doctor) fn event_recent(seconds: i64) -> State {
    let text = format!("the last Stalwart event arrived {}", ago(seconds));
    State::new("doctor-events-recent", text)
}

/// No event for `seconds`.
pub(in crate::doctor) fn quiet(seconds: i64) -> State {
    let text = format!("no Stalwart event for {} hours", seconds / 3600);
    State::new("doctor-events-quiet", text).with_fix(
        "Check the webhook in the Stalwart WebUI, or run `garrison stalwart setup` again.",
    )
}

#[cfg(test)]
pub(super) fn rows() -> Vec<(State, &'static str)> {
    [runs(), times()].concat()
}

/// The release, the services and the collector's runs.
#[cfg(test)]
fn runs() -> Vec<(State, &'static str)> {
    let at = |path: &'static str| Path::new(path);
    vec![
        (
            release("0.2.0", Some("0.1.2")),
            "release 0.2.0, previous 0.1.2 [doctor-release-installed]",
        ),
        (
            no_release(at("/opt/garrison/current")),
            "no installed release in /opt/garrison/current [doctor-release-missing]\n      Run \
             the installer from the release archive.",
        ),
        (
            active("garrison-web.service"),
            "garrison-web.service is active [doctor-service-active]",
        ),
        (
            inactive("garrison-web.service", "failed"),
            "garrison-web.service is failed [doctor-service-inactive]\n      journalctl -u \
             garrison-web.service -n 50 shows why.",
        ),
        (
            unanswered_service("garrison-web.service"),
            "garrison-web.service: systemctl gave no answer [doctor-service-unknown]",
        ),
        (
            collection_unreadable("file is not a database"),
            "when the collector last finished a run: the status database cannot be read (file \
             is not a database) [doctor-collection-unreadable]",
        ),
        (
            no_collection(),
            "no collection run has finished yet [doctor-collection-none]\n      The collector \
             runs every minute; if this stays, `systemctl status garrison-collect.service \
             garrison-collect.timer` and `garrison check-config` say why.",
        ),
        (
            collection_undated(i64::MAX),
            "when the collector last finished a run: the newest status snapshot is dated \
             9223372036854775807, which is no time [doctor-collection-undated]",
        ),
        (
            collection_stopped(1_793_999_399, 601),
            "no collection run has finished since 2026-11-06T21:09:59+00:00, 10 minutes ago \
             [doctor-collection-stopped]\n      Until one does, Garrison checks nothing and \
             reports nothing: `systemctl status garrison-collect.service \
             garrison-collect.timer` and `garrison check-config` say why.",
        ),
        (
            snapshot_ahead(3600),
            "the newest status snapshot is dated 60 minutes ahead of this host's clock, so its \
             age is not known [doctor-collection-ahead]\n      The clock went back after it \
             was written; `timedatectl` shows whether it is synchronized.",
        ),
        (
            collection_recent(90),
            "the last collection run finished 1 minute ago [doctor-collection-recent]",
        ),
        (
            run_failed("exit-code"),
            "the last collection run ended with exit-code [doctor-collection-run-failed]\n      \
             journalctl -u garrison-collect.service -n 50 shows why.",
        ),
        (
            run_unknown(),
            "garrison-collect.service: systemctl gave no answer about its last run \
             [doctor-collection-run-unknown]",
        ),
    ]
}

/// The clock, free space and the events.
#[cfg(test)]
fn times() -> Vec<(State, &'static str)> {
    let at = |path: &'static str| Path::new(path);
    vec![
        (
            synchronized(),
            "the clock is synchronized [doctor-clock-synchronized]",
        ),
        (
            unsynchronized(),
            "the clock is not synchronized [doctor-clock-unsynchronized]\n      Sign-in tokens \
             and certificates depend on the time: enable a time service (timedatectl set-ntp \
             true).",
        ),
        (
            clock_unknown(),
            "clock synchronization: timedatectl gave no answer [doctor-clock-unknown]",
        ),
        (
            space_unknown(
                "/proc/self/status/garrison",
                "Not a directory (os error 20)",
            ),
            "free space of /proc/self/status/garrison: Not a directory (os error 20) \
             [doctor-space-unknown]",
        ),
        (
            room("/var/backups", at("/var"), 2048),
            "/var/backups does not exist yet; /var, where it will be made, has 2048 MiB free \
             [doctor-space-enough]",
        ),
        (
            little_room("/var/lib/garrison", at("/var/lib/garrison"), 512),
            "/var/lib/garrison has only 512 MiB free [doctor-space-low]\n      Databases and \
             backups grow; make room before the next upgrade.",
        ),
        (
            events_unreadable(
                at("/var/lib/garrison/ingest/events.sqlite"),
                "file is not a database",
            ),
            "when the last Stalwart event arrived: the events database \
             /var/lib/garrison/ingest/events.sqlite cannot be read (file is not a database) \
             [doctor-events-unreadable]",
        ),
        (
            event_undated(i64::MIN),
            "when the last Stalwart event arrived: the newest event is recorded at \
             -9223372036854775808, which is no time [doctor-events-undated]",
        ),
        (
            event_ahead(3630),
            "the last Stalwart event is recorded 60 minutes ahead of this host's clock, so when \
             it arrived is not known [doctor-events-ahead]\n      The clock went back after it \
             arrived; `timedatectl` shows whether it is synchronized.",
        ),
        (
            event_recent(615),
            "the last Stalwart event arrived 10 minutes ago [doctor-events-recent]",
        ),
        (
            quiet(30 * 3600),
            "no Stalwart event for 30 hours [doctor-events-quiet]\n      Check the webhook in \
             the Stalwart WebUI, or run `garrison stalwart setup` again.",
        ),
        (
            no_event(),
            "no Stalwart event recorded yet [doctor-events-none]\n      Stalwart sends events \
             through the webhook that `garrison stalwart setup` creates.",
        ),
    ]
}
