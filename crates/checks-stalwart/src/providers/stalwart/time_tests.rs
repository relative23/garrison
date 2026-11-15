//! The time a run has for its checks: Stalwart's API is asked once, within
//! its own time, and not at all once the run's time is up.

use std::time::{Duration, Instant};

use garrison_testing::silent::Silent;

use super::*;
use crate::context::Deadline;
use crate::testing::{Canned, config, context, table};

/// The report of the check against a Stalwart at `url`, and how long it took.
fn collected(url: &str, deadline: Deadline) -> (Report, Duration) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url = url.to_owned();
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".to_owned()),
        deadline,
        ..context(&config, &runner)
    };
    let provider = Stalwart::new(&table("type = \"stalwart\"")).unwrap();
    let began = Instant::now();
    let report = provider.collect(&context).unwrap();
    (report, began.elapsed())
}

/// The observation of the management API.
fn api(report: &Report) -> &Observation {
    report
        .observations
        .iter()
        .find(|observation| observation.id == "stalwart.api")
        .unwrap()
}

#[test]
fn a_stalwart_that_never_answers_is_given_up_after_the_requests_time() {
    let silent = Silent::new();
    let (report, took) = collected(&silent.url, Deadline::NONE);
    assert_eq!(silent.finish(), 1);
    assert!(took < Duration::from_secs(12), "{took:?}");
    assert_eq!(api(&report).state, State::Unknown);
    assert_eq!(
        api(&report).findings,
        ["Not readable: Stalwart unavailable."]
    );
}

#[test]
fn stalwart_is_not_asked_once_the_runs_time_is_over() {
    let silent = Silent::new();
    let (report, _) = collected(&silent.url, Deadline::within(Duration::ZERO));
    assert_eq!(silent.finish(), 0);
    assert_eq!(api(&report).state, State::Unknown);
    assert_eq!(
        api(&report).findings,
        ["Not asked: the collection run's time was used up."]
    );
}
