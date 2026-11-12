use garrison_testing::http::{answer, serve};
use serde_json::json;

use super::*;
use crate::context::Context;
use crate::testing::{Canned, Remembered, config, now, table};

/// The release of Garrison that runs in these tests.
const RUNS: &str = "0.5.0";

/// A release as GitHub serves it, from its beginning.
fn entry(tag: &str) -> serde_json::Value {
    json!({
        "url": "https://api.github.com/repos/relative23/garrison/releases/1",
        "html_url": "https://github.com/relative23/garrison/releases/tag/x",
        "id": 1, "author": {"login": "relative23"},
        "tag_name": tag, "name": "A release", "draft": false, "prerelease": false,
        "body": "Notes that mention \"tag_name\": \"v9.9.9\" further down.",
    })
}

/// GitHub's answer for the latest release.
fn release(tag: &str) -> String {
    entry(tag).to_string()
}

/// GitHub's answer for the list of releases.
fn list(tags: &[&str]) -> String {
    serde_json::Value::Array(tags.iter().map(|tag| entry(tag)).collect()).to_string()
}

/// The check on a host where the release `RUNS` of Garrison runs.
fn provider(api: &str) -> Releases {
    running(api, RUNS)
}

/// The check on a host where `version` of Garrison runs.
fn running(api: &str, version: &str) -> Releases {
    Releases {
        garrison: version.to_owned(),
        ..Releases::new(&table(&format!(
            "type = \"releases\"\nproducts = [\"garrison\"]\napi = \"{api}\""
        )))
        .unwrap()
    }
}

/// One collection at `at` seconds after the tests' clock.
fn collected(provider: &Releases, memory: &Remembered, at: i64) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = Context {
        now: time::Timestamp::from_second(now().as_second() + at).unwrap(),
        memory,
        ..crate::testing::context(&config, &runner)
    };
    provider.collect(&context).unwrap().observations.remove(0)
}

fn field<'a>(observation: &'a Observation, label: &str) -> &'a serde_json::Value {
    &observation
        .fields
        .iter()
        .find(|field| field.label == label)
        .unwrap()
        .value
}

#[test]
fn a_newer_release_is_a_warning_and_is_asked_for_once_a_day() {
    let server = serve(vec![
        answer(200, &release("v99.0.0")),
        answer(200, &release("v99.0.1")),
    ]);
    let provider = provider(&server.url);
    let memory = Remembered::default();
    let first = collected(&provider, &memory, 0);
    assert_eq!(first.state, State::Warning);
    assert_eq!(
        first.findings,
        [format!("Garrison 99.0.0 is available; {RUNS} runs here.")]
    );
    assert_eq!(field(&first, "Newest release"), &json!("99.0.0"));
    assert_eq!(field(&first, "Runs here"), &json!(RUNS));
    assert_eq!(first.id, "release.garrison");
    // The source names the host and the repository, not the whole address.
    assert_eq!(
        first.source,
        format!(
            "{}: releases of relative23/garrison",
            server.url.trim_start_matches("http://")
        )
    );
    // A minute and nearly a day later the answer is the kept one.
    for later in [60, DAY - 1] {
        let again = collected(&provider, &memory, later);
        assert_eq!(field(&again, "Newest release"), &json!("99.0.0"));
        assert_eq!(field(&again, "Asked"), field(&first, "Asked"));
    }
    // After a day GitHub is asked again.
    let next = collected(&provider, &memory, DAY);
    assert_eq!(field(&next, "Newest release"), &json!("99.0.1"));
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0].starts_with("GET /repos/relative23/garrison/releases/latest HTTP/1.1\r\n"),
        "{}",
        requests[0]
    );
    assert!(requests[0].contains("Accept: application/vnd.github+json\r\n"));
}

#[test]
fn the_running_release_or_a_newer_one_is_in_order() {
    for tag in [RUNS, "0.0.1", "v0.0.9", "v0.5.0-rc.1"] {
        let server = serve(vec![answer(200, &release(tag))]);
        let observation = collected(&provider(&server.url), &Remembered::default(), 0);
        assert_eq!(observation.state, State::Ok, "{tag}");
        assert_eq!(observation.findings, Vec::<String>::new());
        server.requests();
    }
}

#[test]
fn no_answer_is_unknown_and_is_asked_for_again_within_the_hour() {
    for (response, problem) in [
        (answer(404, "{}"), "GitHub lists no release"),
        (answer(403, "rate limit"), "GitHub answered 403"),
        (answer(200, "<html>"), "GitHub's answer names no release"),
        (
            answer(200, &release("latest")),
            "GitHub names latest, which is no version",
        ),
    ] {
        let server = serve(vec![response, answer(200, &release("0.0.1"))]);
        let provider = provider(&server.url);
        let memory = Remembered::default();
        let failed = collected(&provider, &memory, 0);
        assert_eq!(failed.state, State::Unknown, "{problem}");
        assert_eq!(
            failed.findings,
            [format!("The newest release is not known: {problem}.")]
        );
        // Not again within the hour, then again.
        assert_eq!(
            collected(&provider, &memory, RETRY - 1).state,
            State::Unknown
        );
        assert_eq!(collected(&provider, &memory, RETRY).state, State::Ok);
        assert_eq!(server.requests().len(), 2);
    }
    // Nothing listens there: unknown as well, with the reason.
    let unreachable = collected(&provider("http://127.0.0.1:9"), &Remembered::default(), 0);
    assert_eq!(unreachable.state, State::Unknown);
}

#[test]
fn a_release_known_before_stays_known_when_github_does_not_answer() {
    let server = serve(vec![
        answer(200, &release("99.0.0")),
        answer(502, "bad gateway"),
    ]);
    let provider = provider(&server.url);
    let memory = Remembered::default();
    collected(&provider, &memory, 0);
    let later = collected(&provider, &memory, DAY);
    assert_eq!(later.state, State::Warning);
    assert_eq!(field(&later, "Newest release"), &json!("99.0.0"));
    server.requests();
}

#[test]
fn where_a_pre_release_runs_the_newest_of_the_listed_releases_counts() {
    // The order GitHub lists them in is not the order of the versions.
    let server = serve(vec![
        answer(
            200,
            &list(&["v0.5.0-dev", "nightly", "v0.5.0-rc.1", "v0.4.9"]),
        ),
        answer(200, &list(&["v0.5.0-rc.1", "v0.5.0", "v0.5.0-dev"])),
    ]);
    let provider = running(&server.url, "0.5.0-dev");
    let memory = Remembered::default();
    let first = collected(&provider, &memory, 0);
    assert_eq!(first.state, State::Warning);
    assert_eq!(
        first.findings,
        ["Garrison 0.5.0-rc.1 is available; 0.5.0-dev runs here."]
    );
    // A day later the release itself is out, which is newer than both.
    let next = collected(&provider, &memory, DAY);
    assert_eq!(field(&next, "Newest release"), &json!("0.5.0"));
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0].starts_with("GET /repos/relative23/garrison/releases?per_page=10 HTTP/1.1\r\n"),
        "{}",
        requests[0]
    );

    // The pre-release that runs is the newest one: in order.
    let server = serve(vec![answer(200, &list(&["v0.5.0-dev", "v0.4.9"]))]);
    let same = collected(
        &running(&server.url, "0.5.0-dev"),
        &Remembered::default(),
        0,
    );
    assert_eq!(same.state, State::Ok);
    server.requests();

    for (body, problem) in [
        (list(&[]), "GitHub lists no release"),
        (
            list(&["nightly"]),
            "GitHub names nightly, which is no version",
        ),
    ] {
        let server = serve(vec![answer(200, &body)]);
        let none = collected(
            &running(&server.url, "0.5.0-dev"),
            &Remembered::default(),
            0,
        );
        assert_eq!(
            none.findings,
            [format!("The newest release is not known: {problem}.")]
        );
        server.requests();
    }
}

#[test]
fn an_answer_kept_from_the_other_way_of_asking_is_not_used() {
    let server = serve(vec![
        answer(200, &list(&["v0.5.0-rc.2"])),
        answer(200, &release("v0.5.0")),
    ]);
    let memory = Remembered::default();
    // The pre-release learns of the next one; a minute later the release is
    // installed, and it must not be told of a pre-release.
    let before = collected(&running(&server.url, "0.5.0-rc.1"), &memory, 0);
    assert_eq!(before.state, State::Warning);
    let after = collected(&running(&server.url, "0.5.0"), &memory, 60);
    assert_eq!(after.state, State::Ok);
    assert_eq!(field(&after, "Newest release"), &json!("0.5.0"));
    let requests = server.requests();
    assert!(requests[1].starts_with("GET /repos/relative23/garrison/releases/latest "));
}

#[test]
fn stalwart_without_a_recorded_start_is_unknown() {
    let server = serve(vec![answer(200, &release("v1.1.0"))]);
    let provider = Releases::new(&table(&format!(
        "type = \"releases\"\nproducts = [\"stalwart\"]\napi = \"{}\"",
        server.url
    )))
    .unwrap();
    let observation = collected(&provider, &Remembered::default(), 0);
    assert_eq!(observation.state, State::Unknown);
    assert_eq!(
        observation.findings,
        ["The version of Stalwart that runs here is not known."]
    );
    assert_eq!(observation.title, "Stalwart release");
    assert!(server.requests()[0].starts_with("GET /repos/stalwartlabs/stalwart/releases/latest "));
}

#[test]
fn options_are_checked() {
    assert_eq!(
        Releases::new(&table("type = \"releases\""))
            .unwrap()
            .products,
        [Product::Garrison, Product::Stalwart]
    );
    for wrong in [
        "products = []",
        "products = [\"postfix\"]",
        "products = [\"garrison\", \"garrison\"]",
        "products = \"garrison\"",
        "api = \"http://example.org\"",
        "api = 7",
        "every = 3",
    ] {
        assert!(
            Releases::new(&table(&format!("type = \"releases\"\n{wrong}"))).is_err(),
            "{wrong}"
        );
    }
}
