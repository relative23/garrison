//! Stalwart's own rate limit: where it answers the collector's request 429,
//! the Management API card names the limit, which passes once Stalwart's
//! minute is over, and not an outage.

use garrison_testing::http::{answer, serve};

use super::*;
use crate::testing::{Canned, config, context, table};

/// The Management API card of a run against a Stalwart that answers the
/// check's one request with `response`.
fn api(response: String) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(vec![response]);
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&server.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".to_owned()),
        ..context(&config, &runner)
    };
    let provider = Stalwart::new(&table("type = \"stalwart\"")).unwrap();
    let report = provider.collect(&context).unwrap();
    server.requests();
    report
        .observations
        .into_iter()
        .find(|observation| observation.id == "stalwart.api")
        .unwrap()
}

#[test]
fn stalwarts_rate_limit_is_named_on_the_management_api_card() {
    let limited = api(answer(429, ""));
    assert_eq!(limited.state, State::Unknown);
    assert_eq!(
        limited.findings,
        ["Not readable: Stalwart refused the collector's key for its rate limit (HTTP 429)."]
    );
    // An outage is still called one.
    let away = api(answer(503, ""));
    assert_eq!(away.findings, ["Not readable: Stalwart unavailable."]);
}
