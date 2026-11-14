//! The domains after the first `max_domains` are not checked, and the
//! check says so.

use garrison_testing::http::{json as answer_json, serve};
use serde_json::json;

use super::*;
use crate::testing::{Canned, config, table};

#[test]
fn domains_beyond_max_domains_are_named_not_left_out() {
    let domains: Vec<serde_json::Value> = (0..3)
        .map(
            |number| json!({"id": format!("b{number}"), "name": format!("d{number}.example.test")}),
        )
        .collect();
    let stalwart = serve(vec![answer_json(&json!({
        "methodResponses": [["x:Domain/get", {"list": domains}, "0"]]
    }))]);
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&stalwart.url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        ..crate::testing::context(&config, &runner)
    };
    // Stalwart names no records for these domains: nothing is asked.
    let provider = Dns::new(&table(
        "type = \"dns\"\nresolver = \"127.0.0.1:9\"\nmax_domains = 2",
    ))
    .unwrap();
    let observations = provider.collect(&context).unwrap().observations;
    stalwart.requests();
    let ids: Vec<&str> = observations
        .iter()
        .map(|observation| observation.id.as_str())
        .collect();
    assert_eq!(
        ids,
        ["dns.d0.example.test", "dns.d1.example.test", "dns.records"]
    );
    assert_eq!(observations[2].state, State::Unknown);
    assert_eq!(
        observations[2].findings,
        ["Stalwart has 3 domains; only the first 2 are checked (`max_domains`)."]
    );
}
