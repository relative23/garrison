//! The domains after the first `max_domains` are not checked, and the
//! check says so.

use garrison_testing::http::{json as answer_json, serve};
use serde_json::json;

use super::*;
use crate::testing::{Canned, config, table};

/// What the checks that take their mail hosts from Stalwart say of its
/// domains after the first 20.
pub(crate) const LEFT_OUT: &str =
    "Stalwart has 21 domains; only the first 20 are checked (`max_domains`).";

/// Stalwart's answer to the checks' request for the domains `list`, each
/// with its `id`: the query's IDs from the first, with their total, and the
/// get of them. It gives them all, as many as the request asks for or more:
/// the checks take what they asked for.
pub(crate) fn domains_value(list: &serde_json::Value) -> serde_json::Value {
    let ids: Vec<serde_json::Value> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|domain| domain["id"].clone())
        .collect();
    json!({"methodResponses": [
        ["x:Domain/query", {"ids": ids, "position": 0, "total": ids.len()}, "0"],
        ["x:Domain/get", {"list": list, "notFound": []}, "1"],
    ]})
}

/// Stalwart's answer for 21 domains: the first 20 with the mail host
/// `mail.example.test`, the last with `mx2.example.test`.
pub(crate) fn twenty_one_domains() -> serde_json::Value {
    let domains: Vec<serde_json::Value> = (0..21)
        .map(|number| {
            let host = if number < 20 { "mail" } else { "mx2" };
            let name = format!("d{number}.example.test");
            let zone = format!("{name}. IN MX 10 {host}.example.test.\n");
            json!({"id": format!("b{number}"), "name": name, "dnsZoneFile": zone})
        })
        .collect();
    domains_value(&serde_json::json!(domains))
}

/// A context in which Stalwart, at `url`, gives its domains to the key.
pub(crate) fn with_stalwart<'a>(
    config: &'a mut garrison_core::config::Config,
    runner: &'a Canned,
    url: &str,
) -> Context<'a> {
    config.deployment.stalwart_url = url.to_owned();
    Context {
        native_key: Some("key".into()),
        ..crate::testing::context(config, runner)
    }
}

#[test]
fn domains_beyond_max_domains_are_named_not_left_out() {
    let domains: Vec<serde_json::Value> = (0..3)
        .map(
            |number| json!({"id": format!("b{number}"), "name": format!("d{number}.example.test")}),
        )
        .collect();
    let stalwart = serve(vec![answer_json(&domains_value(&serde_json::json!(
        domains
    )))]);
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
