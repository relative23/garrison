//! Where neither a check's `resolver` nor this host's `/etc/resolv.conf`
//! names a resolver, the checks that ask one say so, and name the option
//! that mends it.

use garrison_core::observations::{Observation, State};
use garrison_testing::http::{json as answer_json, serve};

use super::{Dns, Reputation};
use crate::context::{Context, Provider};
use crate::testing::{Canned, config, table};

/// The cards of `provider` with the collector's key, where Stalwart at
/// `stalwart` names the domains.
fn cards(provider: &dyn Provider, stalwart: &str) -> Vec<Observation> {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    stalwart.clone_into(&mut config.deployment.stalwart_url);
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        ..crate::testing::context(&config, &runner)
    };
    provider.collect(&context).unwrap().observations
}

#[test]
fn a_host_that_names_no_resolver_is_named_with_the_option_that_mends_it() {
    let directory = tempfile::tempdir().unwrap();
    // A resolv.conf with a search domain and no nameserver.
    let resolv_conf = directory.path().join("resolv.conf");
    std::fs::write(&resolv_conf, "search example.test\n").unwrap();
    let said = "this host names no resolver in /etc/resolv.conf; name one with `resolver`";
    let dns = Dns::new(&table("type = \"dns\""))
        .unwrap()
        .with_resolv_conf(&resolv_conf);
    let reputation = Reputation::new(&table(
        "type = \"reputation\"\nhosts = [\"mail.example.test\"]",
    ))
    .unwrap()
    .with_resolv_conf(&resolv_conf);
    // The dns check asks Stalwart for its domains first; the reputation
    // check with mail hosts of its own asks Stalwart nothing.
    let stalwart = serve(vec![answer_json(&serde_json::json!({"methodResponses": [[
        "x:Domain/get",
        {"list": [{"id": "b", "name": "example.test",
                   "dnsZoneFile": "example.test. IN MX 10 mail.example.test.\n"}]},
        "0"
    ]]}))]);
    let mut found: Vec<(String, State, Vec<String>)> = Vec::new();
    for card in cards(&dns, &stalwart.url)
        .into_iter()
        .chain(cards(&reputation, "http://127.0.0.1:9"))
    {
        found.push((card.id, card.state, card.findings));
    }
    stalwart.requests();
    let unknown = |id: &str, finding: String| (id.to_owned(), State::Unknown, vec![finding]);
    assert_eq!(
        found,
        [
            unknown("dns.records", format!("Not asked: {said}.")),
            unknown(
                "reputation.blocklists",
                format!("Nothing could be asked: {said}.")
            ),
            unknown(
                "reputation.reverse",
                format!("Nothing could be asked: {said}.")
            ),
        ]
    );
}
