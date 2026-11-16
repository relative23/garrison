//! A key Stalwart does not let read what a check reads, and a key it does
//! not know, are refusals: the checks that read Stalwart's domains,
//! listeners and accounts give the setup's advice for them, and not the
//! words for a Stalwart that did not answer or met its rate limit, and so
//! does the Management API card, naming the calls Stalwart refused.

use std::time::Duration;

use garrison_collector::providers::stalwart::calls;
use garrison_collector::providers::{Dns, Reputation, Stalwart, Tls};
use garrison_core::observations::State;
use garrison_stalwart::jmap::JmapClient;
use garrison_testing::lab::{Lab, random_hex, unique};
use serde_json::{Value, json};

use super::{collect, deployment, one_at_a_time};

const DOMAINS: &str = "Stalwart did not give its domains to the collector's API key; run \
                       `garrison stalwart setup` again to let it read them";

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_key_stalwart_refuses_gets_the_setups_advice() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    // A key that may authenticate and read nothing, as one made before the
    // checks that read domains and listeners.
    let created = lab.call(
        "x:ApiKey/set",
        &json!({"create": {"k": {
            "description": format!("{} refused key contract test", unique()),
            "permissions": {"@type": "Replace", "permissions": {"authenticate": true}},
            "expiresAt": null,
        }}}),
    );
    let key = &created["created"]["k"];
    lab.created
        .push(("ApiKey".into(), key["id"].as_str().unwrap().to_owned()));
    let narrow = key["secret"].as_str().unwrap().to_owned();
    let deployment = deployment(&lab);
    for (secret, which) in [(narrow, "a narrow key"), (random_hex(24), "an unknown key")] {
        // The client takes each for a refusal, for every kind of object the
        // checks read with the collector's key; the mail flow's accounts
        // among them, whose card needs an event history to show it.
        let client = JmapClient::new(&lab.url, &secret).with_timeout(Duration::from_secs(15));
        for kind in ["Domain", "NetworkListener", "Account"] {
            let read = client.get::<Value>(kind, None, &["id"]);
            assert!(
                matches!(read, Err(garrison_stalwart::Error::Denied(_))),
                "{which}, {kind}: {read:?}"
            );
        }
        let dns = Dns::new(
            &"type = \"dns\"\nresolver = \"127.0.0.1:9\""
                .parse()
                .unwrap(),
        )
        .unwrap();
        let report = collect(&dns, &deployment, Some(secret.clone()), None);
        let card = &report.observations[0];
        assert_eq!(
            (card.id.as_str(), card.state, card.findings.clone()),
            ("dns.records", State::Unknown, vec![format!("{DOMAINS}.")]),
            "{which}"
        );

        let reputation = Reputation::new(
            &"type = \"reputation\"\nresolver = \"127.0.0.1:9\""
                .parse()
                .unwrap(),
        )
        .unwrap();
        let report = collect(&reputation, &deployment, Some(secret.clone()), None);
        for card in &report.observations {
            assert_eq!(
                card.findings,
                [format!("Nothing could be asked: {DOMAINS}.")],
                "{which}: {}",
                card.id
            );
        }

        // Stalwart refuses each of the check's calls to the narrow key, and
        // the whole request to a key it does not know (401).
        let stalwart = Stalwart::new(&"type = \"stalwart\"".parse().unwrap()).unwrap();
        let report = collect(&stalwart, &deployment, Some(secret.clone()), None);
        let api = report
            .observations
            .iter()
            .find(|card| card.id == "stalwart.api")
            .unwrap_or_else(|| panic!("{which}: {:?}", report.observations));
        let methods: Vec<&str> = calls().iter().map(|(method, _)| *method).collect();
        let refused = if which == "a narrow key" {
            format!(" to {}", methods.join(", "))
        } else {
            String::new()
        };
        assert_eq!(
            api.findings,
            [format!(
                "Not readable: access denied{refused}; run `garrison stalwart setup` again, which \
                 gives the collector's API key the permissions it needs."
            )],
            "{which}"
        );

        let tls = Tls::new(&"type = \"tls\"".parse().unwrap()).unwrap();
        let report = collect(&tls, &deployment, Some(secret), None);
        assert_eq!(
            report.observations[0].findings,
            [
                "The endpoints are not known: Stalwart did not give its listeners to the \
                 collector's API key; run `garrison stalwart setup` again to let it read them, \
                 or name `endpoints`."
            ],
            "{which}"
        );
    }
}
