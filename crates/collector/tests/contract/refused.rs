//! A key Stalwart does not let read what a check reads, and a key it does
//! not know, are refusals: the checks that read Stalwart's domains and
//! listeners give the setup's advice for them, and not the words for a
//! Stalwart that did not answer or met its rate limit.

use garrison_collector::providers::{Dns, Reputation, Tls};
use garrison_core::observations::State;
use garrison_testing::lab::{Lab, random_hex, unique};
use serde_json::json;

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
