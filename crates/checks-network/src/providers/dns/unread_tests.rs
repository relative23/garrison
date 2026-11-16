//! Where Stalwart did not give the collector's key its domains or its
//! listeners, the checks that read them say why, each kind of failure in
//! words of its own, and give the setup's advice only where it helps: for a
//! key Stalwart refused, not for a Stalwart that did not answer or refused
//! the key for its rate limit, which pass by themselves, nor for an answer
//! this release does not read, which they name, pointing to the supported
//! Stalwart releases.

use garrison_core::observations::Observation;
use garrison_stalwart::http::MAX_RESPONSE;
use garrison_testing::http::{answer, json as answer_json, serve};
use serde_json::json;

use super::*;
use crate::providers::{Reputation, Tls};
use crate::testing::{Canned, config, table};

/// What Stalwart answers a request it cannot or will not take: an outage, its
/// rate limit, a key it refuses, or a method it refuses the key; and answers
/// this release does not read: no JSON, a status it does not expect, more
/// than it reads.
fn failures() -> Vec<(&'static str, Option<String>)> {
    let method = |kind: &str| {
        Some(answer_json(
            &json!({"methodResponses": [["error", {"type": kind}, "0"]]}),
        ))
    };
    vec![
        // Nothing listens at the address the configuration names.
        ("closed", None),
        ("503", Some(answer(503, ""))),
        ("serverFail", method("serverFail")),
        ("429", Some(answer(429, ""))),
        ("403", Some(answer(403, ""))),
        ("forbidden", method("forbidden")),
        ("no JSON", Some(answer(200, "<html>Welcome</html>"))),
        ("400", Some(answer(400, ""))),
        (
            "too large",
            Some(answer(200, &"x".repeat(MAX_RESPONSE + 1))),
        ),
    ]
}

/// What a card says for each failure of [`failures`], `framed` around the
/// words for what Stalwart was asked for, `what`; `besides` is what else
/// mends it, after the setup's advice or the supported releases.
fn said(framed: &str, what: &str, besides: &str) -> Vec<(&'static str, Vec<String>)> {
    let unanswered = format!("Stalwart did not answer the collector's request for its {what}");
    let limited = format!(
        "Stalwart refused the collector's key for its rate limit (HTTP 429), so its {what} \
         could not be read"
    );
    let refused = format!(
        "Stalwart did not give its {what} to the collector's API key; run `garrison stalwart \
         setup` again to let it read them{besides}"
    );
    let unread = |why: &str| {
        format!(
            "Stalwart answered the collector's request for its {what} in a form this release of \
             Garrison does not read ({why}); see the supported Stalwart releases in the \
             README{besides}"
        )
    };
    let kinds = [
        unanswered.clone(),
        unanswered.clone(),
        unanswered,
        limited,
        refused.clone(),
        refused,
        unread("Malformed native API response"),
        unread("Unexpected native API status 400"),
        unread("Stalwart response exceeds its size limit"),
    ];
    failures()
        .into_iter()
        .zip(kinds)
        .map(|((failure, _), kind)| (failure, vec![framed.replace("{}", &kind)]))
        .collect()
}

/// The observations of `provider` against a Stalwart that answers the
/// collector's requests with `answers`, one after another; with none, at a
/// port where nothing listens.
fn collected(provider: &dyn Provider, answers: Vec<String>) -> Vec<Observation> {
    let stalwart = (!answers.is_empty()).then(|| serve(answers));
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    if let Some(stalwart) = &stalwart {
        config.deployment.stalwart_url.clone_from(&stalwart.url);
    }
    let runner = Canned(String::new());
    let context = Context {
        native_key: Some("key".into()),
        ..crate::testing::context(&config, &runner)
    };
    let observations = provider.collect(&context).unwrap().observations;
    if let Some(stalwart) = stalwart {
        stalwart.requests();
    }
    observations
}

/// For each failure, the findings of every card `provider` reports, each
/// card Unknown; `before` answers the requests that come first.
fn findings(provider: &dyn Provider, before: &[String]) -> Vec<(&'static str, Vec<String>)> {
    failures()
        .into_iter()
        .map(|(failure, answer)| {
            let answers: Vec<String> = match answer {
                Some(answer) => before.iter().cloned().chain([answer]).collect(),
                None => Vec::new(),
            };
            let observations = collected(provider, answers);
            for card in &observations {
                assert_eq!(card.state, State::Unknown, "{failure}: {}", card.id);
            }
            let first = observations[0].findings.clone();
            for card in &observations {
                assert_eq!(card.findings, first, "{failure}: {}", card.id);
            }
            (failure, first)
        })
        .collect()
}

#[test]
fn the_dns_card_says_why_stalwarts_domains_could_not_be_read() {
    let provider = Dns::new(&table("type = \"dns\"\nresolver = \"127.0.0.1:9\"")).unwrap();
    assert_eq!(findings(&provider, &[]), said("{}.", "domains", ""));
    let observations = collected(&provider, vec![answer(503, "")]);
    assert_eq!(observations[0].id, "dns.records");
}

#[test]
fn the_reputation_cards_say_why_stalwarts_domains_could_not_be_read() {
    let provider =
        Reputation::new(&table("type = \"reputation\"\nresolver = \"127.0.0.1:9\"")).unwrap();
    assert_eq!(
        findings(&provider, &[]),
        said("Nothing could be asked: {}.", "domains", "")
    );
}

/// The certificate check asks for the listeners first, then for the
/// domains, whose mail hosts it probes under: either may fail, and naming
/// `endpoints` makes both unnecessary.
const TLS_BESIDES: &str = ", or name `endpoints`";
const TLS_FRAMED: &str = "The endpoints are not known: {}.";

#[test]
fn the_certificate_card_says_why_stalwarts_listeners_could_not_be_read() {
    let provider = Tls::new(&table("type = \"tls\"")).unwrap();
    assert_eq!(
        findings(&provider, &[]),
        said(TLS_FRAMED, "listeners", TLS_BESIDES)
    );
}

#[test]
fn the_certificate_card_says_why_stalwarts_domains_could_not_be_read() {
    let provider = Tls::new(&table("type = \"tls\"")).unwrap();
    let listeners = answer_json(
        &json!({"methodResponses": [["x:NetworkListener/get", {"list": [
        {"protocol": "smtp", "bind": {"[::]:465": true}, "useTls": true, "implicitTls": true}
    ]}, "0"]]}),
    );
    // Where nothing listens, the listeners are not read either.
    let mut domains = said(TLS_FRAMED, "domains", TLS_BESIDES);
    domains[0] = said(TLS_FRAMED, "listeners", TLS_BESIDES).remove(0);
    assert_eq!(findings(&provider, &[listeners]), domains);
}
