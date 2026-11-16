//! Where Stalwart did not give the collector's key its domains or its
//! listeners, the checks that read them say why, each kind of failure in
//! words of its own, and give the setup's advice only where it helps: for a
//! key Stalwart refused, not for a Stalwart that did not answer or refused
//! the key for its rate limit, which pass by themselves.

use garrison_core::observations::Observation;
use garrison_testing::http::{answer, json as answer_json, serve};
use serde_json::json;

use super::*;
use crate::providers::{Reputation, Tls};
use crate::testing::{Canned, config, table};

const UNANSWERED: &str = "Stalwart did not answer the collector's request for its domains";
const LIMITED: &str = "Stalwart refused the collector's key for its rate limit (HTTP 429), so its \
                       domains could not be read";
const REFUSED: &str = "Stalwart did not give its domains to the collector's API key; run \
                       `garrison stalwart setup` again to let it read them";

/// What Stalwart answers a request it cannot or will not take: an outage, its
/// rate limit, a key it refuses, or a method it refuses the key.
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
    ]
}

/// What a card says for each failure of [`failures`], `framed` around the
/// words for what Stalwart was asked for, `what`; `fix` is the setup's
/// advice for a key Stalwart refused.
fn said(framed: &str, what: &str, fix: &str) -> Vec<(&'static str, Vec<String>)> {
    let words = |words: &str| {
        framed.replace(
            "{}",
            &words
                .replace("domains", what)
                .replace("let it read them", fix),
        )
    };
    let kinds = [
        UNANSWERED, UNANSWERED, UNANSWERED, LIMITED, REFUSED, REFUSED,
    ];
    failures()
        .into_iter()
        .zip(kinds)
        .map(|((failure, _), kind)| (failure, vec![words(kind)]))
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
    assert_eq!(
        findings(&provider, &[]),
        said("{}.", "domains", "let it read them")
    );
    let observations = collected(&provider, vec![answer(503, "")]);
    assert_eq!(observations[0].id, "dns.records");
}

#[test]
fn the_reputation_cards_say_why_stalwarts_domains_could_not_be_read() {
    let provider =
        Reputation::new(&table("type = \"reputation\"\nresolver = \"127.0.0.1:9\"")).unwrap();
    assert_eq!(
        findings(&provider, &[]),
        said("Nothing could be asked: {}.", "domains", "let it read them")
    );
}

/// The certificate check asks for the listeners first, then for the
/// domains, whose mail hosts it probes under: either may fail, and naming
/// `endpoints` makes both unnecessary.
const TLS_FIX: &str = "let it read them, or name `endpoints`";
const TLS_FRAMED: &str = "The endpoints are not known: {}.";

#[test]
fn the_certificate_card_says_why_stalwarts_listeners_could_not_be_read() {
    let provider = Tls::new(&table("type = \"tls\"")).unwrap();
    assert_eq!(
        findings(&provider, &[]),
        said(TLS_FRAMED, "listeners", TLS_FIX)
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
    let mut domains = said(TLS_FRAMED, "domains", TLS_FIX);
    domains[0] = said(TLS_FRAMED, "listeners", TLS_FIX).remove(0);
    assert_eq!(findings(&provider, &[listeners]), domains);
}
