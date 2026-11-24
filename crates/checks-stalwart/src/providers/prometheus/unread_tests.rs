//! Where the exporter's answer could not be read, the card says why, each
//! kind of failure in words of its own: an outage, Stalwart's rate limit,
//! and an answer larger than the collector reads, which points to the
//! supported Stalwart releases.

use garrison_stalwart::http::MAX_RESPONSE;
use garrison_testing::http::{answer, serve};

use super::*;
use crate::testing::{Canned, config, context, table};

/// The exporter's card where Stalwart answers the scrape with `response`.
fn card(response: String) -> (State, Vec<String>) {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(vec![response]);
    let mut config = config(directory.path());
    config.deployment.stalwart_url.clone_from(&server.url);
    let runner = Canned(String::new());
    let context = Context {
        metrics_credential: Scrape::Credential("metrics".to_owned(), "secret".to_owned()),
        ..context(&config, &runner)
    };
    let provider = Prometheus::new(&table("type = \"prometheus\"")).unwrap();
    let report = provider.collect(&context).unwrap();
    server.requests();
    let card = report.observations.into_iter().next().unwrap();
    (card.state, card.findings)
}

#[test]
fn the_exporters_card_says_why_its_answer_could_not_be_read() {
    let unknown = |finding: &str| (State::Unknown, vec![finding.to_owned()]);
    assert_eq!(
        [
            card(answer(503, "")),
            card(answer(429, "")),
            card(answer(200, &"#".repeat(MAX_RESPONSE + 1))),
        ],
        [
            unknown("The exporter is unavailable."),
            unknown("Stalwart refused the collector's scrape for its rate limit (HTTP 429)."),
            unknown(
                "The exporter's answer could not be read: Stalwart response exceeds its size \
                 limit; see the supported Stalwart releases in the README."
            ),
        ]
    );
}

/// Stalwart refuses a scrape credential it does not take, as after it was
/// changed in the Stalwart WebUI, with 401 or 403: the card says so and
/// names what writes it.
#[test]
fn a_refused_scrape_credential_names_what_writes_it() {
    for status in [401, 403] {
        assert_eq!(
            card(answer(status, "")),
            (
                State::Unknown,
                vec![format!(
                    "The exporter refused the collector's scrape credential (HTTP {status}). \
                     {SCRAPE_FIX}"
                )]
            )
        );
    }
    // Another status is named as it is.
    assert_eq!(
        card(answer(404, "")),
        (
            State::Unknown,
            vec!["The exporter answered HTTP 404.".to_owned()]
        )
    );
}
