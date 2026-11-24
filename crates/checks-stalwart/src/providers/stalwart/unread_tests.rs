//! Where Stalwart answers the check's one request in a form this release
//! does not read, as a release Garrison does not support yet may, the
//! Management API card names the answer and points to the supported
//! Stalwart releases, not to setup; where it refuses the collector's key,
//! the card gives the setup's advice, as the other cards do.

use garrison_stalwart::http::MAX_RESPONSE;
use garrison_testing::http::{answer, json as answer_json};
use serde_json::{Value, json};

use super::limit_tests::{api, cards};
use super::*;

#[test]
fn an_answer_this_release_does_not_read_is_named_on_the_management_api_card() {
    let unread = |why: &str| {
        vec![format!(
            "Not readable: Stalwart answered in a form this release of Garrison does not read \
             ({why}); see the supported Stalwart releases in the README."
        )]
    };
    for (response, why) in [
        (
            answer(200, "<html>Welcome</html>"),
            "Malformed native API response",
        ),
        (answer(400, ""), "Unexpected native API status 400"),
        (
            answer(200, &"x".repeat(MAX_RESPONSE + 1)),
            "Stalwart response exceeds its size limit",
        ),
    ] {
        let card = api(response);
        assert_eq!((card.state, card.findings), (State::Unknown, unread(why)));
    }
}

/// Stalwart refuses a key it does not know with 401 and one it does not let
/// read with 403: the setup gives the key what the check reads.
#[test]
fn a_refused_key_gets_the_setups_advice_on_the_management_api_card() {
    for status in [401, 403] {
        let card = api(answer(status, ""));
        assert_eq!(
            (card.state, card.findings),
            (
                State::Unknown,
                vec![
                    "Not readable: access denied; run `garrison stalwart setup` again, which \
                     gives the collector's API key the permissions it needs."
                        .to_owned()
                ]
            ),
            "{status}"
        );
    }
}

/// Each call of the one request answers for itself. Where Stalwart refused
/// the key some of them, as it refuses every call of a key that may only
/// authenticate (measured on Stalwart 1.1.0), or answered one in a form this
/// release does not read, the Management API card says which, beside the
/// cards the other calls fill.
#[test]
fn calls_that_gave_nothing_are_named_on_the_management_api_card() {
    let error = |kind: &str, tag: usize| json!(["error", {"type": kind}, tag.to_string()]);
    let methods: Vec<&str> = calls().iter().map(|(method, _)| *method).collect();
    let all: Vec<Value> = (0..methods.len())
        .map(|tag| error("forbidden", tag))
        .collect();
    let refused = api(answer_json(&json!({ "methodResponses": all })));
    assert_eq!(
        (refused.state, refused.findings),
        (
            State::Unknown,
            vec![format!(
                "Not readable: access denied to {}; run `garrison stalwart setup` again, which \
                 gives the collector's API key the permissions it needs.",
                methods.join(", ")
            )]
        )
    );
    // One refused, one Stalwart does not know, one not answered, the
    // others answered: the queue is read.
    let some = cards(answer_json(&json!({"methodResponses": [
        error("forbidden", 0),
        ["x:SpamClassifier/get", {"list": []}, "1"],
        error("unknownMethod", 2),
        ["x:SpamTrainingSample/query", {"total": 0}, "3"],
        ["x:QueuedMessage/query", {"total": 4}, "4"],
        ["x:MtaMilter/get", {"list": []}, "5"],
    ]})));
    let card = |id: &str| cards_of(&some, id);
    assert_eq!(
        card("stalwart.api").findings,
        [
            "Not readable: access denied to x:SpamSettings/get; run `garrison stalwart setup` \
             again, which gives the collector's API key the permissions it needs.",
            "Not readable: Stalwart answered in a form this release of Garrison does not read \
             (x:SpamRule/query answered the error unknownMethod, x:Account/get was not \
             answered); see the supported Stalwart releases in the README.",
        ]
    );
    assert_eq!(card("stalwart.queue").state, State::Ok);
    assert_eq!(card("stalwart.spam").state, State::Unknown);
}

fn cards_of<'a>(observations: &'a [Observation], id: &str) -> &'a Observation {
    observations
        .iter()
        .find(|observation| observation.id == id)
        .unwrap()
}
