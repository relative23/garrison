//! Where Stalwart answers the check's one request in a form this release
//! does not read, as a release Garrison does not support yet may, the
//! Management API card names the answer and points to the supported
//! Stalwart releases, not to setup.

use garrison_stalwart::http::MAX_RESPONSE;
use garrison_testing::http::answer;

use super::limit_tests::api;
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
