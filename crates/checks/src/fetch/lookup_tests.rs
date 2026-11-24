//! A name the system's lookup could not resolve is named with the lookup's
//! own words, which tell a name that does not exist from a lookup that
//! could not be made now ("Name does not resolve", "Try again").

use super::*;

#[test]
fn a_failed_lookup_keeps_the_systems_words() {
    // `invalid` is a name that never exists (RFC 6761).
    let error = get("https://garrison-test.invalid/", &roots()).unwrap_err();
    let reason = error
        .strip_prefix("garrison-test.invalid could not be looked up: ")
        .unwrap_or_else(|| panic!("{error}"));
    assert!(!reason.is_empty(), "{error}");
}
