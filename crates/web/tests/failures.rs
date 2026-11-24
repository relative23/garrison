//! Every kind of failure of a check of a user's rights, from Stalwart
//! through Garrison's own authority and broker to the web service, at a
//! sign-in and at a request of a signed-in user: what the web service
//! answers, whether the session ends, what the sign-in page says, and what
//! the broker's and the web service's journals say of it.
//!
//! What each kind ends in is decided once, by an exhaustive match over the
//! kinds the Stalwart client and the broker's client give: a new kind does
//! not build until its row is decided, and each test fails while one of the
//! match's arms has no case.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use garrison_broker::client::CallError;
use garrison_broker::protocol::BrokerError;
use garrison_core::config::Config;
use garrison_stalwart::Error;
use garrison_testing::http::{answer, json};
use garrison_testing::{credentials, policy_document, write_policy, write_private};
use garrison_web::security::Broker;
use serde_json::{Value, json as value};
use support::brokers::{
    ahead, another, closing, failing, garbled, gone, late, ungranting, unreading, unsent, unstated,
};
use support::rights::{
    Expected, at_stalwart, at_the_broker, ended, granting, identity, journal, kept, listed,
};

const UNAVAILABLE: &str = "Authorization is temporarily unavailable";
const NOT_SET_UP: &str =
    "Garrison is not set up to check access rights; the broker's journal says why";

/// What a check that meets `kind` at Stalwart ends in, as the broker names
/// the kind with its reason; the number is the arm's, `ARMS` how many there
/// are. What Stalwart says of the user (a token it no longer takes, a
/// refusal) ends the session and fails the sign-in; everything else keeps
/// the session and says at sign-in that access could not be checked.
fn at_stalwart_row(kind: &Error) -> (u8, Expected) {
    match kind {
        Error::Unavailable(how) => (
            0,
            kept(
                503,
                UNAVAILABLE,
                &format!("WARN Stalwart did not complete a check of a user's rights ({how})"),
            ),
        ),
        Error::Limited(whose) => (
            1,
            kept(
                503,
                UNAVAILABLE,
                &format!(
                    "WARN Stalwart refused a check of a user's rights for its rate limit (HTTP \
                     429 to {whose})"
                ),
            ),
        ),
        Error::InvalidToken(reason) => (
            2,
            ended(
                401,
                "Sign-in required again",
                &format!("INFO Sign-in required again: {reason}"),
            ),
        ),
        Error::Denied(reason) => (
            3,
            ended(
                403,
                "Garrison access is not authorized",
                &format!("INFO Garrison access denied: {reason}"),
            ),
        ),
        Error::Unreadable(what) => (
            4,
            kept(
                503,
                UNAVAILABLE,
                &format!(
                    "ERROR Access rights cannot be checked: Stalwart answered in a form this \
                     release of Garrison does not read ({what})"
                ),
            ),
        ),
        Error::Misconfigured(why) => (
            5,
            kept(
                503,
                NOT_SET_UP,
                &format!("ERROR Access rights cannot be checked: {why}"),
            ),
        ),
    }
}

const STALWART_ARMS: u8 = 6;

/// What a check ends in where the broker's client gives `given` for it, as
/// the web service's journal names it (`why` for a broker that gave no
/// answer); the number is the arm's. A refusal of the broker's own here is a
/// failure inside it, as the user's refusals and Stalwart's are the other
/// table's.
fn at_the_broker_row(given: &Result<Value, CallError>, why: &str) -> (u8, Expected) {
    match given {
        Err(CallError::Unavailable(_)) => (
            0,
            kept(
                503,
                UNAVAILABLE,
                &format!("WARN The broker gave the web service no answer it can use ({why}"),
            ),
        ),
        Err(CallError::Refused(refusal)) => (
            1,
            kept(
                500,
                "Internal error",
                &format!(
                    "the broker answered HTTP {}: {}",
                    refusal.status, refusal.message
                ),
            ),
        ),
        Ok(grant) if grant["subject"] == "1" => (
            2,
            kept(
                502,
                "The broker returned an invalid authorization",
                "ERROR The broker answered a check of a user's rights with a grant this web \
                 service does not read: the two read different configurations",
            ),
        ),
        Ok(grant) => (
            3,
            Expected {
                status: 401,
                detail: "Sign-in required",
                ended: true,
                // The sign-in makes the session of whoever the grant names.
                reason: None,
                line: format!(
                    "WARN The session of account 1 got a grant of account {}",
                    grant["subject"].as_str().unwrap()
                ),
            },
        ),
    }
}

const BROKER_ARMS: u8 = 4;

fn unchanged(_: &Config) {}

/// A typo in the policy: it no longer reads as one.
fn mistyped(config: &Config) {
    write_private(&config.broker.policy, b"{\"schemaVersion\": 1,");
}

/// The broker's key is gone.
fn keyless(config: &Config) {
    std::fs::remove_file(credentials(config).path(&config.broker.native_key)).unwrap();
}

/// The policy binds subject 1 by hand to an account Stalwart does not have.
fn bound_to_a_missing_account(config: &Config) {
    let mut document = policy_document();
    document["subjects"] = value!({"1": {"accountId": "zz", "profile": "viewer"}});
    write_policy(config, &document);
}

/// Stalwart's management API has no account of `id`.
fn missing(id: &str) -> String {
    json(&value!({"methodResponses": [["x:Account/get", {"list": [], "notFound": [id]}, "0"]]}))
}

/// The account of subject 1 as Stalwart's management API answers for it.
fn account(shape: &Value) -> String {
    listed("x:Account/get", &value!([shape]))
}

/// The error Stalwart's management API answers a method with.
fn method_error(kind: &str) -> String {
    json(&value!({"methodResponses": [["error", {"type": kind}, "0"]]}))
}

/// A kind of failure at Stalwart: Stalwart's answers to one check, what
/// `before` breaks of Garrison's own setup, and the kind the broker meets.
struct AtStalwart(&'static str, Vec<String>, fn(&Config), Error);

/// A case whose Stalwart answers one check with `answers`.
fn case(name: &'static str, answers: Vec<String>, kind: Error) -> AtStalwart {
    AtStalwart(name, answers, unchanged, kind)
}

/// UserInfo, then the management API answering with `answer`.
fn at_the_api(answer: String) -> Vec<String> {
    vec![identity(), answer]
}

/// Stalwart that could not be reached, failed on its side or turned the
/// check away for its rate limit: none of them refuses the user.
fn passing() -> Vec<AtStalwart> {
    let unavailable = |how: &str| Error::Unavailable(how.into());
    vec![
        case(
            "UserInfo answers 503",
            vec![answer(503, "")],
            unavailable("UserInfo: Stalwart answered HTTP 503"),
        ),
        case(
            "UserInfo answers 408",
            vec![answer(408, "")],
            unavailable("UserInfo: Stalwart answered HTTP 408"),
        ),
        case(
            "UserInfo does not answer",
            vec![String::new()],
            unavailable("UserInfo: Stalwart is unavailable"),
        ),
        case(
            "the management API answers 502",
            at_the_api(answer(502, "")),
            unavailable("the management API: Stalwart answered HTTP 502"),
        ),
        case(
            "the management API fails its request",
            at_the_api(method_error("serverFail")),
            unavailable("the management API: Stalwart could not complete the request"),
        ),
        case(
            "UserInfo's rate limit",
            vec![answer(429, "")],
            Error::Limited("the user's token".into()),
        ),
        case(
            "the management API's rate limit",
            at_the_api(answer(429, "")),
            Error::Limited("the broker's key".into()),
        ),
    ]
}

/// What Stalwart says of the user: its token no longer taken, its account
/// one Garrison evaluates no rights for, or rights that grant no profile.
fn refusing() -> Vec<AtStalwart> {
    let tenant = account(
        &value!({"id": "b", "@type": "User", "roles": {"@type": "Admin"},
                                  "permissions": {"@type": "Inherit"}, "memberTenantId": "t1"}),
    );
    // As Stalwart 1.1.0 answers for a group, measured there only: its roles
    // are of a kind of their own.
    let group = account(
        &value!({"id": "b", "@type": "Group", "roles": {"@type": "Default"},
                                 "permissions": {"@type": "Inherit"}, "memberTenantId": null}),
    );
    let mut weak = granting();
    weak[3] = listed(
        "x:Role/get",
        &value!([{"id": "e", "roleIds": {}, "disabledPermissions": {},
                  "enabledPermissions": {"authenticate": true}}]),
    );
    let not_a_user = || Error::Denied("This identity's account belongs to a tenant".into());
    vec![
        case(
            "a token Stalwart no longer takes",
            vec![answer(401, "")],
            Error::InvalidToken("The access token is no longer valid".into()),
        ),
        case("an account of a tenant", at_the_api(tenant), not_a_user()),
        case("a group", at_the_api(group), not_a_user()),
        case(
            "no eligible profile",
            weak,
            Error::Denied("This identity has no eligible Garrison profile".into()),
        ),
    ]
}

/// What neither grants nor refuses: an answer of Stalwart's this release
/// does not read, and Garrison's own setup that is broken.
fn undecided() -> Vec<AtStalwart> {
    let mut cycle = granting();
    cycle[3] = listed(
        "x:Role/get",
        &value!([{"id": "e", "roleIds": {"e": true}, "disabledPermissions": {},
                  "enabledPermissions": {"authenticate": true}}]),
    );
    let unread = |why: &str| {
        Error::Misconfigured(format!(
            "the account's rights could not be read from Stalwart: {why}"
        ))
    };
    let unknown = account(
        &value!({"id": "b", "@type": "Individual", "roles": {"@type": "User"},
                                   "permissions": {"@type": "Inherit"}}),
    );
    vec![
        case(
            "an account of a type this release does not know",
            at_the_api(unknown),
            Error::Unreadable(
                "the management API: x:Account/get returned an account of a type this release \
                 does not know (\"Individual\")"
                    .into(),
            ),
        ),
        case(
            "an account Stalwart does not have",
            at_the_api(missing("b")),
            Error::Unreadable(
                "the management API: x:Account/get found no account b for the subject \
                 UserInfo named"
                    .into(),
            ),
        ),
        AtStalwart(
            "a binding to an account Stalwart does not have",
            at_the_api(missing("zz")),
            bound_to_a_missing_account,
            Error::Misconfigured(
                "the policy binds subject 1 to account zz, which Stalwart does not have".into(),
            ),
        ),
        case(
            "UserInfo in a form this release does not read",
            vec![answer(200, "<html>")],
            Error::Unreadable("UserInfo: The provider returned no stable subject".into()),
        ),
        case(
            "UserInfo answers 403",
            vec![answer(403, "")],
            Error::Unreadable("UserInfo: Stalwart answered HTTP 403".into()),
        ),
        case(
            "the broker's key refused",
            at_the_api(answer(401, "")),
            unread("The native API key was rejected"),
        ),
        case(
            "the account's object refused to the key",
            at_the_api(method_error("forbidden")),
            unread("x:Account/get was refused"),
        ),
        case(
            "a cycle of roles",
            cycle,
            unread("Native role inheritance cycle or depth limit"),
        ),
        AtStalwart(
            "a policy that does not read",
            vec![identity()],
            mistyped,
            Error::Misconfigured("Garrison access policy".into()),
        ),
        AtStalwart(
            "the broker's key gone",
            vec![identity()],
            keyless,
            Error::Misconfigured("the broker's API key".into()),
        ),
    ]
}

/// Every kind of failure a check of a user's rights can meet at Stalwart has
/// its answer and the broker's line that names its cause, as its row says.
#[tokio::test]
async fn every_failure_at_stalwart_has_its_answer_and_its_line() {
    let _turn = journal().await;
    let (mut wrong, mut arms) = (Vec::new(), BTreeSet::new());
    let cases = passing().into_iter().chain(refusing()).chain(undecided());
    for AtStalwart(name, answers, before, kind) in cases {
        let (arm, expected) = at_stalwart_row(&kind);
        arms.insert(arm);
        for problem in at_stalwart(&answers, before, &expected).await {
            wrong.push(format!("{name}: {problem}"));
        }
    }
    assert_eq!(wrong, Vec::<String>::new());
    assert_eq!(arms, (0..STALWART_ARMS).collect(), "an arm without a case");
}

/// A kind of failure of the broker's own: the broker that stands for it,
/// what its client gives the web service, and, where it gives no answer,
/// why, as the client's line says it.
struct AtTheBroker(
    &'static str,
    fn(&Path) -> Arc<dyn Broker>,
    Result<Value, CallError>,
    &'static str,
);

fn at_the_broker_cases() -> Vec<AtTheBroker> {
    let silent = || {
        Err(CallError::Unavailable(
            "The maintenance broker is unavailable",
        ))
    };
    let refused = |status, message: &str| {
        Err(CallError::Refused(BrokerError {
            status,
            message: message.into(),
        }))
    };
    vec![
        AtTheBroker(
            "its socket is gone",
            gone,
            silent(),
            "its socket could not be reached",
        ),
        AtTheBroker(
            "it closes the connection unanswered",
            closing,
            silent(),
            "it closed the connection without an answer",
        ),
        AtTheBroker(
            "it does not answer in time",
            late,
            silent(),
            "no answer within 1 s",
        ),
        AtTheBroker(
            "the request cannot be sent",
            unsent,
            silent(),
            "the request could not be sent",
        ),
        AtTheBroker(
            "its answer is no JSON",
            garbled,
            Err(CallError::Unavailable(
                "The maintenance broker returned a malformed answer",
            )),
            "its answer could not be read",
        ),
        AtTheBroker(
            "a request it cannot read",
            unreading,
            refused(400, "Unknown broker operation"),
            "",
        ),
        AtTheBroker(
            "a refusal without a status",
            unstated,
            refused(502, "Broker error"),
            "",
        ),
        AtTheBroker(
            "it fails inside",
            failing,
            refused(500, "Internal broker error"),
            "",
        ),
        AtTheBroker(
            "a grant the web service does not read",
            ungranting,
            Ok(value!({"subject": "1"})),
            "",
        ),
        AtTheBroker(
            "a grant of an action this web service does not have",
            ahead,
            Ok(support::grant("1", &["dashboard", "actions"], &["run_new"])),
            "",
        ),
        AtTheBroker(
            "a grant of another account",
            another,
            Ok(support::grant("2", &["dashboard"], &[])),
            "",
        ),
    ]
}

/// Every kind of failure of the broker's own has its answer and the web
/// service's line that names it, as its row says.
#[tokio::test]
async fn every_failure_of_the_brokers_own_has_its_answer_and_its_line() {
    let _turn = journal().await;
    let (mut wrong, mut arms) = (Vec::new(), BTreeSet::new());
    for AtTheBroker(name, failing, given, why) in at_the_broker_cases() {
        let (arm, expected) = at_the_broker_row(&given, why);
        arms.insert(arm);
        for problem in at_the_broker(failing, &expected).await {
            wrong.push(format!("{name}: {problem}"));
        }
    }
    assert_eq!(wrong, Vec::<String>::new());
    assert_eq!(arms, (0..BROKER_ARMS).collect(), "an arm without a case");
}
