//! Every kind of failure of a check of a user's rights, from Stalwart
//! through Garrison's own authority and broker to the web service, at a
//! sign-in and at a request of a signed-in user: what the web service
//! answers, whether the session ends, what the sign-in page says, and what
//! the broker's and the web service's journals say of it.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use garrison_broker::client::{BrokerClient, CallError};
use garrison_broker::protocol::{BrokerError, read_line};
use garrison_core::config::Config;
use garrison_testing::http::{answer, json, serve};
use garrison_testing::{credentials, write_private};
use garrison_web::App;
use garrison_web::security::Broker;
use serde_json::json as value;
use support::Client;
use support::rights::{
    Asked, Fixed, Switch, configured, granting, identity, journal, listed, service, web, written,
};

/// What a case ends in: the web service's answer to a request of a signed-in
/// user (status and detail), whether that ends the session, the reason the
/// sign-in page gets (`None` where the case is no sign-in's), and words of
/// the one line in a journal that names the cause.
struct Expected {
    status: u16,
    detail: &'static str,
    ended: bool,
    reason: Option<&'static str>,
    line: String,
}

/// How often a line holds `words`.
fn found(lines: &[String], words: &str) -> usize {
    lines.iter().filter(|line| line.contains(words)).count()
}

/// The reason a sign-in ended on the sign-in page with, or "" where it
/// made a session.
async fn signed_in(client: &mut Client) -> String {
    let login = client.get("/auth/login").await;
    let location = url::Url::parse(login.header("location")).unwrap();
    let (_, state) = location
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap();
    let callback =
        format!("/auth/callback?state={state}&code=code&iss=https%3A%2F%2Fmail.example.test");
    let back = client.get(&callback).await.header("location").to_owned();
    back.split_once("login_error=")
        .map(|(_, reason)| reason.to_owned())
        .unwrap_or_default()
}

/// What differs from `expected` at a request of the signed-in user of
/// `client` and in the `lines` it wrote.
async fn requested(client: &mut Client, app: &App, expected: &Expected) -> Vec<String> {
    written();
    let answer = client.get("/api/status").await;
    let lines = written();
    let mut wrong = Vec::new();
    let got = (
        answer.status.as_u16(),
        answer.json()["detail"].as_str().unwrap_or("").to_owned(),
    );
    if got != (expected.status, expected.detail.to_owned()) {
        wrong.push(format!("answered {got:?}"));
    }
    let cookie = client.cookies.get("__Host-garrison_session").cloned();
    let ended = app
        .store
        .get(&cookie.unwrap_or_default())
        .unwrap()
        .is_none();
    if ended != expected.ended {
        wrong.push(format!("session ended: {ended}"));
    }
    if found(&lines, &expected.line) != 1 {
        wrong.push(format!("lines {lines:?}"));
    }
    wrong
}

/// What differs from `expected` at a sign-in through `client`.
async fn at_sign_in(client: &mut Client, expected: &Expected) -> Vec<String> {
    let Some(reason) = expected.reason else {
        return Vec::new();
    };
    written();
    let got = signed_in(client).await;
    let lines = written();
    let mut wrong = Vec::new();
    if got != reason {
        wrong.push(format!("at sign-in the reason {got:?}"));
    }
    let rejected = format!(
        "WARN Sign-in rejected by authorization (HTTP {}: ",
        expected.status
    );
    if found(&lines, &expected.line) != 1 || found(&lines, &rejected) != 1 {
        wrong.push(format!("at sign-in lines {lines:?}"));
    }
    wrong
}

/// One kind of failure at Stalwart, which Stalwart's `answers` to one check
/// make, or which `before` makes of Garrison's own setup: what differs from
/// `expected` at a request of a user whose sign-in Stalwart granted, and at
/// a sign-in.
async fn at_stalwart(answers: &[String], before: fn(&Config), expected: &Expected) -> Vec<String> {
    let directory = tempfile::tempdir().unwrap();
    let server = serve([granting(), answers.to_vec()].concat());
    let config = configured(directory.path(), &server.url);
    let (mut client, app) = web(&config, Arc::new(Asked(service(&config))));
    assert_eq!(signed_in(&mut client).await, "", "the sign-in before");
    before(&config);
    let mut wrong = requested(&mut client, &app, expected).await;
    drop(server);
    let directory = tempfile::tempdir().unwrap();
    let server = serve(answers.to_vec());
    let config = configured(directory.path(), &server.url);
    let (mut client, _app) = web(&config, Arc::new(Asked(service(&config))));
    before(&config);
    wrong.extend(at_sign_in(&mut client, expected).await);
    drop(server);
    wrong
}

/// One kind of failure of the broker's own, which `failing` stands for: what
/// differs from `expected` at a request of a user whose sign-in the broker
/// granted, and at a sign-in.
async fn at_the_broker(failing: fn(&Path) -> Arc<dyn Broker>, expected: &Expected) -> Vec<String> {
    let directory = tempfile::tempdir().unwrap();
    let config = configured(directory.path(), "http://127.0.0.1:9");
    let granting: Arc<dyn Broker> = Arc::new(Fixed(Ok(support::grant("1", &["dashboard"], &[]))));
    let switch = Arc::new(Switch(Mutex::new(granting)));
    let (mut client, app) = web(&config, Arc::clone(&switch) as Arc<dyn Broker>);
    assert_eq!(signed_in(&mut client).await, "", "the sign-in before");
    *switch.0.lock().unwrap() = failing(directory.path());
    let mut wrong = requested(&mut client, &app, expected).await;
    let (mut client, _app) = web(&config, failing(directory.path()));
    wrong.extend(at_sign_in(&mut client, expected).await);
    wrong
}

fn unchanged(_: &Config) {}

/// A typo in the policy: it no longer reads as one.
fn mistyped(config: &Config) {
    write_private(&config.broker.policy, b"{\"schemaVersion\": 1,");
}

/// The broker's key is gone.
fn keyless(config: &Config) {
    std::fs::remove_file(credentials(config).path(&config.broker.native_key)).unwrap();
}

/// A broker whose socket is not there.
fn gone(directory: &Path) -> Arc<dyn Broker> {
    Arc::new(BrokerClient::new(directory.join("gone.sock")))
}

/// A broker that answers each connection with `line`, or closes it unanswered.
fn answering(directory: &Path, name: &str, line: Option<&'static [u8]>) -> Arc<dyn Broker> {
    let path = directory.join(name);
    if !path.exists() {
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                if let Some(line) = line {
                    let _ = read_line(&mut stream, 65536);
                    let _ = stream.write_all(line);
                }
            }
        });
    }
    Arc::new(BrokerClient::new(path).with_timeout(Duration::from_secs(2)))
}

fn closing(directory: &Path) -> Arc<dyn Broker> {
    answering(directory, "closing.sock", None)
}

fn garbled(directory: &Path) -> Arc<dyn Broker> {
    answering(directory, "garbled.sock", Some(b"not json\n"))
}

fn ungranting(_: &Path) -> Arc<dyn Broker> {
    Arc::new(Fixed(Ok(value!({"subject": "1"}))))
}

fn failing(_: &Path) -> Arc<dyn Broker> {
    Arc::new(Fixed(Err(CallError::Refused(BrokerError {
        status: 500,
        message: "Internal broker error".into(),
    }))))
}

fn another(_: &Path) -> Arc<dyn Broker> {
    Arc::new(Fixed(Ok(support::grant("2", &["dashboard"], &[]))))
}

const UNAVAILABLE: &str = "Authorization is temporarily unavailable";

/// A case that keeps the session and says at sign-in that access could not
/// be checked.
fn kept(status: u16, detail: &'static str, line: &str) -> Expected {
    Expected {
        status,
        detail,
        ended: false,
        reason: Some("unchecked"),
        line: line.to_owned(),
    }
}

/// A case that ends the session and fails the sign-in.
fn ended(status: u16, detail: &'static str, line: &str) -> Expected {
    Expected {
        status,
        detail,
        ended: true,
        reason: Some("1"),
        line: line.to_owned(),
    }
}

/// A kind of failure at Stalwart: Stalwart's answers to one check, what
/// `before` breaks of Garrison's own setup, and what it ends in.
struct AtStalwart(&'static str, Vec<String>, fn(&Config), Expected);

/// Stalwart that could not be reached, failed on its side or turned the
/// check away for its rate limit: none of them refuses the user.
fn passing() -> Vec<AtStalwart> {
    let outage = |how: &str| {
        let line = format!("WARN Stalwart did not complete a check of a user's rights ({how})");
        kept(503, UNAVAILABLE, &line)
    };
    let limited = |whose: &str| {
        let line = format!(
            "WARN Stalwart refused a check of a user's rights for its rate limit (HTTP 429 to \
             {whose})"
        );
        kept(503, UNAVAILABLE, &line)
    };
    let failed = json(&value!({"methodResponses": [["error", {"type": "serverFail"}, "0"]]}));
    vec![
        AtStalwart(
            "UserInfo answers 503",
            vec![answer(503, "")],
            unchanged,
            outage("UserInfo: Stalwart answered HTTP 503"),
        ),
        AtStalwart(
            "UserInfo does not answer",
            vec![String::new()],
            unchanged,
            outage("UserInfo: Stalwart is unavailable"),
        ),
        AtStalwart(
            "the management API answers 502",
            vec![identity(), answer(502, "")],
            unchanged,
            outage("the management API: Stalwart answered HTTP 502"),
        ),
        AtStalwart(
            "the management API fails its request",
            vec![identity(), failed],
            unchanged,
            outage("the management API: Stalwart could not complete the request"),
        ),
        AtStalwart(
            "UserInfo's rate limit",
            vec![answer(429, "")],
            unchanged,
            limited("the user's token"),
        ),
        AtStalwart(
            "the management API's rate limit",
            vec![identity(), answer(429, "")],
            unchanged,
            limited("the broker's key"),
        ),
    ]
}

/// What Stalwart says of the user, an answer this release does not read and
/// Garrison's own setup.
fn decided() -> Vec<AtStalwart> {
    let not_set_up = "Garrison is not set up to check access rights; the broker's journal says why";
    let refused = "Garrison access is not authorized";
    let tenant = listed(
        "x:Account/get",
        &value!([{"id": "b", "@type": "User", "roles": {"@type": "Admin"},
                  "permissions": {"@type": "Inherit"}, "memberTenantId": "t1"}]),
    );
    let mut weak = granting();
    weak[3] = listed(
        "x:Role/get",
        &value!([{"id": "e", "roleIds": {}, "disabledPermissions": {},
                  "enabledPermissions": {"authenticate": true}}]),
    );
    vec![
        AtStalwart(
            "a token Stalwart no longer takes",
            vec![answer(401, "")],
            unchanged,
            ended(
                401,
                "Sign-in required again",
                "INFO Sign-in required again: The access token",
            ),
        ),
        AtStalwart(
            "an account of a tenant",
            vec![identity(), tenant],
            unchanged,
            ended(
                403,
                refused,
                "INFO Garrison access denied: This identity's account belongs",
            ),
        ),
        AtStalwart(
            "no eligible profile",
            weak,
            unchanged,
            ended(
                403,
                refused,
                "INFO Garrison access denied: This identity has no eligible",
            ),
        ),
        AtStalwart(
            "UserInfo in a form this release does not read",
            vec![answer(200, "<html>")],
            unchanged,
            kept(
                503,
                UNAVAILABLE,
                "ERROR Access rights cannot be checked: Stalwart answered in a form this release \
                 of Garrison does not read (UserInfo: The provider returned no stable subject)",
            ),
        ),
        AtStalwart(
            "the broker's key refused",
            vec![identity(), answer(401, "")],
            unchanged,
            kept(
                503,
                not_set_up,
                "ERROR Access rights cannot be checked: the account's rights",
            ),
        ),
        AtStalwart(
            "a policy that does not read",
            vec![identity()],
            mistyped,
            kept(
                503,
                not_set_up,
                "ERROR Access rights cannot be checked: Garrison access policy",
            ),
        ),
        AtStalwart(
            "the broker's key gone",
            vec![identity()],
            keyless,
            kept(
                503,
                not_set_up,
                "ERROR Access rights cannot be checked: the broker's API key",
            ),
        ),
    ]
}

/// Every kind of failure a check of a user's rights can meet at Stalwart
/// has its answer and a line in the broker's journal that names its cause:
/// what Stalwart says of the user (401, 403) ends the session and fails the
/// sign-in; everything else keeps the session and says at sign-in that
/// access could not be checked.
#[tokio::test]
async fn every_failure_at_stalwart_has_its_answer_and_its_line() {
    let _turn = journal().await;
    let mut wrong = Vec::new();
    for AtStalwart(name, answers, before, expected) in passing().into_iter().chain(decided()) {
        for problem in at_stalwart(&answers, before, &expected).await {
            wrong.push(format!("{name}: {problem}"));
        }
    }
    assert_eq!(wrong, Vec::<String>::new());
}

/// A kind of failure of the broker's own: the broker that stands for it,
/// and what it ends in.
struct AtTheBroker(&'static str, fn(&Path) -> Arc<dyn Broker>, Expected);

/// Every kind of failure of the broker's own has its answer and a line in
/// the web service's journal that names it: a broker that gives no answer,
/// whyever, is rights that cannot be checked just then; one that failed
/// inside is an internal error under the answer's reference; a grant this
/// web service cannot read refuses nobody; and a grant of another account
/// than the session's ends that session.
#[tokio::test]
async fn every_failure_of_the_brokers_own_has_its_answer_and_its_line() {
    let _turn = journal().await;
    let unanswered = |why: &str| {
        let line = format!("WARN The broker gave the web service no answer it can use ({why}");
        kept(503, UNAVAILABLE, &line)
    };
    let cases = [
        AtTheBroker(
            "its socket is gone",
            gone,
            unanswered("its socket could not be reached"),
        ),
        AtTheBroker(
            "it closes the connection unanswered",
            closing,
            unanswered("it closed the connection without an answer"),
        ),
        AtTheBroker(
            "its answer is no JSON",
            garbled,
            unanswered("its answer could not be read"),
        ),
        AtTheBroker(
            "a grant the web service does not read",
            ungranting,
            kept(
                502,
                "The broker returned an invalid authorization",
                "ERROR The broker answered a check of a user's rights with no grant",
            ),
        ),
        AtTheBroker(
            "it fails inside",
            failing,
            kept(
                500,
                "Internal error",
                "the broker answered HTTP 500: Internal broker error",
            ),
        ),
        AtTheBroker(
            "a grant of another account",
            another,
            Expected {
                status: 401,
                detail: "Sign-in required",
                ended: true,
                reason: None,
                line: "WARN The session of account 1 got a grant of account 2".to_owned(),
            },
        ),
    ];
    let mut wrong = Vec::new();
    for AtTheBroker(name, failing, expected) in cases {
        for problem in at_the_broker(failing, &expected).await {
            wrong.push(format!("{name}: {problem}"));
        }
    }
    assert_eq!(wrong, Vec::<String>::new());
}
