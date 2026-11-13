//! Sign-in over HTTP: PKCE, the login cookie, the issuer and refused identities.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

mod support;

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use garrison_web::attempts::BUDGET;
use garrison_web::routes::auth::challenge;
use serde_json::json;
use sha2::{Digest, Sha256};
use support::{Client, refused, setup};

const STATE_COOKIE: &str = "__Host-garrison_login";

fn api(path: &str) -> String {
    format!("/api/{path}")
}

#[tokio::test]
async fn sign_in_uses_pkce_a_browser_bound_state_and_the_issuer() {
    let mut setup = setup();
    let login = setup.client.get("/auth/login").await;
    let cookie = login.header("set-cookie").to_owned();
    for attribute in ["HttpOnly", "Max-Age=600", "Path=/;", "Secure"] {
        assert!(cookie.contains(attribute), "{cookie}");
    }
    let location = url::Url::parse(login.header("location")).unwrap();
    let query: HashMap<String, String> = location.query_pairs().into_owned().collect();
    let value = setup.client.cookies[STATE_COOKIE].clone();
    let (state, verifier) = value.split_once('.').unwrap();
    assert_eq!(query["state"], state);
    // Only the challenge goes to the provider's login page.
    assert_eq!(query["code_challenge"], challenge(verifier));
    assert!(!login.header("location").contains(verifier));
    let callback = |state: &str, issuer: &str| {
        format!("/auth/callback?state={state}&code=code-admin&iss={issuer}")
    };
    let issuer = "https%3A%2F%2Fmail.example.test";
    let short = format!("{state}.{}", &verifier[..42]);
    // Another state, a cookie without a verifier, a malformed verifier, another issuer.
    for (cookie, state, issuer) in [
        (value.as_str(), "other", issuer),
        (state, state, issuer),
        (short.as_str(), state, issuer),
        (value.as_str(), state, "https%3A%2F%2Fevil.example"),
    ] {
        setup
            .client
            .cookies
            .insert(STATE_COOKIE.into(), cookie.into());
        let refused = setup.client.get(&callback(state, issuer)).await;
        assert!(
            refused.header("location").ends_with("login_error=1"),
            "{cookie}"
        );
        assert!(refused.header("set-cookie").contains("Max-Age=0"));
    }
    assert!(setup.provider.verifiers.lock().unwrap().is_empty());
    setup
        .client
        .cookies
        .insert(STATE_COOKIE.into(), value.clone());
    let signed_in = setup.client.get(&callback(state, issuer)).await;
    assert_eq!(signed_in.header("location"), "/admin/");
    assert_eq!(*setup.provider.verifiers.lock().unwrap(), [verifier]);
    assert!(!setup.client.cookies.contains_key(STATE_COOKIE));
}

#[tokio::test]
async fn anonymous_sign_in_starts_lock_nobody_out() {
    let mut setup = setup();
    // Anyone who reaches nginx can start sign-ins; none of them may block the next user.
    for _ in 0..300 {
        setup.client.get("/auth/login").await;
    }
    setup.client.cookies.clear();
    setup.client.sign_in("code-admin").await;
}

#[tokio::test]
async fn a_rejected_identity_gets_no_session_and_its_token_is_revoked() {
    let mut setup = setup();
    setup.broker.set(
        "bad-token",
        refused(403, "Garrison access is not authorized"),
    );
    let login = setup.client.get("/auth/login").await;
    let location = url::Url::parse(login.header("location")).unwrap();
    let state = location
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let result = setup
        .client
        .get(&format!(
            "/auth/callback?state={state}&code=unknown&iss=https%3A%2F%2Fmail.example.test"
        ))
        .await;
    assert!(result.header("location").ends_with("login_error=1"));
    assert_eq!(*setup.provider.revoked.lock().unwrap(), ["bad-token"]);
    assert_eq!(
        setup.client.get(&api("session")).await.json(),
        json!({"session": null})
    );
}

#[tokio::test]
async fn a_code_stalwart_refuses_or_cannot_exchange_gets_no_session() {
    let mut setup = setup();
    for code in ["code-expired", "code-outage"] {
        let login = setup.client.get("/auth/login").await;
        let location = url::Url::parse(login.header("location")).unwrap();
        let state = location
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let result = setup
            .client
            .get(&format!(
                "/auth/callback?state={state}&code={code}&iss=https%3A%2F%2Fmail.example.test"
            ))
            .await;
        assert!(
            result.header("location").ends_with("login_error=1"),
            "{code}"
        );
        assert_eq!(
            setup.client.get(&api("session")).await.json(),
            json!({"session": null}),
            "{code}"
        );
    }
    // No token was issued, so none is revoked.
    assert!(setup.provider.revoked.lock().unwrap().is_empty());
}

#[tokio::test]
async fn code_exchanges_per_network_are_limited() {
    let mut setup = setup();
    setup.client.get("/auth/login").await;
    let value = setup.client.cookies[STATE_COOKIE].clone();
    let state = value.split_once('.').unwrap().0.to_owned();
    let callback =
        format!("/auth/callback?state={state}&code=code-admin&iss=https%3A%2F%2Fmail.example.test");
    // One cookie can be replayed; only the budget keeps it from Stalwart.
    let budget = usize::try_from(BUDGET).unwrap();
    for round in 0..budget + 2 {
        setup
            .client
            .cookies
            .insert(STATE_COOKIE.into(), value.clone());
        let answer = setup.client.get(&callback).await;
        let limited = answer.header("location").ends_with("login_error=rate");
        assert_eq!(limited, round >= budget, "round {round}");
    }
    assert_eq!(setup.provider.verifiers.lock().unwrap().len(), budget);
}

/// The provider's sign-in URL parameters of a fresh login.
async fn login(client: &mut Client) -> HashMap<String, String> {
    let answer = client.get("/auth/login").await;
    let location = url::Url::parse(answer.header("location")).unwrap();
    location.query_pairs().into_owned().collect()
}

#[tokio::test]
async fn the_challenge_is_the_sha256_of_the_verifier() {
    let mut setup = setup();
    let query = login(&mut setup.client).await;
    let callback = format!(
        "/auth/callback?state={}&code=code-admin&iss=https%3A%2F%2Fmail.example.test",
        query["state"]
    );
    setup.client.get(&callback).await;
    let verifier = setup.provider.verifiers.lock().unwrap()[0].clone();
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    assert_eq!(query["code_challenge"], expected);
}

#[tokio::test]
async fn the_callback_needs_the_state_in_both_url_and_cookie() {
    let refused = "/admin/?login_error=1";
    let issuer = "iss=https%3A%2F%2Fmail.example.test";
    let mut setup = setup();
    login(&mut setup.client).await;
    let no_state = format!("/auth/callback?code=code-admin&{issuer}");
    assert_eq!(
        setup.client.get(&no_state).await.header("location"),
        refused
    );

    let state = login(&mut setup.client).await["state"].clone();
    setup.client.cookies.clear();
    let no_cookie = format!("/auth/callback?state={state}&code=code-admin&{issuer}");
    assert_eq!(
        setup.client.get(&no_cookie).await.header("location"),
        refused
    );

    login(&mut setup.client).await;
    let other = format!("/auth/callback?state=other&code=code-admin&{issuer}");
    assert_eq!(setup.client.get(&other).await.header("location"), refused);
    assert!(setup.provider.verifiers.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_session_lasts_the_configured_minutes_at_most() {
    let mut setup = setup();
    let state = login(&mut setup.client).await["state"].clone();
    let callback =
        format!("/auth/callback?state={state}&code=code-admin&iss=https%3A%2F%2Fmail.example.test");
    let answer = setup.client.get(&callback).await;
    let minutes = setup.config.web.session_minutes;
    let session = answer
        .headers
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap())
        .find(|value| value.starts_with("__Host-garrison_session="))
        .unwrap();
    assert!(
        session.contains(&format!("Max-Age={}", minutes * 60)),
        "{session}"
    );
}
