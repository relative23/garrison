//! How a session ends: at sign-out, when the policy refuses its user, when
//! its token turns out to be another user's, and what survives a restart of
//! the service.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use serde_json::json;
use support::{Client, ORIGIN, application, grant, refused, setup, setup_with_cache};

const SESSION_COOKIE: &str = "__Host-garrison_session";

fn api(path: &str) -> String {
    format!("/api/{path}")
}

#[tokio::test]
async fn revoked_rights_end_the_session_but_outages_do_not() {
    let mut setup = setup_with_cache(Duration::ZERO);
    setup.client.sign_in("code-admin").await;
    setup.broker.set("admin-token", refused(503, "unavailable"));
    assert_eq!(
        setup.client.get(&api("status")).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    // An outage is no sign-out: the session is not reported missing.
    assert_eq!(
        setup.client.get(&api("session")).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    setup
        .broker
        .set("admin-token", Ok(grant("1", &["dashboard"], &[])));
    assert_eq!(
        setup.client.get(&api("status")).await.status,
        StatusCode::OK
    );
    setup.broker.set(
        "admin-token",
        refused(403, "Garrison access is not authorized"),
    );
    assert_eq!(
        setup.client.get(&api("status")).await.status,
        StatusCode::FORBIDDEN
    );
    setup
        .broker
        .set("admin-token", Ok(grant("1", &["dashboard"], &[])));
    assert_eq!(
        setup.client.get(&api("status")).await.status,
        StatusCode::UNAUTHORIZED
    ); // The session is gone.
    // Its token was good for Stalwart still, and is revoked with it.
    assert_eq!(*setup.provider.revoked.lock().unwrap(), ["admin-token"]);
}

#[tokio::test]
async fn a_session_whose_token_became_another_users_ends_with_the_token_revoked() {
    let mut setup = setup_with_cache(Duration::ZERO);
    setup.client.sign_in("code-admin").await;
    setup
        .broker
        .set("admin-token", Ok(grant("2", &["dashboard"], &[])));
    assert_eq!(
        setup.client.get(&api("status")).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(*setup.provider.revoked.lock().unwrap(), ["admin-token"]);
    // A token Stalwart no longer takes needs no revocation.
    let mut expired = setup_with_cache(Duration::ZERO);
    expired.client.sign_in("code-admin").await;
    expired
        .broker
        .set("admin-token", refused(401, "Sign-in required again"));
    assert_eq!(
        expired.client.get(&api("status")).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert!(expired.provider.revoked.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_logout_that_could_not_end_the_session_says_so() {
    let mut setup = setup();
    let csrf = setup.client.sign_in("code-admin").await;
    let database = setup.config.web.state_directory.join("web.sqlite");
    // Something else holds the database: the session's row cannot be deleted.
    let holder = rusqlite::Connection::open(&database).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    let headers = [("origin", ORIGIN), ("x-csrf-token", csrf.as_str())];
    let out = setup
        .client
        .send(Method::POST, &api("logout"), &headers, None)
        .await;
    holder.execute_batch("ROLLBACK").unwrap();
    // No "ok" for a session that is still there, and the cookie stays, so
    // that the user can try again.
    assert_eq!(out.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        out.json(),
        json!({"detail": "The session could not be ended here; sign out again."})
    );
    assert_eq!(out.header("set-cookie"), "");
    // The token was revoked all the same: a copy of the cookie then holds a
    // session whose token Stalwart no longer takes.
    assert_eq!(*setup.provider.revoked.lock().unwrap(), ["admin-token"]);
    assert!(setup.client.get(&api("session")).await.json()["session"].is_object());
    // The second attempt ends it.
    let out = setup
        .client
        .send(Method::POST, &api("logout"), &headers, None)
        .await;
    assert_eq!(out.json(), json!({"ok": true}));
    assert_eq!(
        setup.client.get(&api("session")).await.json(),
        json!({"session": null})
    );
}

#[tokio::test]
async fn sessions_survive_a_service_restart() {
    let mut setup = setup();
    setup.client.sign_in("code-admin").await;
    let restarted = application(
        &setup.config,
        &setup.broker,
        &setup.provider,
        Duration::from_secs(5),
    );
    let mut other = Client::new(restarted);
    other.cookies = setup.client.cookies.clone();
    assert!(other.get(&api("session")).await.json()["session"].is_object());
    drop(setup.directory);
}

#[tokio::test]
async fn logout_revokes_the_token() {
    let mut setup = setup();
    let csrf = setup.client.sign_in("code-admin").await;
    // A cross-site logout without the CSRF token is refused.
    assert_eq!(
        setup
            .client
            .send(Method::POST, &api("logout"), &[("origin", ORIGIN)], None)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let out = setup
        .client
        .send(
            Method::POST,
            &api("logout"),
            &[("origin", ORIGIN), ("x-csrf-token", csrf.as_str())],
            None,
        )
        .await;
    assert_eq!(out.json(), json!({"ok": true}));
    let cookie = out.header("set-cookie");
    assert!(
        cookie.starts_with(SESSION_COOKIE)
            && cookie.contains("Max-Age=0")
            && cookie.contains("Secure"),
        "{cookie}"
    );
    assert_eq!(*setup.provider.revoked.lock().unwrap(), ["admin-token"]);
    assert_eq!(
        setup.client.get(&api("session")).await.json(),
        json!({"session": null})
    );
}
