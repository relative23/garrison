//! How a session ends: at sign-out, when the policy refuses its user, when
//! its token turns out to be another user's, by its time, and with its
//! token in each case; and what survives a restart of the service.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::http::{Method, StatusCode};
use serde_json::json;
use support::{
    Client, ORIGIN, Setup, application, grant, refused, setup, setup_with, setup_with_cache,
};

const SESSION_COOKIE: &str = "__Host-garrison_session";

fn api(path: &str) -> String {
    format!("/api/{path}")
}

/// Each way a session of the user of `admin-token` ends.
#[derive(Clone, Copy, Debug)]
enum Ending {
    SignOut,
    Refused,
    AnotherAccount,
    SignedInAgain,
    TimeOver,
    /// Stalwart no longer takes the token, which so needs no revocation.
    TokenInvalid,
}

/// End the session of `setup`'s browser, whose CSRF token is `csrf`, so.
async fn end(setup: &mut Setup, csrf: &str, ending: Ending) {
    match ending {
        Ending::SignOut => {
            let headers = [("origin", ORIGIN), ("x-csrf-token", csrf)];
            let out = setup
                .client
                .send(Method::POST, &api("logout"), &headers, None)
                .await;
            assert_eq!(out.json(), json!({"ok": true}));
        }
        Ending::Refused | Ending::AnotherAccount | Ending::TokenInvalid => {
            let answer = match ending {
                Ending::Refused => refused(403, "Garrison access is not authorized"),
                Ending::AnotherAccount => Ok(grant("2", &["dashboard"], &[])),
                _ => refused(401, "Sign-in required again"),
            };
            setup.broker.set("admin-token", answer);
            assert!(
                setup
                    .client
                    .get(&api("status"))
                    .await
                    .status
                    .is_client_error()
            );
        }
        Ending::SignedInAgain => {
            setup.client.sign_in("code-viewer").await;
        }
        Ending::TimeOver => {
            let database = setup.config.web.state_directory.join("web.sqlite");
            let db = rusqlite::Connection::open(database).unwrap();
            db.execute(
                "UPDATE sessions SET expires_at = unixepoch() - 1 WHERE token = 'admin-token'",
                [],
            )
            .unwrap();
        }
    }
}

/// The rows that hold `admin-token`, and how many of them a cookie finds.
fn rows(setup: &Setup) -> (i64, i64) {
    let db =
        rusqlite::Connection::open(setup.config.web.state_directory.join("web.sqlite")).unwrap();
    db.query_row(
        "SELECT count(*), count(*) FILTER (WHERE expires_at > unixepoch()) FROM sessions \
         WHERE token = 'admin-token'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

/// However a session ends, no token of it is left that Stalwart still
/// takes: it is revoked, at once or in the web service's next round, and
/// where Stalwart did not answer, the session's row stays, ended, until a
/// round asks again and Stalwart answers. A token Stalwart no longer takes
/// needs none.
#[tokio::test]
async fn every_session_that_ends_takes_its_token_along() {
    for ending in [
        Ending::SignOut,
        Ending::Refused,
        Ending::AnotherAccount,
        Ending::SignedInAgain,
        Ending::TimeOver,
        Ending::TokenInvalid,
    ] {
        let revoking = !matches!(ending, Ending::TokenInvalid);
        let revoked = |setup: &Setup| setup.provider.revoked.lock().unwrap().clone();
        for away in [false, true] {
            let case = format!("{ending:?}, Stalwart away: {away}");
            let mut setup = setup_with_cache(Duration::ZERO);
            let csrf = setup.client.sign_in("code-admin").await;
            setup.provider.away.store(away, Ordering::SeqCst);
            end(&mut setup, &csrf, ending).await;
            assert_eq!(rows(&setup).1, 0, "{case}: no cookie finds it");
            let at_once = revoking && !away && !matches!(ending, Ending::TimeOver);
            let expected: Vec<String> = if at_once {
                vec!["admin-token".into()]
            } else {
                Vec::new()
            };
            assert_eq!(revoked(&setup), expected, "{case}");
            let pending = away && revoking;
            assert_eq!(setup.app.end_ended_sessions(), !pending, "{case}");
            if away {
                assert_eq!(revoked(&setup), Vec::<String>::new(), "{case}");
                assert_eq!(
                    rows(&setup).0,
                    i64::from(revoking),
                    "{case}: kept to ask again"
                );
                setup.provider.away.store(false, Ordering::SeqCst);
                assert!(setup.app.end_ended_sessions(), "{case}");
            }
            let expected: Vec<String> = if revoking {
                vec!["admin-token".into()]
            } else {
                Vec::new()
            };
            assert_eq!(revoked(&setup), expected, "{case}");
            assert_eq!(rows(&setup), (0, 0), "{case}");
        }
    }
}

/// The clock moved on `seconds`, or back where they are fewer than none:
/// every stored time a clock gave lies that much further behind it, and
/// one no clock gives stays.
fn clock_moved(setup: &Setup, seconds: i64) {
    let (first, last) = (
        garrison_core::time::Timestamp::MIN.as_second(),
        garrison_core::time::Timestamp::MAX.as_second(),
    );
    let db =
        rusqlite::Connection::open(setup.config.web.state_directory.join("web.sqlite")).unwrap();
    for column in ["created_at", "expires_at"] {
        db.execute(
            &format!(
                "UPDATE sessions SET {column} = {column} - ?1 WHERE {column} BETWEEN ?2 AND ?3"
            ),
            [seconds, first, last],
        )
        .unwrap();
    }
}

/// A sign-out that Stalwart does not answer the revocation of ends the
/// session for good: after the clock went back five minutes, a copy of
/// its cookie is answered as signed out, and the round revokes the token
/// once Stalwart answers again.
#[tokio::test]
async fn a_session_signed_out_unrevoked_stays_ended_when_the_clock_goes_back() {
    let mut setup = setup_with_cache(Duration::ZERO);
    let csrf = setup.client.sign_in("code-admin").await;
    // Signed in ten minutes ago.
    clock_moved(&setup, 600);
    let copy = setup.client.cookies.clone();
    setup.provider.away.store(true, Ordering::SeqCst);
    let headers = [("origin", ORIGIN), ("x-csrf-token", csrf.as_str())];
    let out = setup
        .client
        .send(Method::POST, &api("logout"), &headers, None)
        .await;
    assert_eq!(out.json(), json!({"ok": true}));
    clock_moved(&setup, -300);
    setup.client.cookies = copy;
    assert_eq!(
        setup.client.get(&api("status")).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        setup.client.get(&api("session")).await.json(),
        json!({"session": null})
    );
    assert_eq!(
        *setup.provider.revoked.lock().unwrap(),
        Vec::<String>::new()
    );
    setup.provider.away.store(false, Ordering::SeqCst);
    assert!(setup.app.end_ended_sessions());
    assert_eq!(*setup.provider.revoked.lock().unwrap(), ["admin-token"]);
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

/// With `web.bind_client_ip`, the session's cookie from another client
/// address is answered as if signed out, the switch row's question and the
/// page drawn for a path too, and the session goes on from its own address. A sign-out, which needs the
/// session's CSRF token, ends it from any address.
#[tokio::test]
async fn a_bound_session_is_signed_out_elsewhere_and_goes_on_at_its_address() {
    let mut setup = setup_with(Duration::from_secs(5), |config| {
        config.web.bind_client_ip = true;
    });
    let (home, away) = ("192.0.2.1", "198.51.100.7");
    let pages = setup.directory.path().join("static/pages");
    std::fs::create_dir_all(&pages).unwrap();
    std::fs::write(pages.join("sign-in.html"), "sign-in").unwrap();
    std::fs::write(pages.join("dashboard.html"), "the frame").unwrap();
    let client = &mut setup.client;
    let login = client.get_from("/auth/login", home).await;
    let location = url::Url::parse(login.header("location")).unwrap();
    let state = location
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let callback =
        format!("/auth/callback?state={state}&code=code-admin&iss=https%3A%2F%2Fmail.example.test");
    assert_eq!(
        client.get_from(&callback, home).await.header("location"),
        "/admin/"
    );
    let csrf = client.get_from(&api("session"), home).await.json()["session"]["csrf"]
        .as_str()
        .unwrap()
        .to_owned();
    let writing = [("origin", ORIGIN), ("x-csrf-token", csrf.as_str())];
    let on = json!({"theme": "system", "hiddenModules": [], "showSwitch": true});
    let saved = client
        .send_from(home, Method::PUT, &api("preferences"), &writing, Some(on))
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    for (address, signed_in) in [(away, false), (home, true)] {
        let session = client.get_from(&api("session"), address).await.json();
        assert_eq!(session["session"].is_object(), signed_in, "{address}");
        assert_eq!(
            client.get_from(&api("switch"), address).await.json(),
            json!({"show": signed_in}),
            "{address}"
        );
        let status = client.get_from(&api("status"), address).await.status;
        let expected = if signed_in {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        };
        assert_eq!(status, expected, "{address}");
        let page = client.get_from("/admin/", address).await.body;
        let expected = if signed_in { "the frame" } else { "sign-in" };
        assert_eq!(String::from_utf8_lossy(&page), expected, "{address}");
    }
    let cookies = client.cookies.clone();
    let out = client
        .send_from(away, Method::POST, &api("logout"), &writing, None)
        .await;
    assert_eq!(out.json(), json!({"ok": true}));
    client.cookies = cookies;
    let after = client.get_from(&api("session"), home).await.json();
    assert_eq!(after, json!({"session": null}));
    assert_eq!(*setup.provider.revoked.lock().unwrap(), ["admin-token"]);
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
