//! The web service's behaviour over HTTP.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::http::{Method, StatusCode};
use garrison_core::config::Database;
use serde_json::{Value, json};
use support::{Client, ORIGIN, application, grant, refused, setup, setup_with_cache, write_status};

const SESSION_COOKIE: &str = "__Host-garrison_session";

fn api(path: &str) -> String {
    format!("/api/{path}")
}

#[tokio::test]
async fn modules_are_enforced_on_the_server() {
    let mut setup = setup();
    setup.client.sign_in("code-viewer").await;
    let session = setup.client.get(&api("session")).await.json()["session"].clone();
    let ids: Vec<&str> = session["modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["dashboard", "logs"]);
    assert_eq!(session["actions"], json!([]));
    assert_eq!(
        session["links"]["other"],
        json!({"webmail": "https://mail.example.test/"})
    );
    for denied in [
        "deliveries",
        "actions",
        "sessions",
        "attacks",
        "destinations",
    ] {
        let answer = setup.client.get(&api(denied)).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{denied}");
        assert_eq!(
            answer.json(),
            json!({"detail": "This Garrison module is not authorized"})
        );
    }
}

fn observation(id: &str, modules: &[&str]) -> Value {
    json!({
        "id": id, "provider": "p", "title": "t", "modules": modules, "evidence": "process",
        "state": "ok", "checkedAt": "2000-01-01T00:00:00+00:00", "source": "s", "kind": "details",
        "scope": "", "fields": [], "table": null, "findings": [], "value": {}, "maxAge": 60,
    })
}

#[tokio::test]
async fn the_status_is_filtered_per_module() {
    let mut setup = setup();
    write_status(
        &setup.config.database(Database::Status),
        &json!([
            observation("a", &["dashboard", "backups"]),
            observation("b", &["backups"])
        ]),
        &json!([{"provider": "x", "error": "crashed"}]),
    );
    setup.client.sign_in("code-viewer").await;
    let status = setup.client.get(&api("status")).await.json();
    let ids: Vec<&str> = status["observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["a"]);
    assert_eq!(status["observations"][0]["modules"], json!(["dashboard"])); // Ungranted names removed.
    assert_eq!(status["observations"][0]["stale"], true);
    assert_eq!(
        status["providerErrors"],
        json!([]),
        "only the services module sees provider errors"
    );
}

#[tokio::test]
async fn writes_need_origin_and_csrf() {
    let mut setup = setup();
    let csrf = setup.client.sign_in("code-admin").await;
    let body = json!({"theme": "dark", "hiddenModules": ["spam"]});
    let put = |headers: &'static [(&'static str, &'static str)]| headers;
    let none = setup
        .client
        .send(
            Method::PUT,
            &api("preferences"),
            put(&[]),
            Some(body.clone()),
        )
        .await;
    assert_eq!(none.status, StatusCode::FORBIDDEN);
    let evil = [
        ("origin", "https://evil.example"),
        ("x-csrf-token", csrf.as_str()),
    ];
    assert_eq!(
        setup
            .client
            .send(Method::PUT, &api("preferences"), &evil, Some(body.clone()))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let good = [("origin", ORIGIN), ("x-csrf-token", csrf.as_str())];
    let ok = setup
        .client
        .send(Method::PUT, &api("preferences"), &good, Some(body.clone()))
        .await;
    // An interface that does not know the switch setting leaves it on.
    let mut saved = body.clone();
    saved["showSwitch"] = json!(true);
    assert_eq!(ok.json(), saved);
    assert_eq!(
        setup.client.get(&api("session")).await.json()["session"]["preferences"],
        saved
    );
    let plain = [
        ("origin", ORIGIN),
        ("x-csrf-token", csrf.as_str()),
        ("content-type", "text/plain"),
    ];
    let text = setup
        .client
        .send(Method::PUT, &api("preferences"), &plain, None)
        .await;
    assert_eq!(text.status, StatusCode::BAD_REQUEST, "only JSON bodies");
    let bad = json!({"theme": "dark", "hiddenModules": ["nonexistent"]});
    assert_eq!(
        setup
            .client
            .send(Method::PUT, &api("preferences"), &good, Some(bad))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let submit = setup
        .client
        .send(
            Method::POST,
            &api("actions"),
            &good,
            Some(json!({"action": "run_monitor", "requestId": "0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b", "confirmation": "RUN HEALTH CHECKS"})),
        )
        .await;
    assert_eq!(submit.status, StatusCode::ACCEPTED);
    let calls = setup.broker.calls.lock().unwrap();
    let sent = calls.iter().find(|call| call["op"] == "submit").unwrap();
    let keys: Vec<&String> = sent.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["op", "token", "action", "requestId", "confirmation"]); // No actor field.
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

#[tokio::test]
async fn security_headers_and_interface_routes() {
    let mut setup = setup();
    let page = setup.client.get("/admin/logs").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&page.body).contains("garrison"));
    assert!(
        page.header("content-security-policy")
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(page.header("cache-control"), "no-store");
    assert_eq!(page.header("x-frame-options"), "DENY");
    let asset = setup.client.get("/admin/assets/app-abc.js").await;
    assert!(asset.header("cache-control").contains("immutable"));
    assert!(asset.header("content-type").starts_with("text/javascript"));
    // An encoded traversal reaches the handler as "../index.html" and is refused.
    assert_eq!(
        setup
            .client
            .get("/admin/assets/..%2Findex.html")
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        setup.client.get(&api("unknown")).await.json(),
        json!({"detail": "Not found"})
    );
    // Below /admin/ every other path is a view of the interface; outside it
    // nothing is.
    let view = setup.client.get("/admin/elsewhere").await;
    assert_eq!(view.status, StatusCode::OK);
    assert!(view.header("content-type").starts_with("text/html"));
    for path in ["/elsewhere", "/auth/unknown", "/admin/assets/missing.js"] {
        let missing = setup.client.get(path).await;
        assert_eq!(
            (missing.status, missing.json()),
            (StatusCode::NOT_FOUND, json!({"detail": "Not found"})),
            "{path}"
        );
    }
    // The root leads to the interface, and so does /admin without the slash.
    for (path, status) in [
        ("/", StatusCode::FOUND),
        ("/admin", StatusCode::PERMANENT_REDIRECT),
    ] {
        let answer = setup.client.get(path).await;
        assert_eq!(
            (answer.status, answer.header("location")),
            (status, "/admin/")
        );
    }
    let wrong = setup
        .client
        .send(Method::POST, &api("status"), &[], None)
        .await;
    assert_eq!(
        (wrong.status, wrong.json()),
        (
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"detail": "Method Not Allowed"})
        )
    );
}

#[tokio::test]
async fn other_host_names_are_sent_to_the_own_origin() {
    let mut setup = setup();
    for host in ["stalwart.example.test", "admin.example.test.evil.example"] {
        let answer = setup
            .client
            .send(Method::GET, "/admin/logs?a=1", &[("host", host)], None)
            .await;
        assert_eq!(answer.status, StatusCode::PERMANENT_REDIRECT, "{host}");
        assert_eq!(
            answer.header("location"),
            "https://admin.example.test/admin/logs?a=1"
        );
        assert_eq!(answer.header("x-frame-options"), "DENY");
    }
    for host in [
        "admin.example.test",
        "ADMIN.example.test:443",
        "127.0.0.1:8091",
        "localhost:8091",
        "[::1]:8091",
    ] {
        let answer = setup
            .client
            .send(Method::GET, "/admin/logs", &[("host", host)], None)
            .await;
        assert_eq!(answer.status, StatusCode::OK, "{host}");
    }
}

#[tokio::test]
async fn the_switch_script_for_the_stalwart_webui() {
    let mut setup = setup();
    let script = setup.client.get("/admin/stalwart-switch.js").await;
    assert_eq!(script.status, StatusCode::OK);
    assert!(script.header("content-type").starts_with("text/javascript"));
    // The Stalwart WebUI lives on its own origin; the tag loads it with CORS.
    assert_eq!(
        script.header("access-control-allow-origin"),
        "https://mail.example.test"
    );
    assert_eq!(script.header("cache-control"), "no-store");
}

#[tokio::test]
async fn parameters_are_checked_after_the_caller() {
    let mut setup = setup();
    assert_eq!(
        setup.client.get(&api("events?limit=500")).await.status,
        StatusCode::UNAUTHORIZED
    );
    setup.client.sign_in("code-admin").await;
    for query in [
        "events?limit=500",
        "events?limit=x",
        "events?before=",
        "deliveries?limit=51",
        "metrics?period=1y",
    ] {
        let answer = setup.client.get(&api(query)).await;
        assert_eq!(
            (answer.status, answer.json()),
            (
                StatusCode::BAD_REQUEST,
                json!({"detail": "Invalid request parameters"})
            ),
            "{query}"
        );
    }
    assert_eq!(
        setup.client.get(&api("events?category=nope")).await.json(),
        json!({"detail": "Unknown event category or type"})
    );
    assert_eq!(
        setup.client.get(&api("events")).await.json(),
        json!({"detail": "The event history is not available yet"})
    );
    let coverage = setup.client.get(&api("coverage")).await.json();
    assert_eq!(
        (
            coverage["available"].clone(),
            coverage["eventCount"].clone()
        ),
        (json!(false), json!(0))
    );
    assert_eq!(
        setup.client.get(&api("deliveries/abc")).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        setup.client.get(&api("metrics")).await.json(),
        json!({"detail": "Metric history is not available yet"})
    );
    let custom = setup
        .client
        .get(&api("metrics?period=custom&from=10&to=5"))
        .await;
    assert_eq!(
        custom.json()["detail"],
        "A custom range needs from < to, at most 90 days, not in the future"
    );
    let catalog = setup.client.get(&api("actions")).await;
    assert_eq!(catalog.json(), json!({"actions": [], "jobs": []}));
    assert_eq!(
        setup.client.get(&api("actions/jobs/nothex")).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn the_client_metadata_names_the_callback() {
    let mut setup = setup();
    let document = setup.client.get("/oauth-client.json").await.json();
    assert_eq!(
        document["client_id"],
        "https://admin.example.test/oauth-client.json"
    );
    assert_eq!(
        document["redirect_uris"],
        json!(["https://admin.example.test/auth/callback"])
    );
    let cross = setup
        .client
        .send(
            Method::GET,
            "/auth/login",
            &[("sec-fetch-site", "cross-site")],
            None,
        )
        .await;
    assert_eq!(cross.header("location"), "/admin/?login_error=cross-site");
    let _ = Arc::clone(&setup.broker);
}

#[tokio::test]
async fn every_answer_has_a_reference_and_hides_an_internal_cause() {
    let mut setup = setup();
    let first = setup.client.get(&api("session")).await;
    let reference = first.header("x-request-id").to_owned();
    assert!(
        reference.len() == 12 && reference.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{reference}"
    );
    let second = setup.client.get(&api("session")).await;
    assert_ne!(second.header("x-request-id"), reference);
    setup.client.sign_in("code-admin").await;
    // A status database that is no database fails inside the service.
    let status = setup.config.database(Database::Status);
    std::fs::create_dir_all(status.parent().unwrap()).unwrap();
    std::fs::write(&status, b"not a database").unwrap();
    let failed = setup.client.get(&api("status")).await;
    assert_eq!(failed.header("x-request-id").len(), 12);
    assert_eq!(
        (failed.status, failed.json()),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"detail": "Internal error"})
        )
    );
}
