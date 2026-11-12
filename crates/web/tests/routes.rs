//! Sign-in details and the exact limits of every route's parameters.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

mod support;

use std::collections::HashMap;

use axum::http::{Method, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use garrison_core::config::Database;
use garrison_core::time;
use garrison_ingest::store::{EventStore, Limits};
use serde_json::json;
use sha2::{Digest, Sha256};
use support::{Client, ORIGIN, setup, write_status};

fn api(path: &str) -> String {
    format!("/api/{path}")
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

#[tokio::test]
async fn custom_metric_ranges_are_bounded() {
    let mut setup = setup();
    setup.client.sign_in("code-admin").await;
    let now = time::now().as_second();
    let refused = "A custom range needs from < to, at most 90 days, not in the future";
    let longest = 90 * 86400;
    for (from, to, accepted) in [
        (now - longest, now, true),
        (now - longest - 1, now, false),
        (now - 1, now, true),
        (now, now, false),
        (now - 60, now + 50, true),
        (now, now + 3600, false),
    ] {
        let answer = setup
            .client
            .get(&api(&format!("metrics?period=custom&from={from}&to={to}")))
            .await;
        let detail = answer.json()["detail"].clone();
        assert_eq!(detail != refused, accepted, "{from}..{to}: {detail}");
    }
    let negative = setup
        .client
        .get(&api("metrics?period=custom&from=-1&to=5"))
        .await;
    assert_eq!(negative.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_custom_range_may_start_at_the_epoch() {
    let mut setup = setup();
    setup.client.sign_in("code-admin").await;
    write_status(
        &setup.config.database(Database::Status),
        &json!([]),
        &json!([]),
    );
    let epoch = setup
        .client
        .get(&api("metrics?period=custom&from=0&to=60"))
        .await;
    assert_eq!(epoch.status, StatusCode::OK, "{}", epoch.json());
    let empty = setup
        .client
        .get(&api("metrics?period=custom&from=0&to=0"))
        .await;
    assert_eq!(
        empty.json()["detail"],
        "A custom range needs from < to, at most 90 days, not in the future"
    );
}

#[tokio::test]
async fn lists_show_50_events_and_25_deliveries_or_sessions_by_default() {
    let mut setup = setup();
    setup.client.sign_in("code-admin").await;
    let store = EventStore::open(
        &setup.config.database(Database::Events),
        Limits::new(30, 1000, 64 << 20),
    )
    .unwrap();
    let now = time::now().as_second();
    let at = time::isoformat(time::now());
    let batch: Vec<_> = (1..=30_u64)
        .flat_map(|index| {
            let event = |offset: u64, kind: &str, data| {
                json!({"id": (1_000_000 + index * 2 + offset).to_string(), "createdAt": at, "type": kind, "data": data})
            };
            [
                event(0, "queue.message-queued", json!({"queueId": index, "to": ["a@example.test"]})),
                event(1, "smtp.connection-start", json!({"spanId": index, "remoteIp": "192.0.2.1"})),
            ]
        })
        .collect();
    store.ingest(&batch, now).unwrap();
    let count = |answer: serde_json::Value| answer["items"].as_array().unwrap().len();
    assert_eq!(count(setup.client.get(&api("events")).await.json()), 50);
    assert_eq!(count(setup.client.get(&api("deliveries")).await.json()), 25);
    assert_eq!(count(setup.client.get(&api("sessions")).await.json()), 25);
}

#[tokio::test]
async fn a_period_ends_at_the_current_minute() {
    let mut setup = setup();
    setup.client.sign_in("code-admin").await;
    write_status(
        &setup.config.database(Database::Status),
        &json!([]),
        &json!([]),
    );
    for (period, seconds) in [
        ("24h", 86400),
        ("7d", 7 * 86400),
        ("30d", 30 * 86400),
        ("90d", 90 * 86400),
    ] {
        let before = time::now().as_second();
        let answer = setup
            .client
            .get(&api(&format!("metrics?period={period}")))
            .await
            .json();
        let (from, to) = (
            answer["from"].as_i64().unwrap(),
            answer["to"].as_i64().unwrap(),
        );
        assert_eq!(to % 60, 0, "{period}");
        assert!((before - 60..=before).contains(&to), "{period}: {to}");
        assert_eq!(to - from, seconds, "{period}");
    }
}

#[tokio::test]
async fn event_filters_have_exact_limits() {
    let mut setup = setup();
    setup.client.sign_in("code-admin").await;
    let unavailable = "The event history is not available yet";
    let long = |count: usize| "x".repeat(count);
    for (query, accepted) in [
        (format!("events?search={}", long(200)), true),
        (format!("events?search={}", long(201)), false),
        (format!("events?category={}", long(40)), false),
        (format!("events?category={}", long(41)), false),
        ("events?category=auth".to_owned(), true),
        (format!("events?type={}", long(101)), false),
        ("events?type=auth.failed".to_owned(), true),
        ("events?type=auth.unknown".to_owned(), false),
        ("events?limit=100".to_owned(), true),
        ("events?limit=0".to_owned(), false),
        ("events?since=0&until=253402300799".to_owned(), true),
        ("events?until=253402300800".to_owned(), false),
        ("events?since=-1".to_owned(), false),
        (format!("events?before={}", "1".repeat(64)), true),
        (format!("events?before={}", "1".repeat(65)), false),
        ("events?before=12:34".to_owned(), true),
        ("events?before=12a".to_owned(), false),
        ("deliveries?limit=50".to_owned(), true),
        ("deliveries?limit=51".to_owned(), false),
        ("sessions?limit=1".to_owned(), true),
        ("attacks".to_owned(), true),
        ("attacks?period=30d".to_owned(), true),
        ("attacks?period=1y".to_owned(), false),
        ("attacks?since=0".to_owned(), false),
        ("destinations?period=7d".to_owned(), true),
        ("destinations?period=90d".to_owned(), false),
    ] {
        let answer = setup.client.get(&api(&query)).await;
        let available = answer.json()["detail"] == unavailable;
        assert_eq!(available, accepted, "{query}: {}", answer.json());
    }
}

#[tokio::test]
async fn job_ids_are_32_lowercase_hex_digits() {
    let mut setup = setup();
    setup.client.sign_in("code-admin").await;
    let valid = "0123456789abcdef".repeat(2);
    let job = setup
        .client
        .get(&api(&format!("actions/jobs/{valid}")))
        .await;
    assert_eq!(
        (job.status, job.json()["id"].clone()),
        (StatusCode::OK, json!(valid))
    );
    for invalid in [
        "0123456789ABCDEF0123456789abcdef".to_owned(),
        valid[..31].to_owned(),
        format!("{valid}0"),
        "g".repeat(32),
    ] {
        let answer = setup
            .client
            .get(&api(&format!("actions/jobs/{invalid}")))
            .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{invalid}");
    }
}

#[tokio::test]
async fn action_requests_have_length_limits() {
    let mut setup = setup();
    let csrf = setup.client.sign_in("code-admin").await;
    let headers = [("origin", ORIGIN), ("x-csrf-token", csrf.as_str())];
    let request = |action: &str, request_id: &str, confirmation: &str| json!({"action": action, "requestId": request_id, "confirmation": confirmation});
    let id = "0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b";
    for (body, accepted) in [
        (request("run_monitor", id, "RUN"), true),
        (request(&"a".repeat(65), id, "RUN"), false),
        (request("run_monitor", &format!("{id}x"), "RUN"), false),
        (request("run_monitor", id, &"R".repeat(65)), false),
    ] {
        let answer = setup
            .client
            .send(Method::POST, &api("actions"), &headers, Some(body))
            .await;
        assert_eq!(answer.status.is_success(), accepted, "{}", answer.json());
    }
}

#[tokio::test]
async fn assets_go_out_in_the_best_coding_the_browser_accepts() {
    let setup = setup();
    let assets = setup.directory.path().join("static/assets");
    let mut client = setup.client;
    for (name, body) in [
        ("app.js", "plain"),
        ("app.js.br", "brotli"),
        ("app.js.gz", "gzip"),
        ("only.css", "plain"),
    ] {
        std::fs::write(assets.join(name), body).unwrap();
    }
    for (accepted, coding, body) in [
        ("gzip, deflate, br, zstd", "br", "brotli"),
        ("GZIP", "gzip", "gzip"),
        ("br;q=0, gzip;q=0.5", "gzip", "gzip"),
        ("*", "br", "brotli"),
        ("*;q=0, gzip", "gzip", "gzip"),
        ("identity", "", "plain"),
        ("", "", "plain"),
    ] {
        let answer = client
            .send(
                Method::GET,
                "/admin/assets/app.js",
                &[("accept-encoding", accepted)],
                None,
            )
            .await;
        assert_eq!(answer.header("content-encoding"), coding, "{accepted}");
        assert_eq!(answer.body, body.as_bytes(), "{accepted}");
        assert_eq!(
            answer.header("content-type"),
            "text/javascript; charset=utf-8",
            "{accepted}"
        );
        assert_eq!(answer.header("vary"), "accept-encoding", "{accepted}");
    }
    // Without a copy, the asset itself goes out.
    let answer = client
        .send(
            Method::GET,
            "/admin/assets/only.css",
            &[("accept-encoding", "br, gzip")],
            None,
        )
        .await;
    assert_eq!(answer.header("content-encoding"), "");
    assert_eq!(answer.body, b"plain");
}

#[tokio::test]
async fn interface_files_carry_their_media_type() {
    let setup = setup();
    let assets = setup.directory.path().join("static/assets");
    let mut client = setup.client;
    for (name, media) in [
        ("a.html", "text/html; charset=utf-8"),
        ("a.js", "text/javascript; charset=utf-8"),
        ("a.mjs", "text/javascript; charset=utf-8"),
        ("a.css", "text/css; charset=utf-8"),
        ("a.json", "application/json"),
        ("a.map", "application/json"),
        ("a.svg", "image/svg+xml"),
        ("a.png", "image/png"),
        ("a.ico", "image/vnd.microsoft.icon"),
        ("a.woff2", "font/woff2"),
        ("a.woff", "font/woff"),
        ("a.txt", "text/plain; charset=utf-8"),
        ("a.bin", "application/octet-stream"),
    ] {
        std::fs::write(assets.join(name), "x").unwrap();
        let answer = client.get(&format!("/admin/assets/{name}")).await;
        assert_eq!(answer.header("content-type"), media, "{name}");
    }
    std::fs::write(assets.join("large.js"), vec![b' '; 2 * 1024 * 1024]).unwrap();
    let large = client.get("/admin/assets/large.js").await;
    assert_eq!(
        large.status,
        StatusCode::OK,
        "files up to 16 MiB are served"
    );
    let favicon = client.get("/admin/favicon.svg").await;
    assert_eq!(favicon.status, StatusCode::NOT_FOUND);
    std::fs::write(setup.directory.path().join("static/favicon.svg"), "<svg/>").unwrap();
    let favicon = client.get("/admin/favicon.svg").await;
    assert_eq!(
        (favicon.status, favicon.body),
        (StatusCode::OK, b"<svg/>".to_vec())
    );
}

#[tokio::test]
async fn the_stalwart_webui_may_read_the_switch_setting_and_nothing_else() {
    let mut setup = setup();
    // Without a session the row stays.
    let anonymous = setup.client.get(&api("switch")).await;
    assert_eq!(anonymous.json(), json!({"show": true}));
    assert_eq!(
        anonymous.header("access-control-allow-origin"),
        "https://mail.example.test"
    );
    assert_eq!(anonymous.header("access-control-allow-credentials"), "true");
    let csrf = setup.client.sign_in("code-admin").await;
    assert_eq!(
        setup.client.get(&api("switch")).await.json(),
        json!({"show": true})
    );
    let off = json!({"theme": "system", "hiddenModules": [], "showSwitch": false});
    let headers = [("origin", ORIGIN), ("x-csrf-token", csrf.as_str())];
    let saved = setup
        .client
        .send(Method::PUT, &api("preferences"), &headers, Some(off))
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    assert_eq!(
        setup.client.get(&api("switch")).await.json(),
        json!({"show": false})
    );
    let session = setup.client.get(&api("session")).await;
    assert_eq!(
        session.json()["session"]["preferences"]["showSwitch"],
        false
    );
    assert!(session.headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn one_delivery_and_one_session_in_detail() {
    let mut setup = setup();
    let store = EventStore::open(
        &setup.config.database(Database::Events),
        Limits::new(30, 1000, 64 << 20),
    )
    .unwrap();
    let at = time::isoformat(time::now());
    let batch = [
        json!({"id": "2000001", "createdAt": at, "type": "queue.message-queued",
               "data": {"queueId": 7, "from": "a@example.test", "to": ["b@example.test"]}}),
        json!({"id": "2000002", "createdAt": at, "type": "smtp.connection-start",
               "data": {"spanId": 9, "remoteIp": "192.0.2.1"}}),
    ];
    store.ingest(&batch, time::now().as_second()).unwrap();
    setup.client.sign_in("code-admin").await;
    let delivery = setup.client.get(&api("deliveries/7")).await.json();
    assert_eq!(delivery["summary"]["queueId"], "7");
    assert_eq!(delivery["summary"]["to"], json!(["b@example.test"]));
    assert_eq!(delivery["events"].as_array().unwrap().len(), 1);
    let session = setup.client.get(&api("sessions/9")).await.json();
    assert_eq!(session["summary"]["spanId"], "9");
    assert_eq!(session["summary"]["remoteIp"], "192.0.2.1");
    for (path, detail) in [
        ("deliveries/8", "No recorded events for this queue ID"),
        ("sessions/8", "No recorded events for this session"),
    ] {
        let answer = setup.client.get(&api(path)).await;
        assert_eq!(
            (answer.status, answer.json()),
            (StatusCode::NOT_FOUND, json!({"detail": detail})),
            "{path}"
        );
    }
    assert_eq!(
        setup.client.get(&api("sessions/abc")).await.status,
        StatusCode::BAD_REQUEST
    );
    // A detail needs its module, also for an ID that exists.
    setup.client.sign_in("code-viewer").await;
    for path in ["deliveries/7", "sessions/9"] {
        let answer = setup.client.get(&api(path)).await;
        assert_eq!(
            (answer.status, answer.json()),
            (
                StatusCode::FORBIDDEN,
                json!({"detail": "This Garrison module is not authorized"})
            ),
            "{path}"
        );
    }
}

#[tokio::test]
async fn history_queries_beyond_their_slots_are_refused() {
    let mut setup = setup();
    setup.client.sign_in("code-admin").await;
    let slots = u32::try_from(setup.app.query_slots.available_permits()).unwrap();
    let held = setup.app.query_slots.try_acquire_many(slots).unwrap();
    for path in ["events", "deliveries", "metrics"] {
        let answer = setup.client.get(&api(path)).await;
        assert_eq!(
            (answer.status, answer.json()),
            (
                StatusCode::TOO_MANY_REQUESTS,
                json!({"detail": "Too many concurrent history queries"})
            ),
            "{path}"
        );
    }
    drop(held);
    assert_eq!(
        setup.client.get(&api("events")).await.json(),
        json!({"detail": "The event history is not available yet"})
    );
}
