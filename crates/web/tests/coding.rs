//! Content codings and media types: the API's answers (src/coding.rs) go out
//! gzipped as JSON, never the session, which carries the CSRF token; the
//! interface's files in the best coding the browser accepts, each with its
//! media type.
#![allow(clippy::unwrap_used)]

mod support;

use std::io::Read;

use axum::http::{Method, StatusCode};
use flate2::read::GzDecoder;
use garrison_core::config::Database;
use serde_json::{Value, json};
use support::{setup, write_status};

fn observation(index: usize) -> Value {
    json!({
        "id": format!("o{index}"), "provider": "p", "title": "t", "modules": ["dashboard"],
        "evidence": "process", "state": "ok", "checkedAt": "2000-01-01T00:00:00+00:00",
        "source": "s", "kind": "details", "scope": "", "fields": [], "table": null,
        "findings": [], "value": {}, "maxAge": 60,
    })
}

#[tokio::test]
async fn json_answers_go_out_gzipped_but_never_the_session() {
    let mut setup = setup();
    write_status(
        &setup.config.database(Database::Status),
        &json!((0..30).map(observation).collect::<Vec<_>>()),
        &json!([]),
    );
    setup.client.sign_in("code-admin").await;
    let plain = setup.client.get("/api/status").await;
    assert_eq!(plain.header("content-encoding"), "");
    let zipped = setup
        .client
        .send(
            Method::GET,
            "/api/status",
            &[("accept-encoding", "gzip, br")],
            None,
        )
        .await;
    assert_eq!(zipped.header("content-encoding"), "gzip");
    assert_eq!(zipped.header("vary"), "accept-encoding");
    let mut body = Vec::new();
    GzDecoder::new(zipped.body.as_slice())
        .read_to_end(&mut body)
        .unwrap();
    assert_eq!(body, plain.body);
    assert!(zipped.body.len() < plain.body.len() / 4);
    // The session stays as it is though large enough; so do small answers.
    let session = setup
        .client
        .send(
            Method::GET,
            "/api/session",
            &[("accept-encoding", "gzip")],
            None,
        )
        .await;
    assert!(session.body.len() > 1024, "{}", session.body.len());
    assert_eq!(session.header("content-encoding"), "");
    assert!(session.json()["session"]["csrf"].is_string());
    let small = setup
        .client
        .send(
            Method::GET,
            "/api/switch",
            &[("accept-encoding", "gzip")],
            None,
        )
        .await;
    assert!(small.body.len() < 1024);
    assert_eq!(small.header("content-encoding"), "");
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
