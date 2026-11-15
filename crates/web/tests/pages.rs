//! The pages the build draws ahead (frontend/prerender.mjs): which one a path
//! gets, with a session and without.
#![allow(clippy::unwrap_used)]

mod support;

use axum::http::{Method, StatusCode};
use serde_json::json;
use support::{Answer, Client, ORIGIN, setup};

/// `printf 'main{color:red}' | openssl dgst -sha256 -binary | base64`
const STYLE_HASH: &str = "sha256-ac1R1kU5izDDnXGpZrb2k+Dct4jThB3/YH1VfglrT3I=";

#[tokio::test]
async fn a_drawn_page_goes_out_compressed_and_its_inline_style_is_allowed_by_hash() {
    let mut setup = setup();
    let pages = setup.directory.path().join("static/pages");
    std::fs::create_dir_all(&pages).unwrap();
    let page = "<!doctype html><style>main{color:red}</style>";
    std::fs::write(pages.join("sign-in.html"), page).unwrap();
    std::fs::write(pages.join("sign-in.html.br"), "brotli copy").unwrap();
    // A stylesheet without its end tag is not allowed.
    std::fs::write(pages.join("dashboard.html"), "<style>main{color:red}").unwrap();
    for (accepted, coding, body) in [("gzip, br", "br", "brotli copy"), ("identity", "", page)] {
        let answer = setup
            .client
            .send(
                Method::GET,
                "/admin/",
                &[("accept-encoding", accepted)],
                None,
            )
            .await;
        assert_eq!(answer.header("content-encoding"), coding, "{accepted}");
        assert_eq!(answer.body, body.as_bytes(), "{accepted}");
        assert_eq!(answer.header("vary"), "accept-encoding", "{accepted}");
        let policy = answer.header("content-security-policy");
        // The hash comes from the plain page, also when the copy goes out.
        assert!(
            policy.contains(&format!("style-src 'self' '{STYLE_HASH}';")),
            "{policy}"
        );
    }
    setup.client.sign_in("code-admin").await;
    for path in ["/admin/", "/api/session"] {
        let policy = setup
            .client
            .get(path)
            .await
            .header("content-security-policy")
            .to_owned();
        assert!(policy.contains("style-src 'self';"), "{path}: {policy}");
    }
}

#[tokio::test]
async fn each_view_gets_the_page_the_build_drew_for_it() {
    let mut setup = setup();
    let pages = setup.directory.path().join("static/pages");
    std::fs::create_dir_all(&pages).unwrap();
    for name in ["dashboard", "deliveries", "sign-in"] {
        std::fs::write(pages.join(format!("{name}.html")), name).unwrap();
    }
    let body = |answer: &Answer| String::from_utf8_lossy(&answer.body).into_owned();
    // Without a session every view draws the sign-in page.
    for path in ["/admin/", "/admin/deliveries", "/admin/logs"] {
        assert_eq!(body(&setup.client.get(path).await), "sign-in", "{path}");
    }
    setup.client.sign_in("code-admin").await;
    for (path, page) in [
        ("/admin/", "dashboard"),
        ("/admin/deliveries", "deliveries"),
        ("/admin/deliveries/", "deliveries"),
        // A detail asks for other data than the list the drawn page preloads.
        ("/admin/deliveries/0123abc", "<!doctype html>"),
        // No drawn page, or no plain name: the index.
        ("/admin/logs", "<!doctype html>"),
        ("/admin/Deliveries", "<!doctype html>"),
        ("/admin/sign-in", "<!doctype html>"),
    ] {
        let answer = setup.client.get(path).await;
        assert_eq!(answer.status, StatusCode::OK, "{path}");
        assert!(body(&answer).starts_with(page), "{path}: {}", body(&answer));
        assert_eq!(answer.header("cache-control"), "no-store", "{path}");
    }
}

/// Save `theme` as the signed-in user's theme.
async fn choose(client: &mut Client, csrf: &str, theme: &str) {
    let headers = [("origin", ORIGIN), ("x-csrf-token", csrf)];
    let body = json!({"theme": theme, "hiddenModules": []});
    let saved = client
        .send(Method::PUT, "/api/preferences", &headers, Some(body))
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{theme}");
}

#[tokio::test]
async fn a_page_goes_out_in_the_theme_its_user_chose() {
    let mut setup = setup();
    let root = setup.directory.path().join("static");
    let pages = root.join("pages");
    std::fs::create_dir_all(&pages).unwrap();
    for name in ["dashboard", "logs", "sign-in"] {
        std::fs::write(pages.join(format!("{name}.html")), name).unwrap();
    }
    // The build draws each page and the index in each theme (prerender.mjs);
    // logs stands for a page of a build without them.
    for theme in ["light", "dark"] {
        let page = format!("<style>main{{color:red}}</style>dashboard {theme}");
        std::fs::write(pages.join(format!("dashboard.{theme}.html")), page).unwrap();
        std::fs::write(
            root.join(format!("index.{theme}.html")),
            format!("index {theme}"),
        )
        .unwrap();
    }
    std::fs::write(pages.join("dashboard.dark.html.br"), "brotli copy, dark").unwrap();
    let body = |answer: &Answer| String::from_utf8_lossy(&answer.body).into_owned();
    // Nobody's theme is known without a session: the sign-in page follows the system.
    assert_eq!(body(&setup.client.get("/admin/").await), "sign-in");
    let csrf = setup.client.sign_in("code-admin").await;
    // Nothing chosen yet, and "system": the page that follows the system.
    assert_eq!(body(&setup.client.get("/admin/").await), "dashboard");
    for (theme, page, index) in [
        ("dark", "dashboard dark", "index dark"),
        ("light", "dashboard light", "index light"),
        ("system", "dashboard", "<!doctype html>"),
    ] {
        choose(&mut setup.client, &csrf, theme).await;
        let answer = setup.client.get("/admin/dashboard").await;
        assert!(body(&answer).ends_with(page), "{theme}: {}", body(&answer));
        assert_eq!(answer.header("cache-control"), "no-store", "{theme}");
        // A detail gets the index, in the same theme.
        let detail = body(&setup.client.get("/admin/deliveries/0123abc").await);
        assert!(detail.starts_with(index), "{theme}: {detail}");
        // A page drawn in no theme of its own goes out as it is.
        assert_eq!(
            body(&setup.client.get("/admin/logs").await),
            "logs",
            "{theme}"
        );
    }
    // The chosen theme's page in the best coding, its stylesheet allowed by hash.
    choose(&mut setup.client, &csrf, "dark").await;
    let answer = setup
        .client
        .send(Method::GET, "/admin/", &[("accept-encoding", "br")], None)
        .await;
    assert_eq!(body(&answer), "brotli copy, dark");
    assert_eq!(answer.header("content-encoding"), "br");
    let policy = answer.header("content-security-policy");
    assert!(
        policy.contains(&format!("style-src 'self' '{STYLE_HASH}';")),
        "{policy}"
    );
    // Another user's pages are in that user's theme.
    let mut other = Client::new(garrison_web::router(std::sync::Arc::clone(&setup.app)));
    other.sign_in("code-viewer").await;
    assert_eq!(body(&other.get("/admin/").await), "dashboard");
    // Signed out, the theme is nobody's again.
    let headers = [("origin", ORIGIN), ("x-csrf-token", csrf.as_str())];
    let out = setup
        .client
        .send(Method::POST, "/api/logout", &headers, Some(json!({})))
        .await;
    assert_eq!(out.status, StatusCode::OK);
    assert_eq!(body(&setup.client.get("/admin/").await), "sign-in");
}
