//! The pages the build draws ahead (frontend/prerender.mjs): which one a path
//! gets, with a session and without.
#![allow(clippy::unwrap_used)]

mod support;

use axum::http::{Method, StatusCode};
use support::{Answer, setup};

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
