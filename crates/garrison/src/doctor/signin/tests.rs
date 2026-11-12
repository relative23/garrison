use std::fmt::Write as _;

use garrison_testing::http::{answer, serve};

use super::super::Level;
use super::*;
use garrison_collector::fetch::roots;

/// The head of Stalwart 1.1.0's sign-in page, as it is served.
const STALWART: &str = r#"<!DOCTYPE html> <html lang="en"> <head> <meta charset="UTF-8">
<title>Sign in</title> <link rel="stylesheet" href="/ui-c2d53b4371a7.css">
<script src="/ui-c2d53b4371a7.js"></script> <style>.app-header{display:flex}</style></head>"#;
/// A webmail's sign-in page: a page in order, only not Stalwart's.
const WEBMAIL: &str = r#"<!DOCTYPE html><html><head><title>Webmail</title>
<link rel="stylesheet" href="/_next/static/css/app.css"><script src="/_next/static/chunks/main.js"></script></head>"#;
/// A sign-in page of one piece, which names no file.
const ONE_PIECE: &str = "<html><style>a{}</style><script>let a = 1</script></html>";

/// A canned answer with a content type.
fn file(status: u16, media: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn html(body: &str) -> String {
    file(200, "text/html; charset=utf-8", body)
}

/// The finding for a public name that gives `public` and a Stalwart that
/// answers `own` itself, with the public server's page address.
fn examined(public: Vec<String>, own: Vec<String>) -> (Finding, String, String) {
    let public = serve(public);
    let own = serve(own);
    let page = format!("{}/login", public.url);
    let stalwart = format!("{}/login", own.url);
    let finding = examine(&page, &stalwart, "client_id=x", &roots());
    public.requests();
    own.requests();
    (finding, page, stalwart)
}

#[test]
fn stalwarts_page_that_gets_its_files_is_in_order() {
    let public = serve(vec![
        html(STALWART),
        file(200, "text/css; charset=utf-8", "a{}"),
        file(200, "text/javascript; charset=utf-8", "1"),
    ]);
    let own = serve(vec![html(STALWART)]);
    let page = format!("{}/login", public.url);
    let finding = examine(
        &page,
        &format!("{}/login", own.url),
        "client_id=x",
        &roots(),
    );
    assert_eq!(finding.level, Level::Ok, "{finding:?}");
    assert_eq!(
        finding.what,
        format!("{page} shows Stalwart's sign-in page, which gets the 2 files it loads")
    );
    let first_lines = |requests: Vec<String>| -> Vec<String> {
        requests
            .iter()
            .map(|request| request.lines().next().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        first_lines(public.requests()),
        [
            "GET /login?client_id=x HTTP/1.1",
            "GET /ui-c2d53b4371a7.css HTTP/1.1",
            "GET /ui-c2d53b4371a7.js HTTP/1.1",
        ]
    );
    // Stalwart itself is asked the same way, and only for the page.
    assert_eq!(
        first_lines(own.requests()),
        ["GET /login?client_id=x HTTP/1.1"]
    );
}

#[test]
fn another_applications_page_is_a_failure_though_it_loads() {
    // The issuer's name is shared with a webmail whose own sign-in page
    // answers; its files would all come back.
    let (finding, page, stalwart) = examined(vec![html(WEBMAIL)], vec![html(STALWART)]);
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.what,
        format!(
            "{page} does not show Stalwart's sign-in page: it loads \
             /_next/static/chunks/main.js, /_next/static/css/app.css, Stalwart's own page at \
             {stalwart} loads /ui-c2d53b4371a7.css, /ui-c2d53b4371a7.js"
        )
    );
    assert!(finding.fix.unwrap().contains("/login with a client_id"));

    // The same against the page of one piece, and the other way round.
    let (finding, ..) = examined(vec![html(WEBMAIL)], vec![html(ONE_PIECE)]);
    assert_eq!(finding.level, Level::Fail);
    assert!(finding.what.ends_with("loads no files"), "{}", finding.what);
    let (finding, ..) = examined(vec![html(ONE_PIECE)], vec![html(STALWART)]);
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding.what.contains("it loads no files, "),
        "{}",
        finding.what
    );
}

#[test]
fn a_page_a_proxy_changed_is_stalwarts_by_the_files_it_loads() {
    // nginx added a tag on the way.
    let changed = STALWART.replace("</head>", "<meta name=\"x\" content=\"y\"></head>");
    let (finding, page, _) = examined(
        vec![
            html(&changed),
            file(200, "text/css", "a{}"),
            file(200, "text/javascript", "1"),
        ],
        vec![html(STALWART)],
    );
    assert_eq!(
        (finding.level, finding.what),
        (
            Level::Ok,
            format!("{page} shows Stalwart's sign-in page, which gets the 2 files it loads")
        )
    );
}

#[test]
fn a_page_whose_files_go_elsewhere_is_a_failure_that_names_them() {
    // A proxy that sends the page to Stalwart and its files to a webmail,
    // which knows neither.
    let (finding, page, _) = examined(
        vec![
            html(STALWART),
            file(404, "text/html; charset=utf-8", "<html>not found</html>"),
            file(200, "text/html; charset=utf-8", "<html>webmail</html>"),
        ],
        vec![html(STALWART)],
    );
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.what,
        format!(
            "Stalwart's sign-in page {page} cannot load \
             /ui-c2d53b4371a7.css (404, text/html; charset=utf-8), \
             /ui-c2d53b4371a7.js (200, text/html; charset=utf-8)"
        )
    );
    assert!(finding.fix.unwrap().contains(origin(&page)));
}

#[test]
fn a_page_of_one_piece_is_stalwarts_only_if_it_is_the_same() {
    let (finding, page, _) = examined(vec![html(ONE_PIECE)], vec![html(ONE_PIECE)]);
    assert_eq!(
        (finding.level, finding.what),
        (
            Level::Ok,
            format!("{page} shows Stalwart's sign-in page, which needs no files of its own")
        )
    );

    // Another page of one piece: nothing tells whose it is, and that is not in order.
    let (finding, page, stalwart) = examined(
        vec![html("<html><script>let b = 2</script></html>")],
        vec![html(ONE_PIECE)],
    );
    assert_eq!(finding.level, Level::Unknown);
    assert_eq!(
        finding.what,
        format!(
            "{page} differs from the sign-in page Stalwart serves at {stalwart}, and neither \
             names a file to tell them by"
        )
    );
}

#[test]
fn without_stalwarts_own_answer_the_page_is_not_called_in_order() {
    for own in [vec![answer(503, "starting")], vec![]] {
        let public = serve(vec![
            html(STALWART),
            file(200, "text/css", "a{}"),
            file(200, "text/javascript", "1"),
        ]);
        // No answer at all: nothing listens there.
        let (stalwart, server) = if own.is_empty() {
            ("http://127.0.0.1:9/login".to_owned(), None)
        } else {
            let server = serve(own);
            (format!("{}/login", server.url), Some(server))
        };
        let page = format!("{}/login", public.url);
        let finding = examine(&page, &stalwart, "a=b", &roots());
        assert_eq!(finding.level, Level::Unknown);
        assert_eq!(
            finding.what,
            format!(
                "the sign-in page at {page} gets the 2 files it loads, but Stalwart did not \
                 answer at {stalwart} to hold it against"
            )
        );
        public.requests();
        if let Some(server) = server {
            server.requests();
        }
    }
}

#[test]
fn a_page_that_is_not_there() {
    let server = serve(vec![answer(502, "bad gateway")]);
    let page = format!("{}/login", server.url);
    let finding = examine(&page, "http://127.0.0.1:9/login", "a=b", &roots());
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.what,
        format!("Stalwart's sign-in page {page} answers 502")
    );
    server.requests();

    // Nothing listens there.
    let finding = examine(
        "http://127.0.0.1:9/login",
        "http://127.0.0.1:9/login",
        "a=b",
        &roots(),
    );
    assert_eq!(finding.level, Level::Fail);
}

#[test]
fn a_file_asked_for_twice_is_asked_once_and_only_so_many_are_asked() {
    let mut tags = String::new();
    for index in 0..20 {
        for _ in 0..2 {
            let _ = write!(tags, "<script src=\"/s{index}.js\"></script>");
        }
    }
    let mut responses = vec![html(&tags)];
    responses.extend((0..MOST).map(|_| file(200, "text/javascript", "1")));
    let public = serve(responses);
    let own = serve(vec![html(&tags)]);
    let page = format!("{}/login", public.url);
    let finding = examine(&page, &format!("{}/login", own.url), "a=b", &roots());
    assert_eq!(
        finding.what,
        format!("{page} shows Stalwart's sign-in page, which gets the {MOST} files it loads")
    );
    assert_eq!(public.requests().len(), MOST + 1);
    own.requests();
}

#[test]
fn whose_page_it_is() {
    assert_eq!(whose(STALWART, STALWART), Whose::Stalwart);
    assert_eq!(whose(WEBMAIL, STALWART), Whose::Another);
    assert_eq!(whose(ONE_PIECE, ONE_PIECE), Whose::Stalwart);
    assert_eq!(whose("<html>a</html>", "<html>b</html>"), Whose::Unclear);
    // Another build of Stalwart's page: other hashes in the names.
    let rebuilt = STALWART.replace("c2d53b4371a7", "0123456789ab");
    assert_eq!(whose(&rebuilt, STALWART), Whose::Another);
    assert_eq!(listed(&[]), "no files");
    assert_eq!(
        listed(&["/a.js".to_owned(), "/b.css".to_owned()]),
        "/a.js, /b.css"
    );
}
