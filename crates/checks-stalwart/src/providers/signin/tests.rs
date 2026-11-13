use std::fmt::Write as _;

use garrison_testing::http::{answer, serve};

use super::*;
use crate::context::Memory;
use crate::fetch::roots;
use crate::testing::{Canned, Remembered, config, now, table};

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
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: {media}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn html(body: &str) -> String {
    file(200, "text/html; charset=utf-8", body)
}

/// Stalwart's page and the two files it loads, all in order.
fn in_order() -> Vec<String> {
    vec![
        html(STALWART),
        file(200, "text/css; charset=utf-8", "a{}"),
        file(200, "text/javascript; charset=utf-8", "1"),
    ]
}

/// What a public name that gives `public` and a Stalwart that answers `own`
/// itself are found to be, with the public server's page address.
fn served(public: Vec<String>, own: Vec<String>) -> (Examined, String, String) {
    let public = serve(public);
    let own = serve(own);
    let page = format!("{}/login", public.url);
    let stalwart = format!("{}/login", own.url);
    let examined = examine(&page, &stalwart, "client_id=x", &roots());
    public.requests();
    own.requests();
    (examined, page, stalwart)
}

fn first_lines(requests: &[String]) -> Vec<String> {
    requests
        .iter()
        .map(|request| request.lines().next().unwrap().to_owned())
        .collect()
}

#[test]
fn stalwarts_page_that_gets_its_files_is_in_order() {
    let public = serve(in_order());
    let own = serve(vec![html(STALWART)]);
    let page = format!("{}/login", public.url);
    let examined = examine(
        &page,
        &format!("{}/login", own.url),
        "client_id=x",
        &roots(),
    );
    assert_eq!(examined.state, State::Ok, "{examined:?}");
    assert_eq!(
        examined.what,
        format!("{page} shows Stalwart's sign-in page, which gets the 2 files it loads")
    );
    assert_eq!(examined.files, Some(2));
    assert_eq!(
        first_lines(&public.requests()),
        [
            "GET /login?client_id=x HTTP/1.1",
            "GET /ui-c2d53b4371a7.css HTTP/1.1",
            "GET /ui-c2d53b4371a7.js HTTP/1.1",
        ]
    );
    // Stalwart itself is asked the same way, and only for the page.
    assert_eq!(
        first_lines(&own.requests()),
        ["GET /login?client_id=x HTTP/1.1"]
    );
}

#[test]
fn another_applications_page_is_a_failure_though_it_loads() {
    // The issuer's name is shared with a webmail whose own sign-in page
    // answers; its files would all come back.
    let (examined, page, stalwart) = served(vec![html(WEBMAIL)], vec![html(STALWART)]);
    assert_eq!(examined.state, State::Failed);
    assert_eq!(
        examined.what,
        format!(
            "{page} does not show Stalwart's sign-in page: it loads \
             /_next/static/chunks/main.js, /_next/static/css/app.css, Stalwart's own page at \
             {stalwart} loads /ui-c2d53b4371a7.css, /ui-c2d53b4371a7.js"
        )
    );
    assert!(examined.fix.unwrap().contains("/login with a client_id"));

    // The same against the page of one piece, and the other way round.
    let (examined, ..) = served(vec![html(WEBMAIL)], vec![html(ONE_PIECE)]);
    assert_eq!(examined.state, State::Failed);
    assert!(
        examined.what.ends_with("loads no files"),
        "{}",
        examined.what
    );
    let (examined, ..) = served(vec![html(ONE_PIECE)], vec![html(STALWART)]);
    assert_eq!(examined.state, State::Failed);
    assert!(
        examined.what.contains("it loads no files, "),
        "{}",
        examined.what
    );
}

#[test]
fn a_page_a_proxy_changed_is_stalwarts_by_the_files_it_loads() {
    // nginx added a tag on the way.
    let changed = STALWART.replace("</head>", "<meta name=\"x\" content=\"y\"></head>");
    let (examined, page, _) = served(
        vec![
            html(&changed),
            file(200, "text/css", "a{}"),
            file(200, "text/javascript", "1"),
        ],
        vec![html(STALWART)],
    );
    assert_eq!(
        (examined.state, examined.what),
        (
            State::Ok,
            format!("{page} shows Stalwart's sign-in page, which gets the 2 files it loads")
        )
    );
}

#[test]
fn a_page_whose_files_go_elsewhere_is_a_failure_that_names_them() {
    // A proxy that sends the page to Stalwart and its files to a webmail,
    // which knows neither.
    let (examined, page, _) = served(
        vec![
            html(STALWART),
            file(404, "text/html; charset=utf-8", "<html>not found</html>"),
            file(200, "text/html; charset=utf-8", "<html>webmail</html>"),
        ],
        vec![html(STALWART)],
    );
    assert_eq!(examined.state, State::Failed);
    assert_eq!(
        examined.what,
        format!(
            "Stalwart's sign-in page {page} cannot load \
             /ui-c2d53b4371a7.css (404, text/html; charset=utf-8), \
             /ui-c2d53b4371a7.js (200, text/html; charset=utf-8)"
        )
    );
    assert_eq!(examined.files, Some(2));
    assert!(examined.fix.unwrap().contains(origin(&page)));
}

#[test]
fn a_page_of_one_piece_is_stalwarts_only_if_it_is_the_same() {
    let (examined, page, _) = served(vec![html(ONE_PIECE)], vec![html(ONE_PIECE)]);
    assert_eq!(
        (examined.state, examined.what),
        (
            State::Ok,
            format!("{page} shows Stalwart's sign-in page, which needs no files of its own")
        )
    );

    // Another page of one piece: nothing tells whose it is, and that is not in order.
    let (examined, page, stalwart) = served(
        vec![html("<html><script>let b = 2</script></html>")],
        vec![html(ONE_PIECE)],
    );
    assert_eq!(examined.state, State::Unknown);
    assert_eq!(
        examined.what,
        format!(
            "{page} differs from the sign-in page Stalwart serves at {stalwart}, and neither \
             names a file to tell them by"
        )
    );
}

#[test]
fn without_stalwarts_own_answer_the_page_is_not_called_in_order() {
    for own in [vec![answer(503, "starting")], vec![]] {
        let public = serve(in_order());
        // No answer at all: nothing listens there.
        let (stalwart, server) = if own.is_empty() {
            ("http://127.0.0.1:9/login".to_owned(), None)
        } else {
            let server = serve(own);
            (format!("{}/login", server.url), Some(server))
        };
        let page = format!("{}/login", public.url);
        let examined = examine(&page, &stalwart, "a=b", &roots());
        assert_eq!(examined.state, State::Unknown);
        assert_eq!(
            examined.what,
            format!(
                "The sign-in page at {page} gets the 2 files it loads, but Stalwart did not \
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
    let examined = examine(&page, "http://127.0.0.1:9/login", "a=b", &roots());
    assert_eq!(examined.state, State::Failed);
    assert_eq!(
        examined.what,
        format!("Stalwart's sign-in page {page} answers 502")
    );
    assert_eq!(examined.files, None);
    server.requests();

    // Nothing listens there.
    let examined = examine(
        "http://127.0.0.1:9/login",
        "http://127.0.0.1:9/login",
        "a=b",
        &roots(),
    );
    assert_eq!(examined.state, State::Failed);
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
    let examined = examine(&page, &format!("{}/login", own.url), "a=b", &roots());
    assert_eq!(
        examined.what,
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

/// One run of the check `seconds` after the tests' clock, with the issuer at
/// `public` and Stalwart's own listener at `own`.
fn collected(memory: &Remembered, seconds: i64, public: &str, own: &str) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.deployment.issuer = public.to_owned();
    config.deployment.stalwart_url = own.to_owned();
    let runner = Canned(String::new());
    let context = Context {
        now: time::Timestamp::from_second(now().as_second() + seconds).unwrap(),
        memory,
        ..crate::testing::context(&config, &runner)
    };
    let check = SignIn::new(&table("type = \"sign-in\"")).unwrap();
    let mut report = check.collect(&context).unwrap();
    assert_eq!(report.observations.len(), 1);
    report.observations.remove(0)
}

fn field<'a>(observation: &'a Observation, label: &str) -> &'a serde_json::Value {
    &observation
        .fields
        .iter()
        .find(|field| field.label == label)
        .unwrap()
        .value
}

#[test]
fn a_page_in_order_is_examined_again_after_five_minutes() {
    let memory = Remembered::default();
    let mut answers = in_order();
    answers.extend(in_order());
    let public = serve(answers);
    let own = serve(vec![html(STALWART), html(STALWART)]);
    let first = collected(&memory, 0, &public.url, &own.url);
    assert_eq!(
        (first.id.as_str(), first.provider.as_str(), first.state),
        ("signin.page", "sign-in", State::Ok)
    );
    assert!(first.findings.is_empty(), "{:?}", first.findings);
    assert_eq!(first.source, format!("{}/login", public.url));
    assert_eq!(field(&first, "Page"), &serde_json::json!(first.source));
    assert_eq!(field(&first, "Files it loads"), &serde_json::json!(2));
    assert_eq!(
        field(&first, "Asked"),
        &serde_json::json!("2026-10-29T12:00:00+00:00")
    );

    // Within five minutes the page is not asked for; it is reported as it was found.
    let kept = collected(&memory, 299, &public.url, &own.url);
    assert_eq!(kept.state, State::Ok);
    assert_eq!(field(&kept, "Asked"), field(&first, "Asked"));
    assert_eq!(field(&kept, "Files it loads"), &serde_json::json!(2));
    assert_eq!(kept.checked_at, "2026-10-29T12:04:59+00:00");

    let again = collected(&memory, 300, &public.url, &own.url);
    assert_eq!(
        field(&again, "Asked"),
        &serde_json::json!("2026-10-29T12:05:00+00:00")
    );
    assert_eq!(public.requests().len(), 6);
    assert_eq!(own.requests().len(), 2);
}

#[test]
fn a_page_that_is_not_in_order_is_examined_in_every_run() {
    let memory = Remembered::default();
    let public = serve(vec![answer(502, "bad gateway"), answer(502, "bad gateway")]);
    let page = format!("{}/login", public.url);
    for seconds in [0, 60] {
        let failed = collected(&memory, seconds, &public.url, "http://127.0.0.1:9");
        assert_eq!(failed.state, State::Failed);
        assert_eq!(
            failed.findings,
            [
                format!("Stalwart's sign-in page {page} answers 502."),
                "This address must reach Stalwart; check the proxy rules of the issuer's host."
                    .to_owned(),
            ]
        );
        assert_eq!(field(&failed, "Files it loads"), &serde_json::Value::Null);
    }
    public.requests();
}

#[test]
fn a_page_kept_for_another_issuer_is_examined_anew() {
    // Kept a moment ago, for the page of another issuer.
    let memory = Remembered::default();
    memory.keep(
        KEPT,
        &format!(
            r#"{{"at": {}, "page": "https://old.example.test/login", "files": 2}}"#,
            now().as_second()
        ),
    );
    let public = serve(vec![answer(502, "bad gateway")]);
    let observation = collected(&memory, 10, &public.url, "http://127.0.0.1:9");
    assert_eq!(observation.state, State::Failed);
    public.requests();
}

#[test]
fn the_check_takes_its_modules_and_nothing_else() {
    let check = SignIn::new(&table("type = \"sign-in\"\nmodules = [\"dns_tls\"]")).unwrap();
    assert_eq!(
        check.modules.iter().copied().collect::<Vec<_>>(),
        [ModuleId::DnsTls]
    );
    assert!(SignIn::new(&table("type = \"sign-in\"\nurl = \"https://x.example\"")).is_err());
}
