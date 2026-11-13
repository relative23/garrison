use std::time::Duration;

use super::*;
use garrison_testing::http::{answer, serve};

#[test]
fn client_errors_are_answers_and_server_errors_are_unavailable() {
    let server = serve(vec![
        answer(404, "missing"),
        answer(503, ""),
        answer(429, ""),
    ]);
    let missing = Request::get(&server.url).send().unwrap();
    assert_eq!(
        (missing.status, missing.body.as_slice()),
        (404, b"missing".as_slice())
    );
    assert_eq!(
        Request::get(&server.url).send(),
        Err(Error::Unavailable("Stalwart answered HTTP 503".into()))
    );
    assert_eq!(
        Request::get(&server.url).send(),
        Err(Error::Unavailable("Stalwart answered HTTP 429".into()))
    );
    server.requests();
}

#[test]
fn redirects_are_not_followed() {
    let redirect = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/\r\n\
                    Content-Length: 0\r\nConnection: close\r\n\r\n";
    let server = serve(vec![redirect.into()]);
    assert_eq!(Request::get(&server.url).send().unwrap().status, 302);
    server.requests();
}

#[test]
fn oversized_bodies_are_refused() {
    let server = serve(vec![answer(200, "12345"), answer(200, "1234")]);
    assert_eq!(
        Request::get(&server.url).limit(4).send(),
        Err(Error::Denied(
            "Stalwart response exceeds its size limit".into()
        ))
    );
    assert_eq!(
        Request::get(&server.url).limit(4).send().unwrap().body,
        b"1234"
    );
    server.requests();
    // Without a limit of their own, requests read up to 1 MiB.
    let largest = "x".repeat(1024 * 1024);
    let server = serve(vec![
        answer(200, &largest),
        answer(200, &format!("{largest}x")),
    ]);
    assert_eq!(
        Request::get(&server.url).send().unwrap().body.len(),
        largest.len()
    );
    assert!(Request::get(&server.url).send().is_err());
    server.requests();
}

#[test]
fn headers_and_body_are_sent_as_given() {
    let server = serve(vec![answer(200, "")]);
    let url = server.url.clone() + "/auth/token";
    Request::post(&url, b"a=1")
        .header("Host", "mail.example.test")
        .header("X-Forwarded-Proto", "https")
        .send()
        .unwrap();
    let request = server.requests().remove(0).to_ascii_lowercase();
    assert!(
        request.starts_with("post /auth/token http/1.1\r\n"),
        "{request}"
    );
    assert!(
        request.contains("\r\nhost: mail.example.test\r\n"),
        "{request}"
    );
    assert!(
        request.contains("\r\nx-forwarded-proto: https\r\n"),
        "{request}"
    );
    assert!(
        request.contains("\r\naccept-encoding: identity\r\n"),
        "{request}"
    );
    assert_eq!(request.matches("host:").count(), 1, "{request}");
    assert!(request.ends_with("\r\n\r\na=1"), "{request}");
}

#[test]
fn unreachable_listeners_are_unavailable() {
    // Port 9: no test can bind it, so another test's server cannot answer
    // here as it could on a free port that was given back.
    let url = "http://127.0.0.1:9".to_owned();
    assert_eq!(
        Request::get(&url).send(),
        Err(Error::Unavailable("Stalwart is unavailable".into()))
    );
    assert_eq!(
        status_of(&url, Duration::from_secs(1)),
        Err(Error::Unavailable("The endpoint did not answer".into()))
    );
}

#[test]
fn a_silent_listener_times_out() {
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", silent.local_addr().unwrap());
    let started = std::time::Instant::now();
    let result = Request::get(&url)
        .timeout(Duration::from_millis(300))
        .send();
    assert_eq!(
        result,
        Err(Error::Unavailable("Stalwart is unavailable".into()))
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn status_of_reports_any_status() {
    let server = serve(vec![answer(503, "")]);
    assert_eq!(status_of(&server.url, Duration::from_secs(1)), Ok(503));
    server.requests();
}
