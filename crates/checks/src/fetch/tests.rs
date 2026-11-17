use std::net::TcpListener;

use super::*;

#[test]
fn urls_split_into_scheme_host_port_and_path() {
    assert_eq!(
        split("https://mail.example.org/metrics/prometheus").unwrap(),
        (
            true,
            "mail.example.org".into(),
            443,
            "/metrics/prometheus".into()
        )
    );
    assert_eq!(
        split("http://127.0.0.1:8080").unwrap(),
        (false, "127.0.0.1".into(), 8080, "/".into())
    );
    assert_eq!(split("http://[::1]:8080/a").unwrap().1, "::1");
    assert!(split("ftp://example.org").is_err());
    assert!(split("https://:443/").is_err());
}

#[test]
fn the_origin_of_a_url() {
    assert_eq!(
        origin("https://stalwart.example.org/admin/"),
        "https://stalwart.example.org"
    );
    assert_eq!(
        origin("https://mail.example.org"),
        "https://mail.example.org"
    );
    assert_eq!(
        origin("http://127.0.0.1:8080/login?a=b"),
        "http://127.0.0.1:8080"
    );
}

#[test]
fn answers_are_parsed_with_chunked_bodies() {
    let plain = parse(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno").unwrap();
    assert_eq!((plain.status, plain.body.as_str()), (404, "no"));
    let chunked = parse(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nStrict-Transport-Security: max-age=1\r\n\r\n\
          4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n",
    )
    .unwrap();
    assert_eq!(chunked.body, "{\"a\":1}");
    assert_eq!(
        chunked.header("strict-transport-security"),
        Some("max-age=1")
    );
    assert!(parse(b"not http").is_none());
    // A chunk size near usize::MAX must neither overflow nor panic.
    let huge = parse(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nab\r\n0\r\n\r\n",
    );
    assert_eq!(huge.unwrap().body, "");
}

#[test]
fn a_compressed_body_is_unpacked_as_far_as_it_goes() {
    use std::io::Write as _;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(b"<html>sign in</html>").unwrap();
    let packed = gzip.finish().unwrap();
    let answer = |body: &[u8]| {
        let mut data = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        data.extend_from_slice(body);
        parse(&data).unwrap().body
    };
    assert_eq!(answer(&packed), "<html>sign in</html>");
    // Cut off, or no gzip at all: what unpacks, never a panic.
    assert!("<html>sign in</html>".starts_with(&answer(&packed[..packed.len() - 9])));
    assert_eq!(answer(b"plain text"), "");
}

#[test]
fn a_post_sends_its_headers_and_its_body() {
    let server = garrison_testing::http::serve(vec![garrison_testing::http::answer(200, "{}")]);
    let request = Request {
        method: "POST",
        url: &format!("{}/topic?x=1", server.url),
        headers: &[
            ("Title", "Two checks failed"),
            ("Authorization", "Bearer token-1"),
            // Nothing that would start another header or line goes out.
            ("X-Bad\r\nInjected", "1"),
            ("X-Also-Bad", "1\r\nInjected: 2"),
        ],
        body: b"Backup job: failed",
        needs: Needs::Whole,
    };
    assert_eq!(send(&request, &roots()).unwrap().status, 200);
    let sent = server.requests().remove(0);
    assert!(sent.starts_with("POST /topic?x=1 HTTP/1.1\r\n"), "{sent}");
    for line in [
        "Title: Two checks failed\r\n",
        "Authorization: Bearer token-1\r\n",
        "Content-Length: 18\r\n",
    ] {
        assert!(sent.contains(line), "{sent}");
    }
    assert!(!sent.contains("Injected"), "{sent}");
    assert!(sent.ends_with("\r\n\r\nBackup job: failed"), "{sent}");
}

#[test]
fn random_answers_never_panic() {
    let mut noise = garrison_testing::noise::Noise::new(0x9e37_79b9_7f4a_7c15);
    let pieces: [&[u8]; 9] = [
        b"HTTP/1.1 ",
        b"200",
        b" OK\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"\r\n",
        b"ffffffff",
        b"\r\n\r\n",
        b"0\r\n",
        b"\xff\xfe",
    ];
    for _ in 0..20_000 {
        let mut data = Vec::new();
        for _ in 0..(noise.next_u64() % 12) {
            match pieces.get(noise.below(10)) {
                Some(piece) => data.extend_from_slice(piece),
                None => data.push(u8::try_from(noise.next_u64() % 256).unwrap()),
            }
        }
        let _ = parse(&data);
        let _ = split(&String::from_utf8_lossy(&data));
    }
}

#[test]
fn a_server_that_sends_a_byte_now_and_then_does_not_hold_a_request_beyond_its_time() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // An answer that never ends: each byte comes within a step's time.
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n");
        for _ in 0..200 {
            if stream.write_all(b"x").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let url = format!("http://127.0.0.1:{port}/");
    let request = Request {
        method: "GET",
        url: &url,
        headers: &[],
        body: &[],
        needs: Needs::Whole,
    };
    let began = Instant::now();
    let error = send_until(&request, &roots(), began + Duration::from_millis(400)).unwrap_err();
    assert!(
        began.elapsed() < Duration::from_secs(5),
        "{:?}",
        began.elapsed()
    );
    assert!(error.contains("not done in its time"), "{error}");
    // A time that is over before the request begins asks nobody.
    let late = send_until(&request, &roots(), Instant::now()).unwrap_err();
    assert!(
        late.contains("no answer within") || late.contains("not reached"),
        "{late}"
    );
}

/// A TLS server on `localhost` that reads one request, answers `answer` and
/// closes the connection without the notice TLS ends with; its port, and the
/// authority its certificate comes from.
fn closes_without_notice(answer: &'static [u8]) -> (u16, Roots) {
    closes_without_notice_with(&garrison_testing::tls::certificates(), answer)
}

/// The same with the certificates given.
fn closes_without_notice_with(
    certificates: &garrison_testing::tls::Certificates,
    answer: &'static [u8],
) -> (u16, Roots) {
    use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
    let mut roots = RootCertStore::empty();
    roots.add(certificates.ca.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificates.server.clone()],
                certificates.key.clone_key(),
            )
            .unwrap();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let connection = ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = StreamOwned::new(connection, stream);
        let mut request = [0u8; 2048];
        let mut read = 0;
        while !request[..read]
            .windows(4)
            .any(|window| window == b"\r\n\r\n")
        {
            match tls.read(&mut request[read..]) {
                Ok(count) if count > 0 => read += count,
                _ => return,
            }
        }
        let _ = tls.write_all(answer);
        let _ = tls.flush();
        // Dropped as it is: the socket closes, and TLS was never ended.
    });
    (port, Arc::new(roots))
}

#[test]
fn an_answer_that_is_whole_counts_though_the_server_ended_tls_without_notice() {
    // Many servers close the socket and leave out TLS's closing notice.
    let (port, roots) = closes_without_notice(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"id\":\"m1\"}",
    );
    let answer = get(&format!("https://localhost:{port}/topic"), &roots).unwrap();
    assert_eq!(
        (answer.status, answer.body.as_str()),
        (200, "{\"id\":\"m1\"}")
    );
    // A chunked answer is whole with its last, empty chunk.
    let (port, roots) = closes_without_notice(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
    );
    let answer = get(&format!("https://localhost:{port}/"), &roots).unwrap();
    assert_eq!((answer.status, answer.body.as_str()), (200, "ok"));
}

#[test]
fn an_answer_cut_short_without_notice_is_no_answer() {
    // Whoever can end the connection could cut an answer anywhere: without
    // the notice, only what its own length calls whole is taken.
    for cut in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"id\"".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n",
        // No length at all: the end of the connection would be the end.
        b"HTTP/1.1 200 OK\r\n\r\nall there is",
    ] {
        let (port, roots) = closes_without_notice(cut);
        let error = get(&format!("https://localhost:{port}/"), &roots).unwrap_err();
        assert!(
            error.contains("ended before its answer was whole"),
            "{error}"
        );
    }
}

/// A request that needs only the head, as a notification does, takes a
/// complete head whatever follows it; one that needs the whole answer does
/// not take an answer without a length, and neither takes a cut head.
#[test]
fn a_request_that_needs_the_head_takes_it_where_the_rest_may_be_cut() {
    let ask = |answer: &'static [u8], needs: Needs| {
        let (port, roots) = closes_without_notice(answer);
        let url = format!("https://localhost:{port}/topic");
        // Without a body: this server reads a request's head alone.
        let request = Request {
            method: "GET",
            url: &url,
            headers: &[],
            body: &[],
            needs,
        };
        send(&request, &roots).map(|answer| answer.status)
    };
    let no_length: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":tr";
    assert_eq!(ask(no_length, Needs::Head), Ok(200));
    let refused = ask(no_length, Needs::Whole).unwrap_err();
    assert!(
        refused.contains("ended before its answer was whole"),
        "{refused}"
    );
    // Another status is that status, for the caller to judge.
    assert_eq!(
        ask(b"HTTP/1.1 503 Service Unavailable\r\n\r\n", Needs::Head),
        Ok(503)
    );
    for needs in [Needs::Head, Needs::Whole] {
        let cut = ask(b"HTTP/1.1 200 OK\r\nContent-Ty", needs).unwrap_err();
        assert!(cut.contains("ended before its answer was whole"), "{cut}");
    }
}

/// A check judges a server's certificate at its run's time: one that ends
/// after the run is valid then, and one that ended before it is not,
/// whatever this host's clock says.
#[test]
fn a_certificate_is_judged_at_the_time_of_the_run_it_is_asked_for() {
    // Valid until 2026-11-13 00:00 UTC.
    let certificates = garrison_testing::tls::certificates_until(2026, 11, 13);
    let answer: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let at = |text: &str| time::parse(text).unwrap();
    let (port, roots) = closes_without_notice_with(&certificates, answer);
    let read = get_at(
        &format!("https://localhost:{port}/"),
        &roots,
        at("2026-11-12T23:59:00Z"),
    );
    assert_eq!(read.map(|answer| answer.body), Ok("ok".to_owned()));
    let (port, roots) = closes_without_notice_with(&certificates, answer);
    let error = get_at(
        &format!("https://localhost:{port}/"),
        &roots,
        at("2026-11-13T00:01:00Z"),
    )
    .unwrap_err();
    // Named as what it is, with the time it ended at.
    assert_eq!(
        error,
        "the certificate expired at 2026-11-13T00:00:00+00:00"
    );
}

/// A certificate's fault is named as what it is, with the time where the
/// certificate gives one; any other is named in the TLS library's words.
#[test]
fn a_certificates_fault_is_named_in_plain_words() {
    let at = |second| UnixTime::since_unix_epoch(Duration::from_secs(second));
    let named = |reason: CertificateError| certificate_fault(&reason);
    assert_eq!(
        named(CertificateError::ExpiredContext {
            time: at(1_794_728_591),
            not_after: at(1_794_528_000),
        }),
        "the certificate expired at 2026-11-13T00:00:00+00:00"
    );
    assert_eq!(
        named(CertificateError::Expired),
        "the certificate has expired"
    );
    assert_eq!(
        named(CertificateError::NotValidYetContext {
            time: at(1_794_528_000),
            not_before: at(1_794_728_591),
        }),
        "the certificate is valid only from 2026-11-15T07:43:11+00:00"
    );
    assert_eq!(
        named(CertificateError::UnknownIssuer),
        "the certificate is not from an authority this host trusts"
    );
    let expected = ServerName::try_from("mail.example.test").unwrap();
    assert_eq!(
        named(CertificateError::NotValidForNameContext {
            expected: expected.clone(),
            presented: vec!["localhost".to_owned(), "127.0.0.1".to_owned()],
        }),
        "the certificate is not valid for this name; it is for localhost, 127.0.0.1"
    );
    assert_eq!(
        named(CertificateError::NotValidForNameContext {
            expected,
            presented: Vec::new(),
        }),
        "the certificate is not valid for this name; it names none"
    );
    assert_eq!(
        named(CertificateError::Revoked),
        "the certificate is revoked"
    );
    assert_eq!(
        named(CertificateError::BadSignature),
        "the certificate is not valid: BadSignature"
    );
}

/// A request to a port other than the scheme's own names it in `Host`, as
/// RFC 9110 has it: a server that tells its names apart by host and port,
/// as Garrison's web service does for `public_origin`, takes the name
/// alone for another one.
#[test]
fn the_host_header_names_a_port_other_than_the_schemes_own() {
    let server = garrison_testing::http::serve(vec![garrison_testing::http::answer(200, "{}")]);
    let port = server.url.rsplit_once(':').unwrap().1.to_owned();
    assert_eq!(
        get(&format!("{}/x", server.url), &roots()).unwrap().status,
        200
    );
    let sent = server.requests().remove(0);
    assert!(
        sent.contains(&format!("\r\nHost: 127.0.0.1:{port}\r\n")),
        "{sent}"
    );
    for (host, port, secure, header) in [
        ("garrison.example.org", 443, true, "garrison.example.org"),
        ("garrison.example.org", 80, false, "garrison.example.org"),
        (
            "garrison.example.org",
            8443,
            true,
            "garrison.example.org:8443",
        ),
        (
            "garrison.example.org",
            443,
            false,
            "garrison.example.org:443",
        ),
        ("2001:db8::1", 8443, true, "[2001:db8::1]:8443"),
    ] {
        assert_eq!(host_header(host, port, secure), header);
    }
}
