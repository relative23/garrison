use super::super::Level;
use super::*;

#[test]
fn a_visitor_is_told_there_is_no_session() {
    assert!(visitor_answer(200, r#"{"session":null}"#));
    assert!(!visitor_answer(401, r#"{"detail":"Sign-in required"}"#));
    assert!(!visitor_answer(200, r#"{"session":{"subject":"1"}}"#));
    assert!(!visitor_answer(200, "<html>Welcome to nginx</html>"));
    assert!(!visitor_answer(401, "Unauthorized"));
    assert!(!visitor_answer(502, r#"{"session":null}"#));
}

/// The certificate is probed where the origin names it: its host, on its
/// port, 443 where it names none.
#[test]
fn the_host_and_the_port_of_an_origin() {
    assert_eq!(
        authority("https://garrison.example.org:8443"),
        ("garrison.example.org", 8443)
    );
    assert_eq!(
        authority("https://garrison.example.org"),
        ("garrison.example.org", 443)
    );
    assert_eq!(
        authority("https://[2001:db8::1]:8443"),
        ("2001:db8::1", 8443)
    );
    assert_eq!(authority("https://[2001:db8::1]"), ("2001:db8::1", 443));
}

/// What doctor says of each answer to its question about the sign-in
/// client: Stalwart's own, which setup mends where it refuses the
/// client, and any other, which the proxy of the issuer's host does.
#[test]
fn the_answer_about_the_sign_in_client_is_read_as_stalwart_gives_it() {
    let answer = |status: u16, kind: &str, body: &str| {
        format!(
            "HTTP/1.1 {status} X\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let json = "application/json";
    for (response, level, said, fix) in [
        (
            answer(200, json, r#"{"name":"Garrison","verified":true}"#),
            Level::Ok,
            "Stalwart knows Garrison's sign-in client as registered",
            None,
        ),
        (
            answer(
                200,
                json,
                r#"{"error":"invalid_client","description":"Client metadata documents are disabled"}"#,
            ),
            Level::Fail,
            "Client metadata documents are disabled",
            Some("garrison stalwart setup"),
        ),
        (
            answer(200, json, r#"{"status":"ok"}"#),
            Level::Fail,
            "not Stalwart's JSON",
            Some("/api/auth/client"),
        ),
        (
            answer(404, "text/html", "<html>Not found</html>"),
            Level::Fail,
            "answers 404 (text/html)",
            Some("/api/auth/client"),
        ),
        (
            answer(502, "text/html", "<html>Bad gateway</html>"),
            Level::Fail,
            "its proxy does not reach Stalwart",
            Some("See that Stalwart runs"),
        ),
        (
            answer(429, json, "{}"),
            Level::Unknown,
            "ask again in a minute",
            None,
        ),
    ] {
        let server = garrison_testing::tls::serve_until(vec![response], 2036, 1, 1);
        let roots = Arc::new(server.roots.clone());
        let directory = tempfile::tempdir().unwrap();
        let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        config.deployment.issuer.clone_from(&server.url);
        let found = sign_in(&config, &roots);
        server.finish();
        assert_eq!(found.level, level, "{}", found.line());
        assert!(found.what.contains(said), "{}", found.line());
        match fix {
            Some(fix) => assert!(
                found.fix.as_deref().is_some_and(|text| text.contains(fix)),
                "{}",
                found.line()
            ),
            None => assert_eq!(found.fix, None),
        }
    }
}
