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
        assert!(found.state.text.contains(said), "{}", found.line());
        match fix {
            Some(fix) => assert!(
                found
                    .state
                    .fix
                    .as_deref()
                    .is_some_and(|text| text.contains(fix)),
                "{}",
                found.line()
            ),
            None => assert_eq!(found.state.fix, None),
        }
    }
}

/// Stalwart names itself in its discovery document, as it names itself
/// in every sign-in; doctor holds that name to `deployment.issuer` and
/// names the setting that mends a difference, or why it could not ask.
#[test]
fn the_issuer_stalwart_names_itself_is_the_one_garrison_takes() {
    use garrison_testing::http::{answer, json, serve};
    let issuer_of = |response: String| {
        let stalwart = serve(vec![response]);
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), &stalwart.url);
        let found = issuer(&config);
        stalwart.requests();
        found
    };
    let same = issuer_of(json(
        &serde_json::json!({"issuer": "https://mail.example.test"}),
    ));
    assert_eq!(
        (same.level, same.state.text.as_str()),
        (
            Level::Ok,
            "Stalwart names itself https://mail.example.test, as deployment.issuer does"
        )
    );
    let other = issuer_of(json(
        &serde_json::json!({"issuer": "https://other.example.test"}),
    ));
    assert_eq!(
        (other.level, other.state.text.as_str()),
        (
            Level::Fail,
            "Stalwart names itself https://other.example.test, but deployment.issuer is \
             https://mail.example.test, so every sign-in fails at Garrison's callback"
        )
    );
    assert_eq!(
        other.state.fix.as_deref(),
        Some(
            "Set issuer = \"https://other.example.test\" under [deployment] and restart \
             garrison-web, or make mail.example.test Stalwart's Default Hostname and reload its \
             settings."
        )
    );
    // A name garrison.toml would not keep as written: only Stalwart's side mends it.
    let slashed = issuer_of(json(
        &serde_json::json!({"issuer": "https://other.example.test/"}),
    ));
    assert_eq!(
        slashed.state.fix.as_deref(),
        Some("Make mail.example.test Stalwart's Default Hostname and reload its settings.")
    );
    for (response, why) in [
        (answer(404, "{}"), "answered 404 without an issuer"),
        (
            json(&serde_json::json!({"issuers": []})),
            "answered 200 without an issuer",
        ),
        (
            answer(200, "<html></html>"),
            "answered 200 without an issuer",
        ),
    ] {
        let unread = issuer_of(response);
        assert_eq!(unread.level, Level::Unknown, "{}", unread.line());
        assert!(unread.state.text.contains(why), "{}", unread.state.text);
        assert!(
            unread.state.text.ends_with(garrison_stalwart::SUPPORTED),
            "{}",
            unread.state.text
        );
    }
    let directory = tempfile::tempdir().unwrap();
    let away = issuer(&garrison_testing::config(
        directory.path(),
        "http://127.0.0.1:9",
    ));
    assert_eq!(away.level, Level::Unknown);
    assert!(
        away.state.text.contains("Stalwart did not answer at"),
        "{}",
        away.state.text
    );
}

#[test]
fn an_issuer_is_kept_as_written_only_in_the_form_garrison_toml_keeps() {
    for (text, kept) in [
        ("https://mail.example.org", true),
        ("https://mail.example.org:8443", true),
        ("https://mail.example.org/", false),
        ("https://mail.example.org:443", false),
        ("https://Mail.example.org", false),
        ("http://mail.example.org", false),
        ("https://mail.example.org/realm", false),
    ] {
        assert_eq!(kept_as_written(text), kept, "{text}");
    }
}

/// nginx answers 502: where nothing listens on web.port, as before the web
/// service was restarted after a change of the port, doctor names the
/// restart; where something does, the lines that name nginx's include or
/// the SELinux module.
#[test]
fn a_502_names_the_restart_where_nothing_listens_on_web_port() {
    let gateway = "<html>Bad gateway</html>";
    let answer = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{gateway}",
        gateway.len()
    );
    let silent = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let listening = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    for (port, fix) in [
        (silent, "systemctl restart garrison-web.service"),
        (
            listening.local_addr().unwrap().port(),
            "the lines above name an include or an SELinux module",
        ),
    ] {
        let server = garrison_testing::tls::serve_until(vec![answer.clone()], 2036, 1, 1);
        let roots = Arc::new(server.roots.clone());
        let directory = tempfile::tempdir().unwrap();
        let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        config.deployment.public_origin.clone_from(&server.url);
        config.web.port = port;
        let found = interface(&config, &roots);
        server.finish();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0]
                .state
                .fix
                .as_deref()
                .is_some_and(|text| text.contains(fix)),
            "{}",
            found[0].line()
        );
    }
}

/// Only Stalwart's exporter's own answer is taken for it: Prometheus text,
/// or its refusal of a scrape without its credential, which names Stalwart
/// in its challenge (measured on 1.1.0). A web page that a webmail's server
/// block answers for any path serves no metrics, and another server's
/// refusal is none of Stalwart's.
#[test]
fn only_the_exporters_own_answer_is_taken_for_it() {
    let page = "<html><body>Welcome to our webmail</body></html>";
    let exported = "# HELP stalwart_up Up.\n# TYPE stalwart_up gauge\nstalwart_up 1\n";
    let stalwarts = "WWW-Authenticate: Bearer realm=\"Stalwart Server\"\r\n";
    let others = "WWW-Authenticate: Basic realm=\"webmail\"\r\n";
    for (status, kind, more, body, public) in [
        (200, "text/html", "", page, false),
        (200, "text/plain; version=0.0.4", "", exported, true),
        (401, "application/problem+json", stalwarts, "", true),
        (401, "text/plain", others, "", false),
    ] {
        let server = garrison_testing::tls::serve_until(
            vec![format!(
                "HTTP/1.1 {status} X\r\nContent-Type: {kind}\r\n{more}Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )],
            2036,
            1,
            1,
        );
        let roots = Arc::new(server.roots.clone());
        let directory = tempfile::tempdir().unwrap();
        let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        config.deployment.issuer.clone_from(&server.url);
        config.deployment.admin_url = format!("{}/admin/", server.url);
        let found = metrics(&config, &roots);
        server.finish();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            found[0].level == Level::Fail,
            public,
            "{status} {kind}: {}",
            found[0].line()
        );
    }
}

/// An IPv6 origin is named as a URL names it, in brackets, before its port.
#[test]
fn an_ipv6_origin_is_named_in_brackets() {
    let found = certificate("https://[::1]:1", &roots());
    assert!(
        found.state.text.starts_with("TLS to [::1]:1: "),
        "{}",
        found.state.text
    );
}
