use super::*;
use crate::state::State;

/// What an answer about the sign-in client is said as, of the client and
/// the issuer's host.
type ClientSaid = fn(&str, &str) -> Finding;
/// What a 502 is said as, of the URL, the status and `web.port`.
type GatewaySaid = fn(&str, u16, u16) -> State;
/// What an answer at the exporter's path is said as, of its origin and URL.
type ExporterSaid = fn(&str, &str) -> Finding;

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
    let cases: [(String, ClientSaid); 6] = [
        (
            answer(200, json, r#"{"name":"Garrison","verified":true}"#),
            |_, _| Finding::ok(states::registered()),
        ),
        (
            answer(
                200,
                json,
                r#"{"error":"invalid_client","description":"Client metadata documents are disabled"}"#,
            ),
            |client, _| {
                let reason = Some("Client metadata documents are disabled");
                Finding::fail(states::client_refused(client, reason))
            },
        ),
        (answer(200, json, r#"{"status":"ok"}"#), |_, host| {
            Finding::fail(states::not_stalwart(host, 200, Some("application/json")))
        }),
        (
            answer(404, "text/html", "<html>Not found</html>"),
            |_, host| Finding::fail(states::not_stalwart(host, 404, Some("text/html"))),
        ),
        (
            answer(502, "text/html", "<html>Bad gateway</html>"),
            |_, host| Finding::fail(states::client_unreached(host, 502)),
        ),
        (answer(429, json, "{}"), |_, host| {
            Finding::unknown(states::client_limited(host))
        }),
    ];
    for (response, said) in cases {
        let server = garrison_testing::tls::serve_until(vec![response], 2036, 1, 1);
        let roots = Arc::new(server.roots.clone());
        let directory = tempfile::tempdir().unwrap();
        let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        config.deployment.issuer.clone_from(&server.url);
        let found = sign_in(&config, &roots);
        server.finish();
        let client = oidc::client_id(&config.deployment.public_origin);
        let host = origin(&config.deployment.issuer);
        assert_eq!(found, said(&client, host));
    }
}

/// Stalwart names itself in its discovery document, as it names itself
/// in every sign-in; doctor holds that name to `deployment.issuer` and
/// names the setting that mends a difference, or why it could not ask.
#[test]
fn the_issuer_stalwart_names_itself_is_the_one_garrison_takes() {
    use garrison_testing::http::{answer, json, serve};
    let discovery = |stalwart: &str| format!("{stalwart}/.well-known/openid-configuration");
    let issuer_of = |response: String| {
        let stalwart = serve(vec![response]);
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), &stalwart.url);
        let found = issuer(&config);
        let url = discovery(&stalwart.url);
        stalwart.requests();
        (found, url)
    };
    let configured = "https://mail.example.test";
    let named = |stated: &str| issuer_of(json(&serde_json::json!({ "issuer": stated }))).0;
    assert_eq!(
        named(configured),
        Finding::ok(states::same_issuer(configured))
    );
    assert_eq!(
        named("https://other.example.test"),
        Finding::fail(states::other_issuer(
            "https://other.example.test",
            configured
        ))
    );
    // A name garrison.toml would not keep as written: only Stalwart's side mends it.
    assert_eq!(
        named("https://other.example.test/"),
        Finding::fail(states::other_issuer_hostname(
            "https://other.example.test/",
            configured
        ))
    );
    for (response, status) in [
        (answer(404, "{}"), 404),
        (json(&serde_json::json!({"issuers": []})), 200),
        (answer(200, "<html></html>"), 200),
    ] {
        let (unread, url) = issuer_of(response);
        assert_eq!(
            unread,
            Finding::unknown(states::issuer_unknown(&states::no_issuer(&url, status)))
        );
    }
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let url = discovery(&config.deployment.stalwart_url);
    let away = issuer(&config);
    let refused = Request::get(&url).limit(DISCOVERY_LIMIT).send();
    let Err(error @ garrison_stalwart::Error::Unavailable(_)) = refused else {
        panic!("{url}: {refused:?}");
    };
    assert_eq!(
        away,
        Finding::unknown(states::issuer_unknown(&states::undiscovered(&url, error)))
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
    // Held, so that no stand-in started below is given it.
    let (_held, silent) = super::super::silent_port();
    let listening = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cases: [(u16, GatewaySaid); 2] = [
        (silent, states::web_down),
        (listening.local_addr().unwrap().port(), states::unreached),
    ];
    for (port, said) in cases {
        let server = garrison_testing::tls::serve_until(vec![answer.clone()], 2036, 1, 1);
        let roots = Arc::new(server.roots.clone());
        let directory = tempfile::tempdir().unwrap();
        let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        config.deployment.public_origin.clone_from(&server.url);
        config.web.port = port;
        let url = format!("{}/api/session", server.url);
        let found = interface(&config, &roots);
        server.finish();
        assert_eq!(found, [Finding::fail(said(&url, 502, port))]);
    }
}

/// Only Stalwart's exporter's own answer is taken for it: Prometheus text,
/// or its refusal of a scrape without its credential, which names Stalwart
/// in its challenge (measured on 1.2.0). A web page that a webmail's server
/// block answers for any path serves no metrics, and another server's
/// refusal is none of Stalwart's.
#[test]
fn only_the_exporters_own_answer_is_taken_for_it() {
    let page = "<html><body>Welcome to our webmail</body></html>";
    let exported = "# HELP stalwart_up Up.\n# TYPE stalwart_up gauge\nstalwart_up 1\n";
    let stalwarts = "WWW-Authenticate: Bearer realm=\"Stalwart Server\"\r\n";
    let others = "WWW-Authenticate: Basic realm=\"webmail\"\r\n";
    let cases: [(u16, &str, &str, &str, ExporterSaid); 4] = [
        (200, "text/html", "", page, |origin, _| {
            Finding::ok(states::metrics_private(origin))
        }),
        (200, "text/plain; version=0.0.4", "", exported, |_, url| {
            Finding::fail(states::metrics_public(url, 200))
        }),
        (401, "application/problem+json", stalwarts, "", |_, url| {
            Finding::fail(states::metrics_public(url, 401))
        }),
        (401, "text/plain", others, "", |_, url| {
            Finding::unknown(states::metrics_unread(url, 401))
        }),
    ];
    for (status, kind, more, body, said) in cases {
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
        let origin = origin(&config.deployment.issuer);
        let url = format!("{origin}/metrics/prometheus");
        assert_eq!(found, [said(origin, &url)], "{status} {kind}");
    }
}

/// An IPv6 origin is named as a URL names it, in brackets, before its port.
#[test]
fn an_ipv6_origin_is_named_in_brackets() {
    let roots = roots();
    let found = certificate("https://[::1]:1", &roots);
    let Err(failure) = probe("::1", 1, "::1", false, &roots, time::now()) else {
        panic!("TLS to [::1]:1");
    };
    assert_eq!(
        found,
        Finding::fail(states::tls_failed("[::1]:1", failure.0))
    );
}
