//! Hosts broken in what doctor asks from outside, the way visitors and
//! Stalwart would ask.

use std::sync::Arc;

use garrison_core::time;
use garrison_testing::http::{json, serve};
use garrison_testing::tls::serve_until;

use super::super::Level;
use super::super::{keys, public};
use super::Broken;

/// The day `days` from now, as a test certificate's end takes it.
fn days_ahead(days: i64) -> (i32, u8, u8) {
    let then = time::now() + time::SignedDuration::from_hours(24 * days);
    let day = then.strftime("%Y %m %d").to_string();
    let parts: Vec<&str> = day.split(' ').collect();
    (
        parts[0].parse().unwrap(),
        parts[1].parse().unwrap(),
        parts[2].parse().unwrap(),
    )
}

/// Garrison's own name on a port of its own, `https://host:port`, whose
/// certificate ends in a few days: doctor must probe that port, whatever
/// listens on 443 of the name.
pub(super) fn origin_with_a_port() -> Broken {
    let (year, month, day) = days_ahead(5);
    let server = serve_until(vec![String::new()], year, month, day);
    let roots = Arc::new(server.roots.clone());
    let found = vec![public::certificate(&server.url, &roots)];
    server.finish();
    Broken {
        host: "public_origin with a port, its certificate ending in five days",
        found,
        said: (Level::Warn, "doctor-certificate-expiring"),
    }
}

/// The issuer's name answers Garrison's question about its sign-in client
/// with a web page, as a webmail on the same name may: that is no answer of
/// Stalwart's, and setup, which registers the client, mends nothing there.
pub(super) fn issuer_answers_with_a_web_page() -> Broken {
    let page = "<html><body>Welcome to our webmail</body></html>";
    let server = serve_until(
        vec![format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{page}",
            page.len()
        )],
        2036,
        1,
        1,
    );
    let roots = Arc::new(server.roots.clone());
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    config.deployment.issuer.clone_from(&server.url);
    let found = vec![public::sign_in(&config, &roots)];
    server.finish();
    Broken {
        host: "an issuer whose answer about the sign-in client is a web page",
        found,
        said: (Level::Fail, "doctor-client-not-stalwart"),
    }
}

/// Stalwart names itself another issuer than `deployment.issuer`, as after
/// its Default Hostname changed: every sign-in comes back under that name.
pub(super) fn issuer_states_another_name() -> Broken {
    let stalwart = serve(vec![json(&serde_json::json!({
        "issuer": "https://other.example.test"
    }))]);
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), &stalwart.url);
    let found = vec![public::issuer(&config)];
    stalwart.requests();
    Broken {
        host: "Stalwart naming itself another issuer than garrison.toml",
        found,
        said: (Level::Fail, "doctor-issuer-other"),
    }
}

/// nginx answers 502 for Garrison's name: it does not reach the web
/// service, so the include nginx has, which "must include garrison.conf"
/// would name, is not what is wrong.
pub(super) fn nginx_answers_502() -> Broken {
    let gateway = "<html>Bad gateway</html>";
    let server = serve_until(
        vec![format!(
            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{gateway}",
            gateway.len()
        )],
        2036,
        1,
        1,
    );
    let roots = Arc::new(server.roots.clone());
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    config.deployment.public_origin.clone_from(&server.url);
    // Where nothing listens, as before garrison-web was restarted.
    let (_held, port) = super::super::silent_port();
    config.web.port = port;
    let found = public::interface(&config, &roots);
    server.finish();
    Broken {
        host: "nginx answering 502 for Garrison",
        found,
        said: (Level::Fail, "doctor-interface-web-down"),
    }
}

/// A TLS server standing in for one of the installation's names, answering
/// `status` with `body` of `kind`.
fn answering(status: u16, kind: &str, body: &str) -> garrison_testing::tls::Server {
    serve_until(
        vec![format!(
            "HTTP/1.1 {status} X\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )],
        2036,
        1,
        1,
    )
}

/// Garrison answers without Strict-Transport-Security, as behind a server
/// block that does without the include.
pub(super) fn no_hsts() -> Broken {
    let server = answering(200, "application/json", r#"{"session":null}"#);
    let roots = Arc::new(server.roots.clone());
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    config.deployment.public_origin.clone_from(&server.url);
    let found = public::interface(&config, &roots);
    server.finish();
    Broken {
        host: "Garrison answering without Strict-Transport-Security",
        found,
        said: (Level::Warn, "doctor-hsts-missing"),
    }
}

/// Stalwart's metrics exporter answers under the issuer's name.
pub(super) fn metrics_public() -> Broken {
    let server = answering(200, "text/plain", "stalwart_up 1");
    let roots = Arc::new(server.roots.clone());
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    config.deployment.issuer.clone_from(&server.url);
    config.deployment.admin_url = format!("{}/admin/", server.url);
    let found = public::metrics(&config, &roots);
    server.finish();
    Broken {
        host: "Stalwart's metrics exporter served under the issuer's name",
        found,
        said: (Level::Fail, "doctor-metrics-public"),
    }
}

/// The issuer's name answers 404 for Stalwart's sign-in page.
pub(super) fn sign_in_page_answers_404() -> Broken {
    let server = answering(404, "text/html", "<html>Not found</html>");
    let roots = Arc::new(server.roots.clone());
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    config.deployment.issuer.clone_from(&server.url);
    let found = vec![public::sign_in_page(&config, &roots)];
    server.finish();
    Broken {
        host: "an issuer's name that answers 404 for Stalwart's sign-in page",
        found,
        said: (Level::Fail, "doctor-sign-in-page-failed"),
    }
}

/// Stalwart no longer knows the broker's API key, as after the key was
/// deleted in the Stalwart WebUI or Stalwart's data put back from before
/// the last rotation: nobody can sign in.
pub(super) fn stalwart_does_not_know_the_brokers_key() -> Broken {
    let stalwart = serve(vec![
        garrison_testing::http::answer(401, ""),
        garrison_testing::http::answer(401, ""),
    ]);
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), &stalwart.url);
    let credentials = garrison_testing::credentials(&config);
    garrison_testing::write_private(
        &credentials.path(&config.collector.native_key),
        b"collector-key-0123456789",
    );
    let found = keys::checks(&config, &credentials);
    stalwart.requests();
    Broken {
        host: "a broker's API key Stalwart no longer knows",
        found,
        said: (Level::Fail, "doctor-key-not-known"),
    }
}
