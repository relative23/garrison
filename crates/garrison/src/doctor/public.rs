//! What visitors and Stalwart see from outside, asked from this host the way
//! they would ask: Garrison's own host name over TLS, the sign-in at the
//! issuer with the page it shows (examined as the `sign-in` check does), and
//! Stalwart's public hosts, which must not serve its metrics.

use std::sync::Arc;

use garrison_collector::providers::signin;
use garrison_collector::providers::tls::probe;
use garrison_core::config::Config;
use garrison_core::observations::State;
use garrison_core::time;
use garrison_stalwart::{oidc, sign_in_page};
use rustls::RootCertStore;

use super::Finding;
use garrison_collector::fetch::{get, origin, roots};

/// Fewer days than this before the certificate expires earn a warning.
const WARN_DAYS: i64 = 14;

/// The host and the port of an origin: `https://host` is port 443, and an
/// IPv6 address is named without its brackets.
fn authority(origin: &str) -> (&str, u16) {
    let rest = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    let (host, port) = match rest.strip_prefix('[') {
        Some(bracketed) => bracketed
            .split_once(']')
            .map_or((bracketed, ""), |(host, after)| {
                (host, after.trim_start_matches(':'))
            }),
        None => rest.rsplit_once(':').unwrap_or((rest, "")),
    };
    (host, port.parse().unwrap_or(443))
}

/// The certificate a visitor's browser meets under Garrison's own name, on
/// the port `public_origin` names.
pub(super) fn certificate(origin: &str, roots: &Arc<RootCertStore>) -> Finding {
    let (name, port) = authority(origin);
    let shown = if port == 443 {
        name.to_owned()
    } else {
        format!("{name}:{port}")
    };
    match probe(name, port, name, false, roots, time::now()) {
        Ok(probed) if probed.days < 0 => Finding::fail(
            format!(
                "the certificate of {shown} expired on {}",
                probed.expires_at
            ),
            "Renew it (certbot renew) and reload nginx.",
        ),
        Ok(probed) if probed.days < WARN_DAYS => Finding::warn(
            format!("the certificate of {shown} expires in {} days", probed.days),
            "Check that certificate renewal runs.",
        ),
        Ok(probed) => Finding::ok(format!(
            "{shown} presents a trusted certificate for {} more days ({})",
            probed.days, probed.protocol
        )),
        Err(failure) => Finding::fail(
            format!("TLS to {shown}: {}", failure.0),
            "Check DNS, the certificate and the nginx server block for this name.",
        ),
    }
}

/// Garrison's answer to a visitor without a session: 200 and no session.
fn visitor_answer(status: u16, body: &str) -> bool {
    status == 200
        && serde_json::from_str::<serde_json::Value>(body)
            .is_ok_and(|value| value.get("session").is_some_and(serde_json::Value::is_null))
}

fn interface(config: &Config, roots: &Arc<RootCertStore>) -> Vec<Finding> {
    let url = format!("{}/api/session", config.deployment.public_origin);
    match get(&url, roots) {
        Ok(answer) if visitor_answer(answer.status, &answer.body) => {
            let mut findings = vec![Finding::ok(format!(
                "Garrison answers at {}",
                config.deployment.public_origin
            ))];
            findings.push(match answer.header("strict-transport-security") {
                Some(_) => Finding::ok("nginx sends Strict-Transport-Security"),
                None => Finding::warn(
                    "no Strict-Transport-Security header",
                    "Include /etc/nginx/snippets/garrison.conf in the server block; it sets the header.",
                ),
            });
            findings
        }
        Ok(answer) => vec![Finding::fail(
            format!(
                "{url} answers {} instead of Garrison's answer to a visitor",
                answer.status
            ),
            "The server block for this name must include /etc/nginx/snippets/garrison.conf.",
        )],
        Err(error) => vec![Finding::fail(
            format!("{url}: {error}"),
            "Check DNS, the certificate and the nginx server block for this name.",
        )],
    }
}

/// The exporter that `stalwart setup` enables must not answer from outside.
fn metrics(config: &Config, roots: &Arc<RootCertStore>) -> Vec<Finding> {
    let mut origins = vec![origin(&config.deployment.issuer)];
    let admin = origin(&config.deployment.admin_url);
    if !origins.contains(&admin) {
        origins.push(admin);
    }
    origins
        .into_iter()
        .map(|origin| {
            let url = format!("{origin}/metrics/prometheus");
            match get(&url, roots) {
                Ok(answer) if matches!(answer.status, 403 | 404 | 410) => {
                    Finding::ok(format!("{origin} does not serve Stalwart's metrics"))
                }
                Ok(answer) if matches!(answer.status, 200 | 401) => Finding::fail(
                    format!("{url} answers {}: Stalwart's metrics exporter is public", answer.status),
                    "Add `include /etc/nginx/snippets/garrison-stalwart-server*.conf;` to that server block.",
                ),
                Ok(answer) => Finding::unknown(format!("{url} answers {}", answer.status)),
                Err(error) => Finding::unknown(format!("{url}: {error}")),
            }
        })
        .collect()
}

fn sign_in(config: &Config, roots: &Arc<RootCertStore>) -> Finding {
    let client = oidc::client_id(&config.deployment.public_origin);
    let url = format!(
        "{}/api/auth/client?{}",
        config.deployment.issuer,
        sign_in_page::query(&config.deployment.public_origin)
    );
    match get(&url, roots) {
        Ok(answer) if answer.status == 200 => {
            let value: serde_json::Value = serde_json::from_str(&answer.body).unwrap_or_default();
            if value["verified"] == true {
                Finding::ok("Stalwart knows Garrison's sign-in client as registered")
            } else {
                let reason = value["description"]
                    .as_str()
                    .or_else(|| value["error"].as_str())
                    .unwrap_or("no reason given");
                Finding::fail(
                    format!("Stalwart refuses Garrison's sign-in client {client}: {reason}"),
                    "Run `garrison stalwart setup` again.",
                )
            }
        }
        Ok(answer) => Finding::fail(
            format!(
                "the issuer answers {} for Garrison's sign-in client",
                answer.status
            ),
            "Run `garrison stalwart setup` again.",
        ),
        Err(error) => Finding::fail(
            format!("{url}: {error}"),
            "Check that the issuer is reachable from this host.",
        ),
    }
}

/// Stalwart's sign-in page as a visitor's browser loads it, with the files it
/// names; the `sign-in` check examines it the same way every few minutes.
fn sign_in_page(config: &Config, roots: &Arc<RootCertStore>) -> Finding {
    // Asked by hand: no run's time to keep, the certificate judged by the clock.
    let examined = signin::check(&config.deployment, signin::Asking::by_hand(roots));
    match examined.state {
        State::Ok => Finding::ok(examined.what),
        State::Failed => Finding::fail(examined.what, examined.fix.unwrap_or_default()),
        _ => Finding::unknown(examined.what),
    }
}

pub(super) fn checks(config: &Config) -> Vec<Finding> {
    let roots = roots();
    let mut findings = vec![certificate(&config.deployment.public_origin, &roots)];
    findings.extend(interface(config, &roots));
    findings.extend(metrics(config, &roots));
    findings.push(sign_in(config, &roots));
    findings.push(sign_in_page(config, &roots));
    findings
}

#[cfg(test)]
mod tests {
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
}
