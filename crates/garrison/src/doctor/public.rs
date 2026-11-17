//! What visitors and Stalwart see from outside, asked from this host the way
//! they would ask: Garrison's own host name over TLS, the sign-in at the
//! issuer with the page it shows (examined as the `sign-in` check does), and
//! Stalwart's public hosts, which must not serve its metrics. And the issuer
//! Stalwart names itself, asked of its own listener.

use std::sync::Arc;

use garrison_collector::providers::signin;
use garrison_collector::providers::tls::probe;
use garrison_core::config::Config;
use garrison_core::json;
use garrison_core::observations::State;
use garrison_core::time;
use garrison_stalwart::http::Request;
use garrison_stalwart::{Error, SUPPORTED, oidc, sign_in_page};
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

pub(super) fn interface(config: &Config, roots: &Arc<RootCertStore>) -> Vec<Finding> {
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
        // What nginx answers where it does not reach the web service.
        Ok(answer) if matches!(answer.status, 502..=504) => vec![Finding::fail(
            format!(
                "{url} answers {}: nginx does not reach Garrison's web service on \
                 127.0.0.1:{}",
                answer.status, config.web.port
            ),
            format!(
                "`systemctl status {}` says whether it runs; the lines above name an include or \
                 an SELinux module for another port.",
                crate::units::WEB
            ),
        )],
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

/// Whether Stalwart knows Garrison's sign-in client. Stalwart answers 200
/// with JSON that holds `verified` or, for a client it refuses, `error`
/// (measured on 1.1.0); any other answer is not Stalwart's.
pub(super) fn sign_in(config: &Config, roots: &Arc<RootCertStore>) -> Finding {
    let client = oidc::client_id(&config.deployment.public_origin);
    let url = format!(
        "{}/api/auth/client?{}",
        config.deployment.issuer,
        sign_in_page::query(&config.deployment.public_origin)
    );
    let answer = match get(&url, roots) {
        Ok(answer) => answer,
        Err(error) => {
            return Finding::fail(
                format!("{url}: {error}"),
                "Check that the issuer is reachable from this host.",
            );
        }
    };
    let host = origin(&config.deployment.issuer);
    let stalwarts = Some(answer.status)
        .filter(|status| *status == 200)
        .and_then(|_| serde_json::from_str::<serde_json::Value>(&answer.body).ok())
        .filter(|value| {
            value
                .get("verified")
                .is_some_and(serde_json::Value::is_boolean)
                || value.get("error").is_some_and(serde_json::Value::is_string)
        });
    match (answer.status, stalwarts) {
        (_, Some(value)) if value["verified"] == true => {
            Finding::ok("Stalwart knows Garrison's sign-in client as registered")
        }
        (_, Some(value)) => {
            let reason = value["description"]
                .as_str()
                .or_else(|| value["error"].as_str())
                .unwrap_or("no reason given");
            Finding::fail(
                format!("Stalwart refuses Garrison's sign-in client {client}: {reason}"),
                "Run `garrison stalwart setup` again.",
            )
        }
        (429, None) => Finding::unknown(format!(
            "whether Stalwart knows Garrison's sign-in client: {host} answered 429 (Stalwart's \
             rate limit); ask again in a minute"
        )),
        (502..=504, None) => Finding::fail(
            format!(
                "{host} answers {} for Garrison's sign-in client: its proxy does not reach \
                 Stalwart",
                answer.status
            ),
            format!("See that Stalwart runs and that the proxy for {host} reaches it."),
        ),
        (status, None) => Finding::fail(
            format!(
                "{host} answers {status} ({}) for Garrison's sign-in client, not Stalwart's JSON",
                answer.header("content-type").unwrap_or("no content type")
            ),
            format!("The proxy for {host} must pass /api/auth/client and /api/auth to Stalwart."),
        ),
    }
}

/// As much of Stalwart's discovery document as doctor reads.
const DISCOVERY_LIMIT: usize = 64 * 1024;

/// Whether `text` is written as garrison.toml keeps an issuer, so that
/// writing it there names the same: `https://host[:port]` in lower case,
/// without a path, a trailing slash or port 443.
fn kept_as_written(text: &str) -> bool {
    text.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && !rest.ends_with(":443")
            && rest.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-:[]".contains(&byte)
            })
    })
}

/// The issuer Stalwart's discovery document at `url` names, or why there is
/// none to compare.
fn stated_issuer(url: &str) -> Result<String, String> {
    let answer = Request::get(url)
        .limit(DISCOVERY_LIMIT)
        .send()
        .map_err(|error| match error {
            Error::Unavailable(why) => format!("Stalwart did not answer at {url} ({why})"),
            Error::Limited(why) => format!("Stalwart's rate limit ({why}); ask again in a minute"),
            Error::Unreadable(why)
            | Error::Denied(why)
            | Error::InvalidToken(why)
            | Error::Misconfigured(why) => {
                format!("{url}: {why}, which this release of Garrison does not read; {SUPPORTED}")
            }
        })?;
    Some(answer.status)
        .filter(|status| *status == 200)
        .and_then(|_| json::parse(&answer.body, DISCOVERY_LIMIT).ok())
        .and_then(|document| document.get("issuer")?.as_str().map(str::to_owned))
        .filter(|issuer| issuer.len() <= 256 && issuer.bytes().all(|byte| byte.is_ascii_graphic()))
        .ok_or_else(|| {
            format!(
                "{url} answered {} without an issuer this release of Garrison reads; {SUPPORTED}",
                answer.status
            )
        })
}

/// The issuer Stalwart names itself, asked of its own listener: every
/// sign-in comes back under that name (measured on 1.1.0: `https://` and
/// its Default Hostname, whatever host was asked), and Garrison's callback
/// takes only `deployment.issuer`.
pub(super) fn issuer(config: &Config) -> Finding {
    let configured = &config.deployment.issuer;
    let url = format!(
        "{}/.well-known/openid-configuration",
        config.deployment.stalwart_url.trim_end_matches('/')
    );
    let stated = match stated_issuer(&url) {
        Ok(stated) => stated,
        Err(why) => return Finding::unknown(format!("which issuer Stalwart names itself: {why}")),
    };
    if stated == *configured {
        return Finding::ok(format!(
            "Stalwart names itself {stated}, as deployment.issuer does"
        ));
    }
    let host = configured.strip_prefix("https://").unwrap_or(configured);
    let fix = if kept_as_written(&stated) {
        format!(
            "Set issuer = \"{stated}\" under [deployment] and restart garrison-web, or make \
             {host} Stalwart's Default Hostname."
        )
    } else {
        format!("Make {host} Stalwart's Default Hostname and reload its settings.")
    };
    Finding::fail(
        format!(
            "Stalwart names itself {stated}, but deployment.issuer is {configured}, so every \
             sign-in fails at Garrison's callback"
        ),
        fix,
    )
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
    findings.push(issuer(config));
    findings.push(sign_in_page(config, &roots));
    findings
}

#[cfg(test)]
mod tests;
