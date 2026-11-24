//! What visitors and Stalwart see from outside, asked from this host the way
//! they would ask: Garrison's own host name over TLS, the sign-in at the
//! issuer with the page it shows (examined as the `sign-in` check does), and
//! Stalwart's public hosts, which must not serve its metrics. And the issuer
//! Stalwart names itself, asked of its own listener.

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use garrison_collector::providers::signin;
use garrison_collector::providers::tls::probe;
use garrison_core::config::Config;
use garrison_core::json;
use garrison_core::observations::State as Observed;
use garrison_core::time;
use garrison_stalwart::http::Request;
use garrison_stalwart::{oidc, sign_in_page};
use rustls::RootCertStore;

use super::Finding;
use super::states::public as states;
use garrison_collector::fetch::{Answer, get, origin, roots};

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
    let host = if name.contains(':') {
        format!("[{name}]")
    } else {
        name.to_owned()
    };
    let shown = if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    };
    match probe(name, port, name, false, roots, time::now()) {
        Ok(probed) if probed.days < 0 => Finding::fail(states::expired(&shown, &probed.expires_at)),
        Ok(probed) if probed.days < WARN_DAYS => {
            Finding::warn(states::expiring(&shown, probed.days))
        }
        Ok(probed) => Finding::ok(states::trusted(&shown, probed.days, probed.protocol)),
        Err(failure) => Finding::fail(states::tls_failed(&shown, failure.0)),
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
            let mut findings = vec![Finding::ok(states::answers(
                &config.deployment.public_origin,
            ))];
            findings.push(match answer.header("strict-transport-security") {
                Some(_) => Finding::ok(states::hsts()),
                None => Finding::warn(states::no_hsts()),
            });
            findings
        }
        // What nginx answers where it does not reach the web service.
        Ok(answer) if matches!(answer.status, 502..=504) => {
            let port = config.web.port;
            let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            vec![Finding::fail(
                if TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_ok() {
                    states::unreached(&url, answer.status, port)
                } else {
                    states::web_down(&url, answer.status, port)
                },
            )]
        }
        Ok(answer) => vec![Finding::fail(states::other_answer(&url, answer.status))],
        Err(error) => vec![Finding::fail(states::unanswered(&url, error))],
    }
}

/// Whether `body` is the text of a Prometheus exporter: a `# TYPE` line or
/// a sample, a series' name and a number, and no markup, which a web page
/// has.
fn exported(body: &str) -> bool {
    let sample = |line: &str| {
        let name: String = line
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':'))
            .collect();
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && line.len() > name.len()
            && line
                .split_whitespace()
                .last()
                .is_some_and(|value| value.parse::<f64>().is_ok())
    };
    !body.contains('<')
        && body
            .lines()
            .any(|line| line.starts_with("# TYPE ") || sample(line))
}

/// The exporter that `stalwart setup` enables must not answer from outside.
/// Only its own answer counts: its text, or 401 for a scrape without its
/// credential with a challenge that names Stalwart (measured on 1.1.0); a
/// page that answers every path serves no metrics.
pub(super) fn metrics(config: &Config, roots: &Arc<RootCertStore>) -> Vec<Finding> {
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
                Ok(answer)
                    if matches!(answer.status, 403 | 404 | 410)
                        || (answer.status == 200 && !exported(&answer.body)) =>
                {
                    Finding::ok(states::metrics_private(origin))
                }
                Ok(answer) if answer.status == 200 || challenged(&answer) => {
                    Finding::fail(states::metrics_public(&url, answer.status))
                }
                Ok(answer) => Finding::unknown(states::metrics_unread(&url, answer.status)),
                Err(error) => Finding::unknown(states::metrics_unanswered(&url, error)),
            }
        })
        .collect()
}

/// Whether `answer` is the exporter's refusal of a scrape without its
/// credential, whose challenge names Stalwart.
fn challenged(answer: &Answer) -> bool {
    answer.status == 401
        && answer
            .header("www-authenticate")
            .is_some_and(|challenge| challenge.contains("realm=\"Stalwart Server\""))
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
        Err(error) => return Finding::fail(states::client_unanswered(&url, error)),
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
        (_, Some(value)) if value["verified"] == true => Finding::ok(states::registered()),
        (_, Some(value)) => {
            let reason = value["description"]
                .as_str()
                .or_else(|| value["error"].as_str());
            Finding::fail(states::client_refused(&client, reason))
        }
        (429, None) => Finding::unknown(states::client_limited(host)),
        (502..=504, None) => Finding::fail(states::client_unreached(host, answer.status)),
        (status, None) => Finding::fail(states::not_stalwart(
            host,
            status,
            answer.header("content-type"),
        )),
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
        .map_err(|error| states::undiscovered(url, error))?;
    Some(answer.status)
        .filter(|status| *status == 200)
        .and_then(|_| json::parse(&answer.body, DISCOVERY_LIMIT).ok())
        .and_then(|document| document.get("issuer")?.as_str().map(str::to_owned))
        .filter(|issuer| issuer.len() <= 256 && issuer.bytes().all(|byte| byte.is_ascii_graphic()))
        .ok_or_else(|| states::no_issuer(url, answer.status))
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
        Err(why) => return Finding::unknown(states::issuer_unknown(&why)),
    };
    if stated == *configured {
        return Finding::ok(states::same_issuer(&stated));
    }
    Finding::fail(if kept_as_written(&stated) {
        states::other_issuer(&stated, configured)
    } else {
        states::other_issuer_hostname(&stated, configured)
    })
}

/// Stalwart's sign-in page as a visitor's browser loads it, with the files it
/// names; the `sign-in` check examines it the same way every few minutes.
pub(super) fn sign_in_page(config: &Config, roots: &Arc<RootCertStore>) -> Finding {
    // Asked by hand: no run's time to keep, the certificate judged by the clock.
    let examined = signin::check(&config.deployment, signin::Asking::by_hand(roots));
    match examined.state {
        Observed::Ok => Finding::ok(states::page_shown(examined.what)),
        Observed::Failed => Finding::fail(states::page_failed(examined.what, examined.fix)),
        _ => Finding::unknown(states::page_unknown(examined.what)),
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
