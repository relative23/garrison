//! The states of what visitors and Stalwart see (`doctor/public.rs`).

use std::fmt::Display;

use garrison_stalwart::{Error, SUPPORTED};

use crate::state::State;
use crate::units;

/// What mends a name whose TLS or answer fails.
const NAME: &str = "Check DNS, the certificate and the nginx server block for this name.";

/// Why Stalwart's discovery document at `url` could not be read.
pub(in crate::doctor) fn undiscovered(url: &str, error: Error) -> String {
    match error {
        Error::Unavailable(why) => super::no_answer(url, why),
        Error::Limited(why) => format!("Stalwart's rate limit ({why}); ask again in a minute"),
        Error::Unreadable(why)
        | Error::Denied(why)
        | Error::InvalidToken(why)
        | Error::Misconfigured(why) => {
            format!("{url}: {why}, which this release of Garrison does not read; {SUPPORTED}")
        }
    }
}

/// Why the discovery document at `url`, answered with `status`, names no
/// issuer.
pub(in crate::doctor) fn no_issuer(url: &str, status: u16) -> String {
    format!("{url} answered {status} without an issuer this release of Garrison reads; {SUPPORTED}")
}

pub(in crate::doctor) fn expired(shown: &str, date: impl Display) -> State {
    let text = format!("the certificate of {shown} expired on {date}");
    State::new("doctor-certificate-expired", text)
        .with_fix("Renew it (certbot renew) and reload nginx.")
}

pub(in crate::doctor) fn expiring(shown: &str, days: i64) -> State {
    let text = format!("the certificate of {shown} expires in {days} days");
    State::new("doctor-certificate-expiring", text).with_fix("Check that certificate renewal runs.")
}

pub(in crate::doctor) fn trusted(shown: &str, days: i64, protocol: impl Display) -> State {
    let text = format!("{shown} presents a trusted certificate for {days} more days ({protocol})");
    State::new("doctor-certificate-valid", text)
}

pub(in crate::doctor) fn tls_failed(shown: &str, why: impl Display) -> State {
    let text = format!("TLS to {shown}: {why}");
    State::new("doctor-certificate-tls-failed", text).with_fix(NAME)
}

pub(in crate::doctor) fn answers(origin: &str) -> State {
    let text = format!("Garrison answers at {origin}");
    State::new("doctor-interface-answers", text)
}

/// nginx answers `status` for `url`: it does not reach the web service on
/// `port`.
fn unreachable(url: &str, status: u16, port: u16) -> String {
    format!(
        "{url} answers {status}: nginx does not reach Garrison's web service on 127.0.0.1:{port}"
    )
}

/// That, where something listens on `port`.
pub(in crate::doctor) fn unreached(url: &str, status: u16, port: u16) -> State {
    State::new("doctor-interface-unreached", unreachable(url, status, port)).with_fix(format!(
        "Something listens on 127.0.0.1:{port}: the lines above name an include or an SELinux \
         module for another port."
    ))
}

/// That, where nothing listens on `port`.
pub(in crate::doctor) fn web_down(url: &str, status: u16, port: u16) -> State {
    State::new("doctor-interface-web-down", unreachable(url, status, port)).with_fix(format!(
        "Nothing listens on 127.0.0.1:{port}: `systemctl restart {0}` starts the web service on \
         web.port, and `systemctl status {0}` says why it does not run.",
        units::WEB
    ))
}

pub(in crate::doctor) fn other_answer(url: &str, status: u16) -> State {
    let text = format!("{url} answers {status} instead of Garrison's answer to a visitor");
    State::new("doctor-interface-other-answer", text)
        .with_fix("The server block for this name must include /etc/nginx/snippets/garrison.conf.")
}

pub(in crate::doctor) fn unanswered(url: &str, error: impl Display) -> State {
    State::new("doctor-interface-unanswered", format!("{url}: {error}")).with_fix(NAME)
}

pub(in crate::doctor) fn hsts() -> State {
    State::new("doctor-hsts-sent", "nginx sends Strict-Transport-Security")
}

pub(in crate::doctor) fn no_hsts() -> State {
    State::new("doctor-hsts-missing", "no Strict-Transport-Security header").with_fix(
        "Include /etc/nginx/snippets/garrison.conf in the server block; it sets the header.",
    )
}

pub(in crate::doctor) fn metrics_private(origin: &str) -> State {
    let text = format!("{origin} does not serve Stalwart's metrics");
    State::new("doctor-metrics-private", text)
}

pub(in crate::doctor) fn metrics_public(url: &str, status: u16) -> State {
    let text = format!("{url} answers {status}: Stalwart's metrics exporter is public");
    State::new("doctor-metrics-public", text).with_fix(
        "Add `include /etc/nginx/snippets/garrison-stalwart-server*.conf;` to that server block.",
    )
}

pub(in crate::doctor) fn metrics_unread(url: &str, status: u16) -> State {
    State::new("doctor-metrics-unread", format!("{url} answers {status}"))
}

pub(in crate::doctor) fn metrics_unanswered(url: &str, error: impl Display) -> State {
    State::new("doctor-metrics-unanswered", format!("{url}: {error}"))
}

pub(in crate::doctor) fn registered() -> State {
    let text = "Stalwart knows Garrison's sign-in client as registered";
    State::new("doctor-client-registered", text)
}

/// Stalwart refuses the sign-in client `client`, giving `reason` where it
/// gives one.
pub(in crate::doctor) fn client_refused(client: &str, reason: Option<&str>) -> State {
    let reason = reason.unwrap_or("no reason given");
    let text = format!("Stalwart refuses Garrison's sign-in client {client}: {reason}");
    State::new("doctor-client-refused", text).with_fix("Run `garrison stalwart setup` again.")
}

pub(in crate::doctor) fn client_unanswered(url: &str, error: impl Display) -> State {
    State::new("doctor-client-unanswered", format!("{url}: {error}"))
        .with_fix("Check that the issuer is reachable from this host.")
}

pub(in crate::doctor) fn client_limited(host: &str) -> State {
    let text = format!(
        "whether Stalwart knows Garrison's sign-in client: {host} answered 429 (Stalwart's \
         rate limit); ask again in a minute"
    );
    State::new("doctor-client-limited", text)
}

pub(in crate::doctor) fn client_unreached(host: &str, status: u16) -> State {
    let text = format!(
        "{host} answers {status} for Garrison's sign-in client: its proxy does not reach \
         Stalwart"
    );
    State::new("doctor-client-unreached", text).with_fix(format!(
        "See that Stalwart runs and that the proxy for {host} reaches it."
    ))
}

/// `host` answers `status` with content of `kind`, where it names one.
pub(in crate::doctor) fn not_stalwart(host: &str, status: u16, kind: Option<&str>) -> State {
    let kind = kind.unwrap_or("no content type");
    let text = format!(
        "{host} answers {status} ({kind}) for Garrison's sign-in client, not Stalwart's JSON"
    );
    State::new("doctor-client-not-stalwart", text).with_fix(format!(
        "The proxy for {host} must pass /api/auth/client and /api/auth to Stalwart."
    ))
}

pub(in crate::doctor) fn issuer_unknown(why: &str) -> State {
    let text = format!("which issuer Stalwart names itself: {why}");
    State::new("doctor-issuer-unknown", text)
}

pub(in crate::doctor) fn same_issuer(stated: &str) -> State {
    let text = format!("Stalwart names itself {stated}, as deployment.issuer does");
    State::new("doctor-issuer-same", text)
}

/// Stalwart names itself `stated`, but garrison.toml `configured`.
fn named_otherwise(stated: &str, configured: &str) -> String {
    format!(
        "Stalwart names itself {stated}, but deployment.issuer is {configured}, so every \
         sign-in fails at Garrison's callback"
    )
}

/// The host of `configured`, which Stalwart's Default Hostname is to be.
fn host(configured: &str) -> &str {
    configured.strip_prefix("https://").unwrap_or(configured)
}

/// That, where garrison.toml can keep `stated` as written.
pub(in crate::doctor) fn other_issuer(stated: &str, configured: &str) -> State {
    let host = host(configured);
    State::new("doctor-issuer-other", named_otherwise(stated, configured)).with_fix(format!(
        "Set issuer = \"{stated}\" under [deployment] and restart garrison-web, or make \
         {host} Stalwart's Default Hostname and reload its settings."
    ))
}

/// That, where only Stalwart's side mends it.
pub(in crate::doctor) fn other_issuer_hostname(stated: &str, configured: &str) -> State {
    let host = host(configured);
    let text = named_otherwise(stated, configured);
    State::new("doctor-issuer-other-hostname", text).with_fix(format!(
        "Make {host} Stalwart's Default Hostname and reload its settings."
    ))
}

/// The `sign-in` check's words, here and on its card.
pub(in crate::doctor) fn page_shown(what: String) -> State {
    State::new("doctor-sign-in-page-shown", what)
}

pub(in crate::doctor) fn page_failed(what: String, fix: Option<String>) -> State {
    State::new("doctor-sign-in-page-failed", what).with_fix(fix.unwrap_or_default())
}

pub(in crate::doctor) fn page_unknown(what: String) -> State {
    State::new("doctor-sign-in-page-unknown", what)
}

#[cfg(test)]
pub(super) fn rows() -> Vec<(State, &'static str)> {
    [garrisons(), stalwarts()].concat()
}

/// Garrison's name from outside, and Stalwart's metrics there.
#[cfg(test)]
fn garrisons() -> Vec<(State, &'static str)> {
    let session = "https://admin.example.org/api/session";
    let issuer = "https://mail.example.org";
    let probe = "https://mail.example.org/metrics/prometheus";
    vec![
        (
            expired("admin.example.org", "2026-11-01"),
            "the certificate of admin.example.org expired on 2026-11-01 \
             [doctor-certificate-expired]\n      Renew it (certbot renew) and reload nginx.",
        ),
        (
            expiring("admin.example.org:8443", 5),
            "the certificate of admin.example.org:8443 expires in 5 days \
             [doctor-certificate-expiring]\n      Check that certificate renewal runs.",
        ),
        (
            trusted("admin.example.org", 61, "TLSv1_3"),
            "admin.example.org presents a trusted certificate for 61 more days (TLSv1_3) \
             [doctor-certificate-valid]",
        ),
        (
            tls_failed("[::1]:1", "connection refused"),
            "TLS to [::1]:1: connection refused [doctor-certificate-tls-failed]\n      Check \
             DNS, the certificate and the nginx server block for this name.",
        ),
        (
            answers("https://admin.example.org"),
            "Garrison answers at https://admin.example.org [doctor-interface-answers]",
        ),
        (
            unreached(session, 502, 8091),
            "https://admin.example.org/api/session answers 502: nginx does not reach Garrison's \
             web service on 127.0.0.1:8091 [doctor-interface-unreached]\n      Something listens \
             on 127.0.0.1:8091: the lines above name an include or an SELinux module for another \
             port.",
        ),
        (
            web_down(session, 502, 8091),
            "https://admin.example.org/api/session answers 502: nginx does not reach Garrison's \
             web service on 127.0.0.1:8091 [doctor-interface-web-down]\n      Nothing listens on \
             127.0.0.1:8091: `systemctl restart garrison-web.service` starts the web service on \
             web.port, and `systemctl status garrison-web.service` says why it does not run.",
        ),
        (
            other_answer(session, 404),
            "https://admin.example.org/api/session answers 404 instead of Garrison's answer to a \
             visitor [doctor-interface-other-answer]\n      The server block for this name must \
             include /etc/nginx/snippets/garrison.conf.",
        ),
        (
            unanswered(session, "connection refused"),
            "https://admin.example.org/api/session: connection refused \
             [doctor-interface-unanswered]\n      Check DNS, the certificate and the nginx \
             server block for this name.",
        ),
        (
            hsts(),
            "nginx sends Strict-Transport-Security [doctor-hsts-sent]",
        ),
        (
            no_hsts(),
            "no Strict-Transport-Security header [doctor-hsts-missing]\n      Include \
             /etc/nginx/snippets/garrison.conf in the server block; it sets the header.",
        ),
        (
            metrics_private(issuer),
            "https://mail.example.org does not serve Stalwart's metrics \
             [doctor-metrics-private]",
        ),
        (
            metrics_public(probe, 200),
            "https://mail.example.org/metrics/prometheus answers 200: Stalwart's metrics \
             exporter is public [doctor-metrics-public]\n      Add `include \
             /etc/nginx/snippets/garrison-stalwart-server*.conf;` to that server block.",
        ),
        (
            metrics_unread(probe, 500),
            "https://mail.example.org/metrics/prometheus answers 500 [doctor-metrics-unread]",
        ),
        (
            metrics_unanswered(probe, "timed out"),
            "https://mail.example.org/metrics/prometheus: timed out [doctor-metrics-unanswered]",
        ),
    ]
}

/// Stalwart's sign-in client, its issuer and its sign-in page.
#[cfg(test)]
fn stalwarts() -> Vec<(State, &'static str)> {
    let issuer = "https://mail.example.org";
    let page = "https://mail.example.org/sign-in";
    vec![
        (
            registered(),
            "Stalwart knows Garrison's sign-in client as registered [doctor-client-registered]",
        ),
        (
            client_refused(
                "https://admin.example.org/client.json",
                Some("Client metadata documents are disabled"),
            ),
            "Stalwart refuses Garrison's sign-in client https://admin.example.org/client.json: \
             Client metadata documents are disabled [doctor-client-refused]\n      Run `garrison \
             stalwart setup` again.",
        ),
        (
            client_unanswered("https://mail.example.org/api/auth/client", "timed out"),
            "https://mail.example.org/api/auth/client: timed out [doctor-client-unanswered]\n      \
             Check that the issuer is reachable from this host.",
        ),
        (
            client_limited(issuer),
            "whether Stalwart knows Garrison's sign-in client: https://mail.example.org answered \
             429 (Stalwart's rate limit); ask again in a minute [doctor-client-limited]",
        ),
        (
            client_unreached(issuer, 502),
            "https://mail.example.org answers 502 for Garrison's sign-in client: its proxy does \
             not reach Stalwart [doctor-client-unreached]\n      See that Stalwart runs and that \
             the proxy for https://mail.example.org reaches it.",
        ),
        (
            not_stalwart(issuer, 404, None),
            "https://mail.example.org answers 404 (no content type) for Garrison's sign-in \
             client, not Stalwart's JSON [doctor-client-not-stalwart]\n      The proxy for \
             https://mail.example.org must pass /api/auth/client and /api/auth to Stalwart.",
        ),
        (
            issuer_unknown(&no_issuer(
                "http://127.0.0.1:8080/.well-known/openid-configuration",
                404,
            )),
            "which issuer Stalwart names itself: \
             http://127.0.0.1:8080/.well-known/openid-configuration answered 404 without an \
             issuer this release of Garrison reads; see the supported Stalwart releases in the \
             README [doctor-issuer-unknown]",
        ),
        (
            same_issuer(issuer),
            "Stalwart names itself https://mail.example.org, as deployment.issuer does \
             [doctor-issuer-same]",
        ),
        (
            other_issuer("https://other.example.org", issuer),
            "Stalwart names itself https://other.example.org, but deployment.issuer is \
             https://mail.example.org, so every sign-in fails at Garrison's callback \
             [doctor-issuer-other]\n      Set issuer = \"https://other.example.org\" under \
             [deployment] and restart garrison-web, or make mail.example.org Stalwart's Default \
             Hostname and reload its settings.",
        ),
        (
            other_issuer_hostname("https://other.example.org/", issuer),
            "Stalwart names itself https://other.example.org/, but deployment.issuer is \
             https://mail.example.org, so every sign-in fails at Garrison's callback \
             [doctor-issuer-other-hostname]\n      Make mail.example.org Stalwart's Default \
             Hostname and reload its settings.",
        ),
        (
            page_shown(format!(
                "{page} shows Stalwart's sign-in page, which gets the 3 files it loads"
            )),
            "https://mail.example.org/sign-in shows Stalwart's sign-in page, which gets the 3 \
             files it loads [doctor-sign-in-page-shown]",
        ),
        (
            page_failed(
                format!("Stalwart's sign-in page {page} cannot load /assets/app.js"),
                Some("Whatever answers for mail.example.org must pass these paths.".into()),
            ),
            "Stalwart's sign-in page https://mail.example.org/sign-in cannot load /assets/app.js \
             [doctor-sign-in-page-failed]\n      Whatever answers for mail.example.org must pass \
             these paths.",
        ),
        (
            page_unknown(format!(
                "{page} differs from the sign-in page Stalwart serves at http://127.0.0.1:8080"
            )),
            "https://mail.example.org/sign-in differs from the sign-in page Stalwart serves at \
             http://127.0.0.1:8080 [doctor-sign-in-page-unknown]",
        ),
    ]
}
