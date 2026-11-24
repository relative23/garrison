//! OAuth 2.0 Authorization Code with PKCE (S256), scope `openid` only.
//!
//! The state and the PKCE verifier of a sign-in live only in the browser's
//! `HttpOnly` login cookie, so a sign-in that is begun stores nothing on the
//! server. A callback with the state of its cookie, which anyone can make,
//! counts in the bounded budget of `attempts`, and a flood of them from more
//! networks than it counts is the security model's known limit.
//!
//! A browser comes to these routes, not the interface's requests: whatever
//! keeps a sign-in from its session sends it back to the sign-in page with a
//! reason the page explains, never an answer of the API.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use garrison_core::constant_time;
use garrison_stalwart::Error;
use garrison_stalwart::oidc::CodeExchange;
use garrison_stalwart::sign_in_page;
use serde_json::json;
use sha2::{Digest, Sha256};
use url::form_urlencoded;

use crate::app::{App, INTERFACE, Reference};
use crate::attempts::{self, Refusal};
use crate::error::{ApiError, ApiResult, Cause, blocking};
use crate::security::{SESSION_COOKIE, STATE_COOKIE, Visitor};
use crate::store::{NewSession, random_token};

const STATE_SECONDS: u64 = 600;
const MAX_CODE: usize = 4096;
/// How much of an issuer the callback names the journal repeats: anyone who
/// can start a sign-in writes it.
const MAX_SHOWN: usize = 200;

pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A verifier as `login` creates it: 43 to 128 base64url characters (RFC 7636).
fn is_verifier(text: &str) -> bool {
    (43..=128).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// A cookie of this host only (`__Host-` needs `Path=/` and no `Domain`),
/// never readable by scripts.
pub(crate) fn set_cookie(response: &mut Response, name: &str, value: &str, max_age: u64) {
    let cookie =
        format!("{name}={value}; HttpOnly; Max-Age={max_age}; Path=/; SameSite=lax; Secure");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// Browsers accept the removal of a `__Host-` cookie only with the same
/// attributes it was set with.
pub(crate) fn delete_cookie(response: &mut Response, name: &str) {
    let cookie = format!(
        "{name}=\"\"; expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; \
         SameSite=lax; Secure"
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

pub(crate) fn redirect(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

pub(crate) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/oauth-client.json", get(client_metadata))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
}

async fn client_metadata(State(app): State<Arc<App>>) -> Response {
    axum::Json(json!({
        "client_id": app.client_id(),
        "client_name": "Garrison",
        "redirect_uris": [app.redirect_uri()],
        "scope": "openid",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }))
    .into_response()
}

async fn login(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    reference: Option<Extension<Reference>>,
) -> Response {
    if visitor.header("sec-fetch-site") == Some("cross-site") {
        return redirect(&format!("{INTERFACE}/?login_error=cross-site"));
    }
    let (state, verifier) = match (random_token(32), random_token(48)) {
        (Ok(state), Ok(verifier)) => (state, verifier),
        (Err(error), _) | (_, Err(error)) => {
            return failed_here(&ApiError::from(error), reference.as_deref());
        }
    };
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &app.client_id())
        .append_pair("redirect_uri", &app.redirect_uri())
        .append_pair("response_type", "code")
        .append_pair("scope", "openid")
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge(&verifier))
        .append_pair("code_challenge_method", "S256")
        .finish();
    let mut response = redirect(&format!(
        "{}{}?{query}",
        app.config.deployment.issuer,
        sign_in_page::PATH
    ));
    // base64url has no dot, so the dot separates the two values.
    set_cookie(
        &mut response,
        STATE_COOKIE,
        &format!("{state}.{verifier}"),
        STATE_SECONDS,
    );
    response
}

/// Why a sign-in got no session, as the sign-in page explains it. Stalwart
/// that did not answer the code exchange, or turned it away for its rate
/// limit, and rights that could not be checked just then, all pass: the
/// page says so and when to try again; an exchange answered in a form this
/// release does not read refuses nobody either and is said as rights that
/// could not be checked. Anything else, a code Stalwart refused or a user
/// the policy refuses, is a failed sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    Failed,
    Unavailable,
    Limited,
    Unchecked,
}

impl Ended {
    /// The `login_error` the sign-in page reads.
    fn reason(self) -> &'static str {
        match self {
            Ended::Failed => "1",
            Ended::Unavailable => "unavailable",
            Ended::Limited => "limited",
            Ended::Unchecked => "unchecked",
        }
    }

    /// What a failed code exchange tells the person signing in.
    fn exchanging(error: &Error) -> Self {
        match error {
            Error::Unavailable(_) => Ended::Unavailable,
            Error::Limited(_) => Ended::Limited,
            Error::Unreadable(_) => Ended::Unchecked,
            Error::Denied(_) | Error::InvalidToken(_) | Error::Misconfigured(_) => Ended::Failed,
        }
    }
}

/// Back to the sign-in page with a reason it explains; the login cookie goes.
fn sign_in_again(reason: &str) -> Response {
    let mut response = redirect(&format!("{INTERFACE}/?login_error={reason}"));
    delete_cookie(&mut response, STATE_COOKIE);
    response
}

/// Back to the sign-in page after a fault of the web service's own, such as
/// a session store that takes no new row or no random numbers: the page says
/// so, with the reference under which this journal names the cause, as for
/// an internal error of the API, and the login cookie goes.
fn failed_here(error: &ApiError, reference: Option<&Reference>) -> Response {
    let mut reason = "internal".to_owned();
    if let Some(Reference(reference)) = reference {
        reason.push_str("&reference=");
        reason.push_str(reference);
    }
    let mut response = sign_in_again(&reason);
    response
        .extensions_mut()
        .insert(Cause(error.cause().to_owned()));
    response
}

/// Why the token exchange failed, for the journal.
fn kind(error: &Error) -> &'static str {
    match error {
        Error::Unavailable(_) => "Stalwart unavailable",
        Error::Limited(_) => "Stalwart's rate limit, HTTP 429",
        Error::Denied(_) | Error::InvalidToken(_) => "denied",
        Error::Unreadable(_) => "an answer this release does not read",
        Error::Misconfigured(_) => "Garrison's own setup",
    }
}

async fn callback(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    reference: Option<Extension<Reference>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let failure = || sign_in_again(Ended::Failed.reason());
    let state = params.get("state").map_or("", String::as_str);
    let cookie = visitor.cookie(STATE_COOKIE).to_owned();
    let Some((expected, verifier)) = cookie.split_once('.') else {
        return failure();
    };
    // Another sign-in's callback, as of one begun before in this browser or
    // one a page made up, leaves the login cookie to its own.
    if state.is_empty() || !constant_time::eq(state, expected) {
        return redirect(&format!(
            "{INTERFACE}/?login_error={}",
            Ended::Failed.reason()
        ));
    }
    if !is_verifier(verifier) {
        return failure();
    }
    // Only a matching state reaches Stalwart, so only it uses the budget.
    let network = attempts::network(visitor.client_ip().as_deref());
    if let Err(refusal) = app.sign_ins.allow(network, Instant::now()) {
        return sign_in_again(match refusal {
            Refusal::Network => "rate",
            Refusal::Crowded => "busy",
        });
    }
    let verifier = verifier.to_owned();
    let outcome = blocking(move || finish(&app, &visitor, &verifier, &params)).await;
    match outcome {
        Ok(Ok((identifier, lifetime))) => {
            let mut response = redirect(&format!("{INTERFACE}/"));
            set_cookie(&mut response, SESSION_COOKIE, &identifier, lifetime);
            delete_cookie(&mut response, STATE_COOKIE);
            response
        }
        Ok(Err(ended)) => sign_in_again(ended.reason()),
        Err(error) => failed_here(&error, reference.as_deref()),
    }
}

/// The rest of the callback: the new session's cookie value and lifetime, or
/// why the sign-in got none.
fn finish(
    app: &App,
    visitor: &Visitor,
    verifier: &str,
    params: &HashMap<String, String>,
) -> ApiResult<Result<(String, u64), Ended>> {
    let code = params.get("code").map_or("", String::as_str);
    let configured = app.config.deployment.issuer.as_str();
    // What kept the callback from the code exchange, for the journal, which
    // repeats the issuer it names, quoted, but never its code.
    let refused = match params.get("iss").map(String::as_str) {
        None => Some(format!(
            "it names no issuer, where deployment.issuer is {configured}"
        )),
        Some(issuer) if issuer != configured => Some(format!(
            "it names the issuer {:?}, where deployment.issuer is {configured}",
            issuer.chars().take(MAX_SHOWN).collect::<String>()
        )),
        Some(_) if code.is_empty() => Some("it carries no code".to_owned()),
        Some(_) if code.chars().count() > MAX_CODE => {
            Some(format!("its code is longer than {MAX_CODE} characters"))
        }
        Some(_) => None,
    };
    if let Some(why) = refused {
        log::warn!("Sign-in rejected at the callback ({why})");
        return Ok(Err(Ended::Failed));
    }
    let address = visitor.client_ip();
    let (client_id, redirect_uri) = (app.client_id(), app.redirect_uri());
    // Log only error classes: the callback URL contains the authorization code.
    let token = match app.identity.exchange_code(&CodeExchange {
        client_id: &client_id,
        redirect_uri: &redirect_uri,
        code,
        verifier,
        client_ip: address.as_deref(),
    }) {
        Ok(token) => token,
        Err(error) => {
            log::warn!("Sign-in rejected at token exchange ({})", kind(&error));
            return Ok(Err(Ended::exchanging(&error)));
        }
    };
    let grant = match app.gate.grant_for(&token.access_token) {
        Ok(grant) => grant,
        Err(error) => {
            log::warn!(
                "Sign-in rejected by authorization (HTTP {}: {})",
                error.status.as_u16(),
                error.cause()
            );
            revoke(app, &token.access_token);
            // 401 and 403 are what Stalwart and the policy say of this user;
            // a 5xx refuses nobody: the rights could not be checked just then.
            let ended = if error.status.is_server_error() {
                Ended::Unchecked
            } else {
                Ended::Failed
            };
            return Ok(Err(ended));
        }
    };
    let lifetime = token
        .expires_in
        .min(u64::from(app.config.web.session_minutes) * 60);
    // A browser that signs in again brings the cookie of its session so
    // far: that one ends now, with its token, instead of lasting out its
    // time under a cookie the new one replaces.
    if let Ok(Some(before)) = app.gate.session(visitor) {
        let _ = app.gate.end(&before, true);
    }
    let created = app.store.create(&NewSession {
        subject: &grant.subject,
        email: &grant.email,
        token: &token.access_token,
        client_ip: address.as_deref(),
        // At most the configured minutes, far inside the type.
        lifetime: i64::try_from(lifetime).unwrap_or_default(),
    });
    let (identifier, _) = match created {
        Ok(created) => created,
        Err(error) => {
            // No session holds this token: nothing here would ever end it.
            revoke(app, &token.access_token);
            return Err(ApiError::internal(&format!(
                "the sign-in's session could not be stored: {error}"
            )));
        }
    };
    log::info!("Sign-in successful");
    Ok(Ok((identifier, lifetime)))
}

/// Ask the provider to revoke a token; a failure is logged, not shown.
pub fn revoke(app: &App, token: &str) {
    if app.identity.revoke(&app.client_id(), token).is_err() {
        log::warn!("Token revocation could not be confirmed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifiers_are_43_to_128_base64url_characters() {
        for text in ["a".repeat(43), "A-_z09".repeat(21) + "xy", "b".repeat(128)] {
            assert!(is_verifier(&text), "{text}");
        }
        for text in [
            "a".repeat(42),
            "a".repeat(129),
            "a".repeat(42) + ".",
            "a".repeat(42) + "~",
        ] {
            assert!(!is_verifier(&text), "{text}");
        }
    }

    #[test]
    fn the_journal_tells_an_outage_from_a_refusal() {
        assert_eq!(
            kind(&Error::Unavailable("down".into())),
            "Stalwart unavailable"
        );
        assert_eq!(kind(&Error::Denied("no".into())), "denied");
        assert_eq!(kind(&Error::InvalidToken("old".into())), "denied");
        assert_eq!(
            kind(&Error::Unreadable("unusable token".into())),
            "an answer this release does not read"
        );
    }

    /// Only what passes by itself gets words of its own on the sign-in
    /// page; a refused code and Garrison's own setup are a failed sign-in,
    /// and an answer this release does not read refuses nobody.
    #[test]
    fn the_sign_in_page_hears_of_an_outage_and_of_the_rate_limit() {
        let reason = |error: Error| Ended::exchanging(&error).reason();
        assert_eq!(reason(Error::Unavailable("down".into())), "unavailable");
        assert_eq!(reason(Error::Limited("HTTP 429".into())), "limited");
        assert_eq!(reason(Error::Denied("invalid_grant".into())), "1");
        assert_eq!(reason(Error::InvalidToken("old".into())), "1");
        assert_eq!(reason(Error::Misconfigured("no key".into())), "1");
        assert_eq!(reason(Error::Unreadable("unusable".into())), "unchecked");
    }

    /// A fault of the web service's own ends on the sign-in page with the
    /// reference, which the journal's line of the cause names, and without
    /// the login cookie.
    #[test]
    fn a_fault_here_sends_the_browser_back_with_its_reference() {
        let failed = failed_here(
            &ApiError::internal(&"database or disk is full"),
            Some(&Reference("0123456789ab".into())),
        );
        assert_eq!(failed.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            failed.headers()[header::LOCATION],
            "/admin/?login_error=internal&reference=0123456789ab"
        );
        let cookie = failed.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(cookie.starts_with("__Host-garrison_login=") && cookie.contains("Max-Age=0"));
        let Some(Cause(cause)) = failed.extensions().get::<Cause>() else {
            panic!("no cause for the journal")
        };
        assert_eq!(cause, "database or disk is full");
        // Without a reference, as where no random numbers were there for one.
        let unnamed = failed_here(&ApiError::internal(&"no random numbers"), None);
        assert_eq!(
            unnamed.headers()[header::LOCATION],
            "/admin/?login_error=internal"
        );
    }

    /// Stalwart's 429 is its rate limit, which passes once Stalwart's minute
    /// is over: the journal names it, not an outage.
    #[test]
    fn the_journal_names_stalwarts_rate_limit() {
        assert_eq!(
            kind(&Error::Limited("Stalwart answered HTTP 429".into())),
            "Stalwart's rate limit, HTTP 429"
        );
    }
}
