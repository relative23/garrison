//! OAuth 2.0 Authorization Code with PKCE (S256), scope `openid` only.
//!
//! The state and the PKCE verifier of a sign-in live only in the browser's
//! `HttpOnly` login cookie. A request that is not signed in writes nothing on the
//! server, so nobody can fill a table and lock other users out of signing in.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use garrison_core::constant_time;
use garrison_stalwart::Error;
use garrison_stalwart::oidc::CodeExchange;
use garrison_stalwart::sign_in_page;
use serde_json::json;
use sha2::{Digest, Sha256};
use url::form_urlencoded;

use crate::app::{App, INTERFACE};
use crate::attempts;
use crate::error::{ApiResult, blocking};
use crate::security::{SESSION_COOKIE, STATE_COOKIE, Visitor};
use crate::store::{NewSession, random_token};

const STATE_SECONDS: u64 = 600;
const MAX_CODE: usize = 4096;

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
pub fn set_cookie(response: &mut Response, name: &str, value: &str, max_age: u64) {
    let cookie =
        format!("{name}={value}; HttpOnly; Max-Age={max_age}; Path=/; SameSite=lax; Secure");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// Browsers accept the removal of a `__Host-` cookie only with the same
/// attributes it was set with.
pub fn delete_cookie(response: &mut Response, name: &str) {
    let cookie = format!(
        "{name}=\"\"; expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; \
         SameSite=lax; Secure"
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

pub fn redirect(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

pub fn routes() -> Router<Arc<App>> {
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

async fn login(State(app): State<Arc<App>>, visitor: Visitor) -> ApiResult<Response> {
    if visitor.header("sec-fetch-site") == Some("cross-site") {
        return Ok(redirect(&format!("{INTERFACE}/?login_error=cross-site")));
    }
    let state = random_token(32)?;
    let verifier = random_token(48)?;
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
    Ok(response)
}

/// Back to the sign-in page with a reason it explains; the login cookie goes.
fn sign_in_again(reason: &str) -> Response {
    let mut response = redirect(&format!("{INTERFACE}/?login_error={reason}"));
    delete_cookie(&mut response, STATE_COOKIE);
    response
}

/// Why the token exchange failed, for the journal.
fn kind(error: &Error) -> &'static str {
    match error {
        Error::Unavailable(_) => "Stalwart unavailable",
        Error::Denied(_) | Error::InvalidToken(_) => "denied",
    }
}

async fn callback(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let failure = || sign_in_again("1");
    let state = params.get("state").map_or("", String::as_str);
    let cookie = visitor.cookie(STATE_COOKIE).to_owned();
    let Some((expected, verifier)) = cookie.split_once('.') else {
        return failure();
    };
    if state.is_empty() || !constant_time::eq(state, expected) || !is_verifier(verifier) {
        return failure();
    }
    // Only a matching state reaches Stalwart, so only it uses the budget.
    let network = attempts::network(visitor.client_ip().as_deref());
    if !app.sign_ins.allow(network, Instant::now()) {
        return sign_in_again("rate");
    }
    let verifier = verifier.to_owned();
    let outcome = blocking(move || finish(&app, &visitor, &verifier, &params)).await;
    match outcome {
        Ok(Some((identifier, lifetime))) => {
            let mut response = redirect(&format!("{INTERFACE}/"));
            set_cookie(&mut response, SESSION_COOKIE, &identifier, lifetime);
            delete_cookie(&mut response, STATE_COOKIE);
            response
        }
        Ok(None) => failure(),
        Err(error) => error.into_response(),
    }
}

/// The rest of the callback: the new session's cookie value and lifetime, or
/// `None` for a refused sign-in.
fn finish(
    app: &App,
    visitor: &Visitor,
    verifier: &str,
    params: &HashMap<String, String>,
) -> ApiResult<Option<(String, u64)>> {
    let code = params.get("code").map_or("", String::as_str);
    let issuer = params.get("iss").map(String::as_str);
    let valid = issuer == Some(app.config.deployment.issuer.as_str())
        && !code.is_empty()
        && code.chars().count() <= MAX_CODE;
    if !valid {
        return Ok(None);
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
            return Ok(None);
        }
    };
    let grant = match app.gate.grant_for(&token.access_token) {
        Ok(grant) => grant,
        Err(error) => {
            log::warn!(
                "Sign-in rejected by authorization (HTTP {})",
                error.status.as_u16()
            );
            revoke(app, &token.access_token);
            return Ok(None);
        }
    };
    let lifetime = token
        .expires_in
        .min(u64::from(app.config.web.session_minutes) * 60);
    let (identifier, _) = app.store.create(&NewSession {
        subject: &grant.subject,
        email: &grant.email,
        token: &token.access_token,
        client_ip: address.as_deref(),
        // At most the configured minutes, far inside the type.
        lifetime: i64::try_from(lifetime).unwrap_or_default(),
    })?;
    log::info!("Sign-in successful");
    Ok(Some((identifier, lifetime)))
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
    }
}
