//! OpenID Connect calls to the local Stalwart provider.
//!
//! Garrison requests only the `openid` scope. Such a token proves who the
//! user is but carries no administrative permission, so a leaked Garrison
//! token cannot change Stalwart. Identity always comes from UserInfo over
//! loopback, never from an unverified ID token.

use std::fmt;

use garrison_core::json;
use serde_json::Value;
use url::form_urlencoded;

use crate::Error;
use crate::http::Request;

const MAX_ANSWER: usize = 65536;
const MAX_EMAIL: usize = 254;

/// A stable OIDC subject: `[A-Za-z0-9_.:@-]{1,128}`.
pub fn is_subject(text: &str) -> bool {
    (1..=128).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:@-".contains(&byte))
}

/// An access token: 16 to 4096 printable ASCII characters.
pub fn is_token(text: &str) -> bool {
    (16..=4096).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_graphic())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub subject: String,
    pub email: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    pub access_token: String,
    pub expires_in: u64,
}

impl fmt::Debug for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Token")
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// The parameters of an authorization-code exchange (with PKCE).
#[derive(Debug)]
pub struct CodeExchange<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code: &'a str,
    pub verifier: &'a str,
    pub client_ip: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct Provider {
    base: String,
    /// The issuer's host (and port), sent as `Host`.
    host: String,
}

impl Provider {
    pub fn new(stalwart_url: &str, issuer: &str) -> Self {
        let host = url::Url::parse(issuer)
            .map(|url| url[url::Position::BeforeHost..url::Position::AfterPort].to_owned())
            .unwrap_or_default();
        Provider {
            base: stalwart_url.to_owned(),
            host,
        }
    }

    fn request<'a>(&'a self, request: Request<'a>, client_ip: Option<&'a str>) -> Request<'a> {
        // Stalwart derives the issuer from the forwarded public host and scheme.
        let request = request
            .header("Accept", "application/json")
            .header("Host", &self.host)
            .header("X-Forwarded-Proto", "https");
        match client_ip {
            Some(address) if !address.is_empty() => request.header("X-Forwarded-For", address),
            _ => request,
        }
    }

    pub fn exchange_code(&self, exchange: &CodeExchange<'_>) -> Result<Token, Error> {
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", exchange.code)
            .append_pair("client_id", exchange.client_id)
            .append_pair("redirect_uri", exchange.redirect_uri)
            .append_pair("code_verifier", exchange.verifier)
            .finish();
        let url = format!("{}/auth/token", self.base);
        let answer = self
            .request(Request::post(&url, form.as_bytes()), exchange.client_ip)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()?;
        if answer.status != 200 {
            return Err(Error::denied("The authorization code was not accepted"));
        }
        let unusable = || Error::denied("The provider returned an unusable token");
        let value = json::parse(&answer.body, MAX_ANSWER).map_err(|_| unusable())?;
        let token = value.get("access_token").and_then(Value::as_str);
        let kind = value.get("token_type").and_then(Value::as_str);
        let expires = value.get("expires_in").and_then(Value::as_u64);
        match (token, kind, expires) {
            (Some(token), Some(kind), Some(expires))
                if is_token(token) && kind.eq_ignore_ascii_case("bearer") && expires >= 1 =>
            {
                Ok(Token {
                    access_token: token.to_owned(),
                    expires_in: expires,
                })
            }
            _ => Err(unusable()),
        }
    }

    pub fn userinfo(&self, token: &str, client_ip: Option<&str>) -> Result<Identity, Error> {
        if !is_token(token) {
            return Err(Error::InvalidToken("Malformed access token".into()));
        }
        let url = format!("{}/auth/userinfo", self.base);
        let authorization = format!("Bearer {token}");
        let answer = self
            .request(Request::get(&url), client_ip)
            .header("Authorization", &authorization)
            .send()?;
        if answer.status != 200 {
            return Err(Error::InvalidToken(
                "The access token is no longer valid".into(),
            ));
        }
        let no_subject = || Error::denied("The provider returned no stable subject");
        let claims = json::parse(&answer.body, MAX_ANSWER).map_err(|_| no_subject())?;
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|subject| is_subject(subject))
            .ok_or_else(no_subject)?;
        let named = |key: &str| {
            claims
                .get(key)
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
        };
        let email = named("email")
            .or_else(|| named("preferred_username"))
            .unwrap_or(subject);
        Ok(Identity {
            subject: subject.to_owned(),
            email: email.chars().take(MAX_EMAIL).collect(),
        })
    }

    /// Ask the provider to revoke a token; its answer does not matter.
    pub fn revoke(&self, client_id: &str, token: &str) -> Result<(), Error> {
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .append_pair("client_id", client_id)
            .finish();
        let url = format!("{}/auth/revoke", self.base);
        self.request(Request::post(&url, form.as_bytes()), None)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .map(drop)
    }
}

#[cfg(test)]
mod tests;
