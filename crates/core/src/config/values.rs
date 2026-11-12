//! Validation of single configuration values. Each function names the setting
//! in its error, so an operator sees which line to fix.

use std::net::IpAddr;
use std::path::PathBuf;

use toml::{Table, Value};
use url::{Host, Url};

use super::ConfigError;
use crate::credentials::{SecretSource, is_credential_name};

fn fail<T>(message: String) -> Result<T, ConfigError> {
    Err(ConfigError(message))
}

/// One `[section]` of the file; a missing section reads as empty.
#[derive(Debug, Clone, Copy)]
pub(super) struct Section<'a> {
    pub(super) table: Option<&'a Table>,
}

impl<'a> Section<'a> {
    /// Accept a table that holds only the allowed settings, so a typo cannot
    /// silently fall back to a default.
    pub(super) fn take(
        value: Option<&'a Value>,
        name: &str,
        allowed: &[&str],
    ) -> Result<Self, ConfigError> {
        match value {
            None => Ok(Section { table: None }),
            Some(Value::Table(table)) => Section::of(table, name, allowed),
            Some(_) => fail(format!("[{name}] must be a table")),
        }
    }

    pub(super) fn of(table: &'a Table, name: &str, allowed: &[&str]) -> Result<Self, ConfigError> {
        let mut unknown: Vec<&str> = table
            .keys()
            .map(String::as_str)
            .filter(|key| !allowed.contains(key))
            .collect();
        if !unknown.is_empty() {
            unknown.sort_unstable();
            return fail(format!(
                "[{name}] has unknown settings: {}",
                unknown.join(", ")
            ));
        }
        Ok(Section { table: Some(table) })
    }

    pub(super) fn get(self, key: &str) -> Option<&'a Value> {
        self.table.and_then(|table| table.get(key))
    }
}

fn parse_url(value: Option<&Value>) -> Option<Url> {
    value
        .and_then(Value::as_str)
        .and_then(|text| Url::parse(text).ok())
}

fn has_credentials(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

/// An `https://` origin, returned in the form a browser sends in `Origin`.
pub(super) fn https_origin(value: Option<&Value>, name: &str) -> Result<String, ConfigError> {
    match parse_url(value) {
        Some(url)
            if url.scheme() == "https"
                && url.host().is_some()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                && !has_credentials(&url) =>
        {
            Ok(url.origin().ascii_serialization())
        }
        _ => fail(format!("{name} must be an https:// origin without a path")),
    }
}

/// `scheme://host[:port]` of a URL as browsers serialize origins; empty if it
/// is not a URL.
pub(super) fn origin_of(url: &str) -> String {
    Url::parse(url)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_default()
}

/// An `https://` URL without credentials, kept as written.
pub(super) fn https_url(value: Option<&Value>, name: &str) -> Result<String, ConfigError> {
    match parse_url(value) {
        Some(url) if url.scheme() == "https" && url.host().is_some() && !has_credentials(&url) => {
            Ok(value.and_then(Value::as_str).unwrap_or_default().to_owned())
        }
        _ => fail(format!("{name} must be an https:// URL")),
    }
}

/// A plain `http://` origin on a loopback IP address: Stalwart's own listener.
pub(super) fn loopback_url(value: Option<&Value>, name: &str) -> Result<String, ConfigError> {
    let loopback = |url: &Url| match url.host() {
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        _ => false,
    };
    match parse_url(value) {
        Some(url)
            if url.scheme() == "http"
                && loopback(&url)
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                && !has_credentials(&url) =>
        {
            Ok(url.origin().ascii_serialization())
        }
        _ => fail(format!("{name} must be a plain http:// loopback IP origin")),
    }
}

/// An integer in a range; `default` applies when the setting is absent.
pub(super) fn integer<T: TryFrom<i64>>(
    value: Option<&Value>,
    default: Option<i64>,
    name: &str,
    low: i64,
    high: i64,
) -> Result<T, ConfigError> {
    match value.map_or(default, Value::as_integer) {
        Some(number) if (low..=high).contains(&number) => {
            T::try_from(number).or_else(|_| fail(format!("{name} is out of range")))
        }
        _ => fail(format!(
            "{name} must be an integer between {low} and {high}"
        )),
    }
}

pub(super) fn boolean(
    value: Option<&Value>,
    default: bool,
    name: &str,
) -> Result<bool, ConfigError> {
    match value {
        None => Ok(default),
        Some(Value::Boolean(flag)) => Ok(*flag),
        Some(_) => fail(format!("{name} must be true or false")),
    }
}

pub(super) fn text<'a>(value: Option<&'a Value>, default: &'a str) -> Option<&'a str> {
    match value {
        None => Some(default),
        Some(value) => value.as_str(),
    }
}

pub(super) fn absolute_path(
    value: Option<&Value>,
    default: &str,
    name: &str,
) -> Result<PathBuf, ConfigError> {
    match text(value, default) {
        Some(path) if path.starts_with('/') => Ok(PathBuf::from(path)),
        _ => fail(format!("{name} must be an absolute path")),
    }
}

pub(super) fn secret_source(
    value: Option<&Value>,
    default: &str,
    name: &str,
) -> Result<SecretSource, ConfigError> {
    match text(value, default) {
        Some(path) if path.starts_with('/') => Ok(SecretSource::File(PathBuf::from(path))),
        Some(text) => match text.strip_prefix("credential:") {
            Some(credential) if is_credential_name(credential) => {
                Ok(SecretSource::Credential(credential.to_owned()))
            }
            _ => fail(format!(
                "{name} must be an absolute path or credential:NAME"
            )),
        },
        None => fail(format!(
            "{name} must be an absolute path or credential:NAME"
        )),
    }
}

/// A text of 1 to 400 characters, such as an action title.
pub(super) fn short_text(value: Option<&Value>, name: &str) -> Result<String, ConfigError> {
    match value.and_then(Value::as_str) {
        Some(text) if (1..=400).contains(&text.chars().count()) => Ok(text.to_owned()),
        _ => fail(format!("{name} must be a short text")),
    }
}

fn matches(
    text: &str,
    length: std::ops::RangeInclusive<usize>,
    first: fn(u8) -> bool,
    rest: fn(u8) -> bool,
) -> bool {
    let bytes = text.as_bytes();
    length.contains(&bytes.len())
        && bytes.first().is_some_and(|byte| first(*byte))
        && bytes[1..].iter().all(|byte| rest(*byte))
}

/// A systemd unit name such as `stalwart.service`. It starts with a letter or
/// digit, so no command line can read it as an option.
pub fn is_unit_name(name: &str) -> bool {
    ["service", "timer", "socket", "path"].iter().any(|kind| {
        name.strip_suffix(kind)
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(|stem| {
                matches(
                    stem,
                    1..=200,
                    |byte| byte.is_ascii_alphanumeric(),
                    |byte| byte.is_ascii_alphanumeric() || b"@_.:-".contains(&byte),
                )
            })
    })
}

/// A maintenance action ID such as `run_backup`.
pub fn is_action_id(id: &str) -> bool {
    matches(
        id,
        1..=64,
        |byte| byte.is_ascii_lowercase(),
        |byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_',
    )
}

/// The phrase an operator types to confirm an action, such as `RUN BACKUP`.
pub fn is_confirmation(phrase: &str) -> bool {
    matches(
        phrase,
        3..=64,
        |byte| byte.is_ascii_uppercase(),
        |byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b' ',
    )
}

/// A system user name as accepted by `useradd` in its default configuration.
pub fn is_user_name(name: &str) -> bool {
    matches(
        name,
        1..=32,
        |byte| byte.is_ascii_lowercase() || byte == b'_',
        |byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-',
    )
}
