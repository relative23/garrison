//! Helpers for the checks' tests, in this crate and, with the feature
//! `testing`, in the crates of the checks: a fixed clock, canned command
//! output and a memory that keeps what it is given.

// Helpers fail the test by panicking, like the test itself.
#![allow(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use std::io;

use garrison_core::config::{Config, Database};
use garrison_core::time::{self, Timestamp};

use crate::command::{Output, Runner};
use crate::context::{Context, Forgetful};

/// 2026-10-29T12:00:00Z, the collection time of the tests.
pub fn now() -> Timestamp {
    time::parse("2026-10-29T12:00:00Z").unwrap()
}

/// Answers every command with the same output and exit code 0.
#[derive(Debug)]
pub struct Canned(pub String);

impl Runner for Canned {
    fn run(&self, _: &[&str]) -> io::Result<Output> {
        Ok(Output {
            code: Some(0),
            stdout: self.0.clone(),
        })
    }
}

/// The workspace's test configuration, from garrison-testing, which is no
/// normal dependency: other crates' tests add it in their own `testing`.
#[cfg(test)]
pub fn config(directory: &std::path::Path) -> Config {
    garrison_testing::config(directory, "http://127.0.0.1:9")
}

pub fn context<'a>(config: &'a Config, runner: &'a dyn Runner) -> Context<'a> {
    Context {
        deployment: &config.deployment,
        now: now(),
        native_key: None,
        metrics_credential: None,
        events_database: config.database(Database::Events),
        runner,
        memory: &Forgetful,
    }
}

/// A memory that keeps what it is given for as long as the test runs.
#[derive(Debug, Default)]
pub struct Remembered(pub std::cell::RefCell<std::collections::BTreeMap<String, String>>);

impl crate::context::Memory for Remembered {
    fn recall(&self, key: &str) -> Option<String> {
        self.0.borrow().get(key).cloned()
    }

    fn keep(&self, key: &str, value: &str) {
        self.0.borrow_mut().insert(key.to_owned(), value.to_owned());
    }
}

pub fn table(text: &str) -> toml::Table {
    text.parse().unwrap()
}

/// A test CA and a server certificate for `localhost` and 127.0.0.1 that it
/// issued, valid until 2036-10-26 00:00 UTC; made at run time, so no key
/// material is stored.
#[derive(Debug)]
pub struct Certificates {
    pub ca: rustls::pki_types::CertificateDer<'static>,
    pub server: rustls::pki_types::CertificateDer<'static>,
    pub key: rustls::pki_types::PrivateKeyDer<'static>,
}

pub fn certificates() -> Certificates {
    certificates_until(2036, 10, 26)
}

/// Like [`certificates`], with the server certificate valid until 00:00 UTC of
/// the given day.
pub fn certificates_until(year: i32, month: u8, day: u8) -> Certificates {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, date_time_ymd,
    };
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "Garrison test CA");
    let ca_certificate = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca, ca_key);
    let server_key = KeyPair::generate().unwrap();
    let mut server =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
    server.not_after = date_time_ymd(year, month, day);
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_certificate = server.signed_by(&server_key, &issuer).unwrap();
    Certificates {
        ca: ca_certificate.der().clone(),
        server: server_certificate.der().clone(),
        key: rustls::pki_types::PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
    }
}
