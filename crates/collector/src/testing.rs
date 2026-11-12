//! Helpers for the providers' tests: a fixed clock and canned command output.

use std::io;
use std::path::Path;

use garrison_core::config::{Config, Database};
use garrison_core::time::{self, Timestamp};

use crate::command::{Output, Runner};
use crate::context::{Context, Forgetful};

/// 2026-10-29T12:00:00Z, the collection time of the tests.
pub(crate) fn now() -> Timestamp {
    time::parse("2026-10-29T12:00:00Z").unwrap()
}

/// Answers every command with the same output and exit code 0.
pub(crate) struct Canned(pub(crate) String);

impl Runner for Canned {
    fn run(&self, _: &[&str]) -> io::Result<Output> {
        Ok(Output {
            code: Some(0),
            stdout: self.0.clone(),
        })
    }
}

pub(crate) fn config(directory: &Path) -> Config {
    garrison_testing::config(directory, "http://127.0.0.1:9")
}

pub(crate) fn context<'a>(config: &'a Config, runner: &'a dyn Runner) -> Context<'a> {
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
pub(crate) struct Remembered(
    pub(crate) std::cell::RefCell<std::collections::BTreeMap<String, String>>,
);

impl crate::context::Memory for Remembered {
    fn recall(&self, key: &str) -> Option<String> {
        self.0.borrow().get(key).cloned()
    }

    fn keep(&self, key: &str, value: &str) {
        self.0.borrow_mut().insert(key.to_owned(), value.to_owned());
    }
}

pub(crate) fn table(text: &str) -> toml::Table {
    text.parse().unwrap()
}

/// A test CA and a server certificate for `localhost` and 127.0.0.1 that it
/// issued, valid until 2036-10-26 00:00 UTC; made at run time, so no key
/// material is stored.
pub(crate) struct Certificates {
    pub(crate) ca: rustls::pki_types::CertificateDer<'static>,
    pub(crate) server: rustls::pki_types::CertificateDer<'static>,
    pub(crate) key: rustls::pki_types::PrivateKeyDer<'static>,
}

pub(crate) fn certificates() -> Certificates {
    certificates_until(2036, 10, 26)
}

/// Like [`certificates`], with the server certificate valid until 00:00 UTC of
/// the given day.
pub(crate) fn certificates_until(year: i32, month: u8, day: u8) -> Certificates {
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
