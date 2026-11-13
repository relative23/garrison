//! Test certificates for TLS servers in the tests: a CA and a server
//! certificate it issued, made at run time, so no key material is stored.
//! Here and not with the checks' helpers, so that the certificate library
//! stays out of every crate that ships.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// A test CA and a server certificate for `localhost` and 127.0.0.1 that it
/// issued.
#[derive(Debug)]
pub struct Certificates {
    pub ca: CertificateDer<'static>,
    pub server: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

/// Certificates with a server certificate valid until 2036-10-26 00:00 UTC.
#[must_use]
pub fn certificates() -> Certificates {
    certificates_until(2036, 10, 26)
}

/// Like [`certificates`], with the server certificate valid until 00:00 UTC of
/// the given day.
#[must_use]
pub fn certificates_until(year: i32, month: u8, day: u8) -> Certificates {
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
        key: PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
    }
}
