//! Stalwart takes a notification that its own account submits.

use std::time::{Duration, Instant};

use garrison_core::time;
use garrison_testing::lab::{Lab, random_hex};

use super::{delivered, one_at_a_time};

/// A certificate check that accepts the lab's self-made certificate. The
/// product never does this: it checks the name against the system's
/// authorities.
#[derive(Debug)]
struct AnyCertificate(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.0.signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, certificate, signature, algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = &self.0.signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, certificate, signature, algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn stalwart_takes_a_notification_its_own_account_submits_past_the_spam_filter() {
    use garrison_collector::notify::mail::{Mail, message, submit_over};

    let _guard = one_at_a_time();
    let lab = Lab::from_environment();
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let admin = std::env::var("GARRISON_LAB_ADMIN").expect("GARRISON_LAB_ADMIN");
    let (user, password) = admin.split_once(':').expect("user:password");
    let mail = Mail {
        host: smtp.clone(),
        port: 465,
        user: user.to_owned(),
        password: password.to_owned(),
        from: user.to_owned(),
        to: user.to_owned(),
    };
    // A name of this run's own, to find the message by.
    let name = format!("garrison-{}.example.org", random_hex(4));
    let text = message(
        &mail,
        &name,
        &format!("Garrison on {name}: 1 failed"),
        "Failed: Local full backup: The last run failed.\n",
        time::now(),
    );
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let server = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let connection = rustls::ClientConnection::new(std::sync::Arc::new(config), server).unwrap();
    let stream = std::net::TcpStream::connect((smtp.as_str(), 465)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    submit_over(
        rustls::StreamOwned::new(connection, stream),
        &mail,
        &name,
        &text,
    )
    .unwrap();

    // A wrong password is refused, and the refusal does not repeat it.
    let wrong = Mail {
        password: format!("wrong-{}", random_hex(8)),
        ..mail.clone()
    };
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let server = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let connection = rustls::ClientConnection::new(std::sync::Arc::new(config), server).unwrap();
    let stream = std::net::TcpStream::connect((smtp.as_str(), 465)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let refused = submit_over(
        rustls::StreamOwned::new(connection, stream),
        &wrong,
        &name,
        &text,
    );
    assert_eq!(
        refused,
        Err("the mail server did not sign in (535)".to_owned())
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let verdict = loop {
        let found = delivered(&lab)
            .into_iter()
            .find(|(id, _)| id.ends_with(&name));
        if let Some((_, verdict)) = found {
            break verdict;
        }
        assert!(
            Instant::now() < deadline,
            "the notification was not delivered"
        );
        std::thread::sleep(Duration::from_secs(1));
    };
    // A stranger's mail gets a verdict of the spam filter; the account's own does not.
    assert_eq!(verdict, "", "the spam filter judged the notification");
}
