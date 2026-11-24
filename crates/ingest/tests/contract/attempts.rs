//! What the count of failed sign-ins on Attacks & bans relies on for mail
//! programs: Stalwart refuses the sign-in after three failed ones in an IMAP
//! session with an event of its own, naming the client's address and the
//! listener, and ends the session.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use garrison_core::sqlite::reading;
use garrison_ingest::app::router;
use garrison_ingest::store::{EventStore, Limits};
use garrison_testing::lab::{Lab, random_hex};

use super::{create_webhook, one_at_a_time};

/// A certificate check that accepts the lab's self-made certificate, as the
/// collector's contract test does; the product never does this.
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

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

/// An IMAP session over TLS on the lab's port 993.
fn imap(host: &str) -> BufReader<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let server = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let connection = rustls::ClientConnection::new(Arc::new(config), server).unwrap();
    let stream = TcpStream::connect((host, 993)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut session = BufReader::new(rustls::StreamOwned::new(connection, stream));
    let mut greeting = String::new();
    session.read_line(&mut greeting).unwrap();
    assert!(greeting.starts_with("* OK"), "{greeting}");
    session
}

/// The tagged answer to one LOGIN, or what ended the session instead.
fn login(
    session: &mut BufReader<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>,
    tag: &str,
) -> String {
    let command = format!(
        "{tag} LOGIN nobody-{} wrong-{}\r\n",
        random_hex(3),
        random_hex(6)
    );
    if session.get_mut().write_all(command.as_bytes()).is_err() {
        return "(closed)".to_owned();
    }
    loop {
        let mut line = String::new();
        match session.read_line(&mut line) {
            Ok(0) | Err(_) => return "(closed)".to_owned(),
            Ok(_) if line.starts_with(&format!("{tag} ")) => return line.trim_end().to_owned(),
            Ok(_) => {}
        }
    }
}

/// The addresses and listeners of the stored events of `kind`.
fn stored(path: &Path, kind: &str) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        std::thread::sleep(Duration::from_secs(1));
        // The receiver may be writing at this moment.
        if let Ok(Some(db)) = reading(path, Duration::from_secs(2)) {
            let fields: Vec<String> = db
                .prepare("SELECT fields FROM events WHERE type=?1")
                .unwrap()
                .query_map([kind], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            if !fields.is_empty() {
                return fields;
            }
        }
        assert!(Instant::now() < deadline, "no {kind} arrived");
    }
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_mail_session_with_too_many_failed_sign_ins_is_refused_by_address() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let host = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    let key = random_hex(32);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.sqlite");
    let store = Arc::new(EventStore::open(&path, Limits::new(30, 10_000, 64 << 20)).unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind((callback.as_str(), 0)))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = router(Arc::clone(&store), key.as_bytes());
    runtime.spawn(async move { axum::serve(listener, app).await });
    create_webhook(&mut lab, &format!("http://{callback}:{port}/webhook"), &key);
    std::thread::sleep(Duration::from_secs(2));

    // Four wrong passwords, far below the hundred that ban this address.
    let mut session = imap(&host);
    let answers: Vec<String> = ["a1", "a2", "a3", "a4"]
        .iter()
        .map(|tag| login(&mut session, tag))
        .collect();
    assert!(
        answers[..3].iter().all(|answer| answer.contains("NO")),
        "{answers:?}"
    );
    assert!(
        answers[3].contains("Too many authentication attempts"),
        "{answers:?}"
    );
    assert_eq!(login(&mut session, "a5"), "(closed)");

    // The fourth is no auth.failed but an event of its own, under the
    // client's address and the listener, which the summary counts.
    let refused = stored(&path, "auth.too-many-attempts");
    let fields: serde_json::Value = serde_json::from_str(&refused[0]).unwrap();
    assert!(
        fields["remoteIp"]
            .as_str()
            .is_some_and(|address| address.parse::<std::net::IpAddr>().is_ok()),
        "{fields}"
    );
    assert_eq!(fields["listenerId"], "imaps", "{fields}");
    assert!(fields.get("causedBy").is_none(), "{fields}");
}
