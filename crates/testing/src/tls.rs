//! Test certificates for TLS servers in the tests: a CA and a server
//! certificate it issued, made at run time, so no key material is stored;
//! and a TLS server with such a certificate. Here and not with the checks'
//! helpers, so that the certificate library stays out of every crate that
//! ships.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

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

/// How long the server waits for a connection, and for its request.
const PATIENCE: Duration = Duration::from_secs(10);

/// A TLS server on 127.0.0.1 under the name `localhost`, with a certificate
/// [`certificates_until`] makes: each connection gets the next of its
/// answers, as [`crate::http::serve`] gives them without TLS.
#[derive(Debug)]
pub struct Server {
    /// `https://localhost:` and the port.
    pub url: String,
    /// The authority its certificate comes from.
    pub roots: RootCertStore,
    done: Arc<AtomicBool>,
    handle: JoinHandle<usize>,
}

impl Server {
    /// Ends the server and says how many connections it took, those whose
    /// handshake a client refused among them.
    pub fn finish(self) -> usize {
        self.done.store(true, Ordering::SeqCst);
        self.handle.join().unwrap()
    }
}

/// A server whose certificate is valid until 00:00 UTC of the given day,
/// with `responses` for the connections in turn.
#[must_use]
pub fn serve_until(responses: Vec<String>, year: i32, month: u8, day: u8) -> Server {
    let certificates = certificates_until(year, month, day);
    let mut roots = RootCertStore::empty();
    roots.add(certificates.ca.clone()).unwrap();
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificates.server], certificates.key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    // Polled, so that waiting for a connection can end.
    listener.set_nonblocking(true).unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let done = Arc::new(AtomicBool::new(false));
    let handle = thread::spawn({
        let done = Arc::clone(&done);
        move || {
            let mut taken = 0;
            for response in responses {
                let Some(stream) = accepted(&listener, &done) else {
                    break;
                };
                taken += 1;
                let connection = ServerConnection::new(Arc::clone(&config)).unwrap();
                let mut tls = StreamOwned::new(connection, stream);
                // A client that refuses the certificate ends the handshake,
                // and so this read, with an error.
                if head(&mut tls).is_ok() {
                    let _ = tls.write_all(response.as_bytes());
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
            }
            taken
        }
    });
    Server {
        url,
        roots,
        done,
        handle,
    }
}

/// The next connection, or `None` once the server is to end or none came
/// within [`PATIENCE`].
fn accepted(listener: &TcpListener, done: &AtomicBool) -> Option<TcpStream> {
    let deadline = Instant::now() + PATIENCE;
    while !done.load(Ordering::SeqCst) && Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(PATIENCE)).unwrap();
                return Some(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("{error}"),
        }
    }
    None
}

/// Reads a request's head, up to its empty line.
fn head(tls: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if tls.read(&mut byte)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        head.push(byte[0]);
    }
    Ok(head)
}
