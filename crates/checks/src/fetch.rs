//! One HTTP request, as a visitor would make it: name lookup through the
//! system, TLS validated against the system's trust store with the host name
//! as SNI. Only what the caller reads comes back: status, headers and a
//! bounded body, unpacked if the server sent it compressed. `garrison doctor`
//! asks the installation's public names with it, the collector the release
//! list, the notification channel and Stalwart's sign-in page. No redirect is
//! followed.
//!
//! A request has a time by which it must be done, all of it: the name
//! lookup, the connection, TLS and the answer. A limit for each step alone
//! would let a server that sends a byte now and then, or a resolver that
//! does not answer, hold the caller for as long as it likes.
//!
//! Requests to Stalwart's own listener on this host do not come through
//! here: `garrison_stalwart::http` speaks plain HTTP to a loopback address,
//! without TLS and without a name to look up, and bounds a request in the
//! same way.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use garrison_core::time::{self, Timestamp};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::time_provider::{DefaultTimeProvider, TimeProvider};
use rustls::{CertificateError, ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::timed::Timed;

mod answer;

pub use answer::Answer;
use answer::{enough, parse};

/// One step waits this long at most: the lookup, the connection, one read
/// or write.
const TIMEOUT: Duration = Duration::from_secs(8);
/// A request without a time of its caller's has this long in all.
pub const WITHIN: Duration = Duration::from_secs(20);
const LIMIT: u64 = 256 * 1024;

/// The authorities a server's certificate is checked against.
pub type Roots = Arc<RootCertStore>;

/// The system's trust store, as `curl` on this host would use it.
#[must_use]
pub fn roots() -> Roots {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    Arc::new(roots)
}

/// The time a check judges a server's certificate at: its run's, so that
/// one run judges every certificate at one time, and a test can set it.
#[derive(Debug)]
struct At(UnixTime);

impl TimeProvider for At {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.0)
    }
}

/// A TLS client that trusts `roots` and judges a server's certificate at
/// `at`, a check's run time, or by the clock where it has none.
pub fn client_config(roots: &Roots, at: Option<Timestamp>) -> Result<ClientConfig, String> {
    let time: Arc<dyn TimeProvider> = match at {
        Some(at) => Arc::new(At(UnixTime::since_unix_epoch(Duration::from_secs(
            u64::try_from(at.as_second()).unwrap_or(0),
        )))),
        None => Arc::new(DefaultTimeProvider),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(ClientConfig::builder_with_details(provider, time)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots.clone())
        .with_no_client_auth())
}

/// `scheme://host[:port]` of a URL.
pub fn origin(url: &str) -> &str {
    let start = url.find("://").map_or(0, |index| index + 3);
    url[start..]
        .find('/')
        .map_or(url, |index| &url[..start + index])
}

/// `http://` or `https://`, a host, an optional port and a path.
fn split(url: &str) -> Result<(bool, String, u16, String), String> {
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(format!("{url} is not an http or https URL"));
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let default = if secure { 443 } else { 80 };
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        // An IPv6 address: `[::1]` or `[::1]:8080`.
        let (host, after) = bracketed
            .split_once(']')
            .ok_or_else(|| format!("{url} has an unclosed IPv6 address"))?;
        match after.strip_prefix(':') {
            Some(port) => (
                host,
                port.parse()
                    .map_err(|_| format!("{url} has no valid port"))?,
            ),
            None => (host, default),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse()
                    .map_err(|_| format!("{url} has no valid port"))?,
            ),
            None => (authority, default),
        }
    };
    if host.is_empty() {
        return Err(format!("{url} names no host"));
    }
    let path = if path.is_empty() { "/" } else { path };
    Ok((secure, host.to_owned(), port, path.to_owned()))
}

/// The addresses of `host`, asked of the system on a thread of its own: the
/// system's lookup has no time limit, and a resolver that does not answer
/// would hold the caller for as long as its own configuration says.
fn resolve(host: &str, port: u16, until: Instant) -> Result<Vec<SocketAddr>, String> {
    let (answer, asked) = mpsc::channel();
    let name = host.to_owned();
    std::thread::spawn(move || {
        let found = (name.as_str(), port)
            .to_socket_addrs()
            .map(Iterator::collect::<Vec<_>>);
        // Nobody waits any more once the time is up.
        let _ = answer.send(found);
    });
    let patience = until.saturating_duration_since(Instant::now()).min(TIMEOUT);
    match asked.recv_timeout(patience) {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(_)) => Err(format!("{host} does not resolve")),
        Err(_) => Err(format!(
            "{host}: the name lookup gave no answer within {} s",
            patience.as_secs()
        )),
    }
}

fn connect(host: &str, port: u16, until: Instant) -> Result<Timed, String> {
    let mut last = format!("{host} does not resolve");
    for target in resolve(host, port, until)? {
        let patience = until.saturating_duration_since(Instant::now()).min(TIMEOUT);
        if patience.is_zero() {
            return Err(format!("{host}:{port}: not reached in the request's time"));
        }
        match TcpStream::connect_timeout(&target, patience) {
            Ok(stream) => return Ok(Timed::new(stream, until, TIMEOUT)),
            Err(error) => last = format!("{host}:{port}: {error}"),
        }
    }
    Err(last)
}

/// A TLS session with `host`, its certificate checked against `roots` for
/// that name. The handshake happens with the first read or write.
pub fn secure_stream(
    host: &str,
    port: u16,
    roots: &Arc<RootCertStore>,
) -> Result<StreamOwned<ClientConnection, Timed>, String> {
    secure_stream_until(host, port, roots, Instant::now() + WITHIN)
}

/// The same, with everything said over it done by `until`.
pub fn secure_stream_until(
    host: &str,
    port: u16,
    roots: &Arc<RootCertStore>,
    until: Instant,
) -> Result<StreamOwned<ClientConnection, Timed>, String> {
    secure_stream_at(host, port, roots, until, None)
}

/// The same, with the certificate judged at `at` where it is given.
fn secure_stream_at(
    host: &str,
    port: u16,
    roots: &Arc<RootCertStore>,
    until: Instant,
    at: Option<Timestamp>,
) -> Result<StreamOwned<ClientConnection, Timed>, String> {
    let stream = connect(host, port, until)?;
    let name =
        ServerName::try_from(host.to_owned()).map_err(|_| format!("{host} is no host name"))?;
    let config = client_config(roots, at)?;
    let connection =
        ClientConnection::new(Arc::new(config), name).map_err(|error| error.to_string())?;
    Ok(StreamOwned::new(connection, stream))
}

/// Why TLS failed, in words an operator can act on.
pub fn tls_error(error: &std::io::Error) -> String {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(reason)) => certificate_fault(reason),
        Some(other) => format!("TLS failed: {other}"),
        None => error.to_string(),
    }
}

/// What is wrong with a server's certificate, in the words of a finding:
/// the common faults as what they are, with the time where the certificate
/// gives one, and any other in the TLS library's words.
#[must_use]
pub fn certificate_fault(reason: &CertificateError) -> String {
    let at = |at: &UnixTime| {
        i64::try_from(at.as_secs())
            .ok()
            .and_then(|second| Timestamp::from_second(second).ok())
            .map_or_else(|| format!("{} (UNIX)", at.as_secs()), time::isoformat)
    };
    match reason {
        CertificateError::Expired => "the certificate has expired".to_owned(),
        CertificateError::ExpiredContext { not_after, .. } => {
            format!("the certificate expired at {}", at(not_after))
        }
        CertificateError::NotValidYet => "the certificate is not valid yet".to_owned(),
        CertificateError::NotValidYetContext { not_before, .. } => {
            format!("the certificate is valid only from {}", at(not_before))
        }
        CertificateError::UnknownIssuer => {
            "the certificate is not from an authority this host trusts".to_owned()
        }
        CertificateError::NotValidForName => {
            "the certificate is not valid for this name".to_owned()
        }
        CertificateError::NotValidForNameContext { presented, .. } if !presented.is_empty() => {
            format!(
                "the certificate is not valid for this name; it is for {}",
                presented.join(", ")
            )
        }
        CertificateError::NotValidForNameContext { .. } => {
            "the certificate is not valid for this name; it names none".to_owned()
        }
        CertificateError::Revoked => "the certificate is revoked".to_owned(),
        other => format!("the certificate is not valid: {other}"),
    }
}

/// The `Host` header of a request to `host` on `port`: with the port where
/// it is not the scheme's own (RFC 9110, 7.2), since a server that tells
/// its names apart by host and port, as Garrison's web service does for
/// `public_origin`, takes the name alone for another one; an IPv6 address
/// in brackets.
fn host_header(host: &str, port: u16, secure: bool) -> String {
    let name = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if port == if secure { 443 } else { 80 } {
        name
    } else {
        format!("{name}:{port}")
    }
}

fn exchange(
    stream: &mut impl ReadWrite,
    authority: &str,
    path: &str,
    request: &Request<'_>,
) -> std::io::Result<Vec<u8>> {
    write!(
        stream,
        "{} {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: garrison\r\nAccept: */*\r\n\
         Connection: close\r\n",
        request.method
    )?;
    for (name, value) in request.headers {
        // A header is one line: nothing that ends it is sent on.
        if !name.contains(['\r', '\n', ':']) && !value.contains(['\r', '\n']) {
            write!(stream, "{name}: {value}\r\n")?;
        }
    }
    if request.method != "GET" {
        write!(stream, "Content-Length: {}\r\n", request.body.len())?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(request.body)?;
    stream.flush()?;
    let mut data = Vec::new();
    match stream.take(LIMIT).read_to_end(&mut data) {
        Ok(_) => Ok(data),
        // Many servers close the socket without the notice TLS ends with.
        // What arrived before counts where it holds what the request needs:
        // whoever can end the connection could cut the answer anywhere, so
        // a body counts only where its own length says that it is all of
        // it, and a head only where it ended before the cut.
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            if enough(&data, request.needs) {
                Ok(data)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the connection ended before its answer was whole",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// What of an answer a request needs, where the server ends TLS without
/// its closing notice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Needs {
    /// All of it, as its own length says: what reads the body.
    Whole,
    /// The status line and the headers: a notification needs only the
    /// status, which a cut after the head cannot change.
    Head,
}

/// A request to send: `GET` without a body, or `POST` with one.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
    pub needs: Needs,
}

/// `GET url` with no headers of its own.
pub fn get(url: &str, roots: &Arc<RootCertStore>) -> Result<Answer, String> {
    send(
        &Request {
            method: "GET",
            url,
            headers: &[],
            body: &[],
            needs: Needs::Whole,
        },
        roots,
    )
}

/// `GET url`, with the server's certificate judged at `at`, the time of a
/// check's run.
pub fn get_at(url: &str, roots: &Arc<RootCertStore>, at: Timestamp) -> Result<Answer, String> {
    let request = Request {
        method: "GET",
        url,
        headers: &[],
        body: &[],
        needs: Needs::Whole,
    };
    send_at(&request, roots, Instant::now() + WITHIN, Some(at))
}

pub fn send(request: &Request<'_>, roots: &Arc<RootCertStore>) -> Result<Answer, String> {
    send_until(request, roots, Instant::now() + WITHIN)
}

/// The same, with the whole request done by `until`.
pub fn send_until(
    request: &Request<'_>,
    roots: &Arc<RootCertStore>,
    until: Instant,
) -> Result<Answer, String> {
    send_at(request, roots, until, None)
}

/// The request done by `until`, with a server's certificate judged at `at`
/// where it is given, else by the clock.
fn send_at(
    request: &Request<'_>,
    roots: &Arc<RootCertStore>,
    until: Instant,
    at: Option<Timestamp>,
) -> Result<Answer, String> {
    let url = request.url;
    let (secure, host, port, path) = split(url)?;
    let authority = host_header(&host, port, secure);
    let data = if secure {
        let mut tls = secure_stream_at(&host, port, roots, until, at)?;
        exchange(&mut tls, &authority, &path, request).map_err(|error| tls_error(&error))?
    } else {
        let mut stream = connect(&host, port, until)?;
        exchange(&mut stream, &authority, &path, request).map_err(|error| error.to_string())?
    };
    parse(&data).ok_or_else(|| format!("{url} gave no HTTP answer"))
}

#[cfg(test)]
mod tests;
