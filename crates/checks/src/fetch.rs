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

use flate2::read::GzDecoder;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// One step waits this long at most: the lookup, the connection, one read
/// or write.
const TIMEOUT: Duration = Duration::from_secs(8);
/// A request without a time of its caller's has this long in all.
pub const WITHIN: Duration = Duration::from_secs(20);
const LIMIT: u64 = 256 * 1024;
/// The most a compressed body may unpack to.
const UNPACKED: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    headers: Vec<(String, String)>,
    pub body: String,
}

impl Answer {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The authorities a server's certificate is checked against.
pub type Roots = Arc<RootCertStore>;

/// The system's trust store, as `curl` on this host would use it.
#[must_use]
pub fn roots() -> Roots {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    Arc::new(roots)
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

/// A connection whose every read and write must be done by `until`.
#[derive(Debug)]
pub struct Timed {
    stream: TcpStream,
    until: Instant,
}

impl Timed {
    /// How long the next step may wait; an error once the time is up.
    fn patience(&self) -> std::io::Result<Duration> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the request was not done in its time",
            ));
        }
        Ok(left.min(TIMEOUT))
    }

    /// A step that waited out its time says so in words: the system's own
    /// error for it reads "Resource temporarily unavailable".
    fn waited<T>(&self, step: std::io::Result<T>) -> std::io::Result<T> {
        use std::io::ErrorKind::{TimedOut, WouldBlock};
        step.map_err(|error| match error.kind() {
            WouldBlock | TimedOut => match self.patience() {
                Ok(_) => std::io::Error::new(
                    TimedOut,
                    format!("the server was silent for {} s", TIMEOUT.as_secs()),
                ),
                Err(over) => over,
            },
            _ => error,
        })
    }
}

impl Read for Timed {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.patience()?))?;
        let read = self.stream.read(buffer);
        self.waited(read)
    }
}

impl Write for Timed {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.patience()?))?;
        let written = self.stream.write(data);
        self.waited(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
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
            Ok(stream) => return Ok(Timed { stream, until }),
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
    let stream = connect(host, port, until)?;
    let name =
        ServerName::try_from(host.to_owned()).map_err(|_| format!("{host} is no host name"))?;
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| error.to_string())?
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
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
        Some(rustls::Error::InvalidCertificate(reason)) => {
            format!("the certificate is not valid for this name: {reason:?}")
        }
        Some(other) => format!("TLS failed: {other}"),
        None => error.to_string(),
    }
}

fn exchange(
    stream: &mut impl ReadWrite,
    host: &str,
    path: &str,
    request: &Request<'_>,
) -> std::io::Result<Vec<u8>> {
    write!(
        stream,
        "{} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: garrison\r\nAccept: */*\r\n\
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
        // What arrived before counts where its own length says that it is
        // all of it: otherwise whoever can end the connection could cut the
        // answer anywhere, and a message that did arrive would count as lost
        // and be sent again.
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            if whole(&data) {
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

/// Whether `data` is an answer that its own length calls whole: the head,
/// and a body as long as `Content-Length` says or with the last chunk of a
/// chunked one. An answer that gives no length ends with its connection,
/// and so is never known to be whole.
fn whole(data: &[u8]) -> bool {
    let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&data[..end]);
    let body = &data[end + 4..];
    let header = |name: &str| {
        head.split("\r\n")
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim().to_owned())
    };
    if header("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
        return dechunk(body).1;
    }
    header("content-length")
        .and_then(|length| length.parse::<usize>().ok())
        .is_some_and(|length| body.len() >= length)
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// A request to send: `GET` without a body, or `POST` with one.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

/// `GET url` with no headers of its own.
pub fn get(url: &str, roots: &Arc<RootCertStore>) -> Result<Answer, String> {
    send(
        &Request {
            method: "GET",
            url,
            headers: &[],
            body: &[],
        },
        roots,
    )
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
    let url = request.url;
    let (secure, host, port, path) = split(url)?;
    let data = if secure {
        let mut tls = secure_stream_until(&host, port, roots, until)?;
        exchange(&mut tls, &host, &path, request).map_err(|error| tls_error(&error))?
    } else {
        let mut stream = connect(&host, port, until)?;
        exchange(&mut stream, &host, &path, request).map_err(|error| error.to_string())?
    };
    parse(&data).ok_or_else(|| format!("{url} gave no HTTP answer"))
}

/// Status line, headers and body; a chunked body is joined.
fn parse(data: &[u8]) -> Option<Answer> {
    let end = data.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&data[..end]);
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect();
    let mut body = data[end + 4..].to_vec();
    let chunked = headers.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked")
    });
    if chunked {
        body = dechunk(&body).0;
    }
    // Stalwart sends its pages compressed whatever the request accepts.
    let packed = headers.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("content-encoding") && value.eq_ignore_ascii_case("gzip")
    });
    if packed {
        body = unpack(&body);
    }
    Some(Answer {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// A gzip body as far as it unpacks: one cut off at the size limit ends early,
/// and what came before the cut still counts.
fn unpack(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    let _ = GzDecoder::new(data).take(UNPACKED).read_to_end(&mut body);
    body
}

/// A chunked body joined, and whether its last, empty chunk was there.
fn dechunk(mut data: &[u8]) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    while let Some(line) = data.windows(2).position(|window| window == b"\r\n") {
        let size = String::from_utf8_lossy(&data[..line]);
        let Ok(size) = usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16)
        else {
            break;
        };
        if size == 0 {
            return (body, true);
        }
        let start = line + 2;
        // A size from the server: an absurd one must not overflow the bounds.
        let Some(end) = start.checked_add(size).filter(|end| *end <= data.len()) else {
            break;
        };
        body.extend_from_slice(&data[start..end]);
        data = data.get(end + 2..).unwrap_or_default();
    }
    (body, false)
}

#[cfg(test)]
mod tests;
