//! One HTTP request, as a visitor would make it: name lookup through the
//! system, TLS validated against the system's trust store with the host name
//! as SNI. Only what the caller reads comes back: status, headers and a
//! bounded body, unpacked if the server sent it compressed. `garrison doctor`
//! asks the installation's public names with it, the collector the release
//! list, the notification channel and Stalwart's sign-in page. No redirect is
//! followed.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use flate2::read::GzDecoder;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const TIMEOUT: Duration = Duration::from_secs(8);
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

fn connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let targets = (host, port)
        .to_socket_addrs()
        .map_err(|_| format!("{host} does not resolve"))?;
    let mut last = format!("{host} does not resolve");
    for target in targets {
        match TcpStream::connect_timeout(&target, TIMEOUT) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(TIMEOUT))
                    .map_err(|error| error.to_string())?;
                stream
                    .set_write_timeout(Some(TIMEOUT))
                    .map_err(|error| error.to_string())?;
                return Ok(stream);
            }
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
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let stream = connect(host, port)?;
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
    stream.take(LIMIT).read_to_end(&mut data)?;
    Ok(data)
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
    let url = request.url;
    let (secure, host, port, path) = split(url)?;
    let data = if secure {
        let mut tls = secure_stream(&host, port, roots)?;
        match exchange(&mut tls, &host, &path, request) {
            Ok(data) => data,
            // Servers often close without close_notify; what arrived counts.
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Vec::new(),
            Err(error) => return Err(tls_error(&error)),
        }
    } else {
        let mut stream = connect(&host, port)?;
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
        body = dechunk(&body);
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

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(line) = data.windows(2).position(|window| window == b"\r\n") {
        let size = String::from_utf8_lossy(&data[..line]);
        let Ok(size) = usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16)
        else {
            break;
        };
        let start = line + 2;
        // A size from the server: an absurd one must not overflow the bounds.
        let Some(end) = start
            .checked_add(size)
            .filter(|end| size > 0 && *end <= data.len())
        else {
            break;
        };
        body.extend_from_slice(&data[start..end]);
        data = data.get(end + 2..).unwrap_or_default();
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_split_into_scheme_host_port_and_path() {
        assert_eq!(
            split("https://mail.example.org/metrics/prometheus").unwrap(),
            (
                true,
                "mail.example.org".into(),
                443,
                "/metrics/prometheus".into()
            )
        );
        assert_eq!(
            split("http://127.0.0.1:8080").unwrap(),
            (false, "127.0.0.1".into(), 8080, "/".into())
        );
        assert_eq!(split("http://[::1]:8080/a").unwrap().1, "::1");
        assert!(split("ftp://example.org").is_err());
        assert!(split("https://:443/").is_err());
    }

    #[test]
    fn the_origin_of_a_url() {
        assert_eq!(
            origin("https://stalwart.example.org/admin/"),
            "https://stalwart.example.org"
        );
        assert_eq!(
            origin("https://mail.example.org"),
            "https://mail.example.org"
        );
        assert_eq!(
            origin("http://127.0.0.1:8080/login?a=b"),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn answers_are_parsed_with_chunked_bodies() {
        let plain = parse(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno").unwrap();
        assert_eq!((plain.status, plain.body.as_str()), (404, "no"));
        let chunked = parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nStrict-Transport-Security: max-age=1\r\n\r\n\
              4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(chunked.body, "{\"a\":1}");
        assert_eq!(
            chunked.header("strict-transport-security"),
            Some("max-age=1")
        );
        assert!(parse(b"not http").is_none());
        // A chunk size near usize::MAX must neither overflow nor panic.
        let huge = parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nab\r\n0\r\n\r\n");
        assert_eq!(huge.unwrap().body, "");
    }

    #[test]
    fn a_compressed_body_is_unpacked_as_far_as_it_goes() {
        use std::io::Write as _;
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(b"<html>sign in</html>").unwrap();
        let packed = gzip.finish().unwrap();
        let answer = |body: &[u8]| {
            let mut data = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
            data.extend_from_slice(body);
            parse(&data).unwrap().body
        };
        assert_eq!(answer(&packed), "<html>sign in</html>");
        // Cut off, or no gzip at all: what unpacks, never a panic.
        assert!("<html>sign in</html>".starts_with(&answer(&packed[..packed.len() - 9])));
        assert_eq!(answer(b"plain text"), "");
    }

    #[test]
    fn a_post_sends_its_headers_and_its_body() {
        let server = garrison_testing::http::serve(vec![garrison_testing::http::answer(200, "{}")]);
        let request = Request {
            method: "POST",
            url: &format!("{}/topic?x=1", server.url),
            headers: &[
                ("Title", "Two checks failed"),
                ("Authorization", "Bearer token-1"),
                // Nothing that would start another header or line goes out.
                ("X-Bad\r\nInjected", "1"),
                ("X-Also-Bad", "1\r\nInjected: 2"),
            ],
            body: b"Backup job: failed",
        };
        assert_eq!(send(&request, &roots()).unwrap().status, 200);
        let sent = server.requests().remove(0);
        assert!(sent.starts_with("POST /topic?x=1 HTTP/1.1\r\n"), "{sent}");
        for line in [
            "Title: Two checks failed\r\n",
            "Authorization: Bearer token-1\r\n",
            "Content-Length: 18\r\n",
        ] {
            assert!(sent.contains(line), "{sent}");
        }
        assert!(!sent.contains("Injected"), "{sent}");
        assert!(sent.ends_with("\r\n\r\nBackup job: failed"), "{sent}");
    }

    #[test]
    fn random_answers_never_panic() {
        let mut noise = garrison_testing::noise::Noise::new(0x9e37_79b9_7f4a_7c15);
        let pieces: [&[u8]; 9] = [
            b"HTTP/1.1 ",
            b"200",
            b" OK\r\n",
            b"Transfer-Encoding: chunked\r\n",
            b"\r\n",
            b"ffffffff",
            b"\r\n\r\n",
            b"0\r\n",
            b"\xff\xfe",
        ];
        for _ in 0..20_000 {
            let mut data = Vec::new();
            for _ in 0..(noise.next_u64() % 12) {
                match pieces.get(noise.below(10)) {
                    Some(piece) => data.extend_from_slice(piece),
                    None => data.push(u8::try_from(noise.next_u64() % 256).unwrap()),
                }
            }
            let _ = parse(&data);
            let _ = split(&String::from_utf8_lossy(&data));
        }
    }
}
