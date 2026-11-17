//! HTTP as the stand-ins of this test read and write it: one request on a
//! connection, and an answer that closes it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

/// One HTTP request as it arrived.
pub(super) struct Request {
    pub(super) method: String,
    pub(super) path: String,
    headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
}

impl Request {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The next request on `stream`, or none where the client closed it.
pub(super) fn read_request(stream: &TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next()?.to_owned(), parts.next()?.to_owned());
    let mut headers = Vec::new();
    let mut length = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        let (name, value) = (name.trim().to_owned(), value.trim().to_owned());
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().ok()?;
        }
        headers.push((name, value));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

/// An answer that closes the connection.
pub(super) fn answer(stream: &mut TcpStream, status: u16, media: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status} Relayed\r\nContent-Type: {media}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}
