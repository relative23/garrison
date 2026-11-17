//! What an answer says: its status, headers and body, a chunked body joined
//! and a compressed one unpacked, and whether it holds what its request
//! needs.

use std::io::Read;

use flate2::read::GzDecoder;

use super::Needs;

/// The most a compressed body may unpack to.
const UNPACKED: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    headers: Vec<(String, String)>,
    pub body: String,
    /// Why the body is not all that the server sent, where it is not: the
    /// answer is longer than the client reads, or its body unpacks to more.
    /// A caller that reads the body decides whether what came before the
    /// cut is of use.
    pub cut: Option<String>,
}

impl Answer {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Whether `data` holds what `needs` asks of an answer: its whole head, and
/// for the whole answer a body as long as `Content-Length` says or with the
/// last chunk of a chunked one. An answer that gives no length ends with its
/// connection, and so is never known to be whole.
pub(super) fn enough(data: &[u8], needs: Needs) -> bool {
    let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    if needs == Needs::Head {
        return true;
    }
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

/// Status line, headers and body; a chunked body is joined.
pub(super) fn parse(data: &[u8]) -> Option<Answer> {
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
    let mut cut = None;
    if packed {
        let more;
        (body, more) = unpack(&body);
        cut = more.then(|| {
            format!(
                "its body unpacks to more than the {} MiB that are read",
                UNPACKED / 1024 / 1024
            )
        });
    }
    Some(Answer {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
        cut,
    })
}

/// A gzip body as far as it unpacks, and whether it unpacks to more than
/// the size limit: one cut off ends early, and what came before the cut
/// still counts.
fn unpack(data: &[u8]) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    // One byte past the limit tells a body that ends there from a longer one.
    let _ = GzDecoder::new(data)
        .take(UNPACKED + 1)
        .read_to_end(&mut body);
    let most = usize::try_from(UNPACKED).unwrap_or(usize::MAX);
    let more = body.len() > most;
    body.truncate(most);
    (body, more)
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
