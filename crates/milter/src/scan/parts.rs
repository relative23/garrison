//! Reading the message as a mail program does: its MIME parts, each decoded
//! by the transfer encoding its own headers declare, and uuencode blocks in
//! any body. A part the scan cannot decode — a declared encoding it does not
//! read, or a uuencode block that began and did not end — is a gap, not a
//! clean message.
//!
//! This is the little of MIME the scan needs and no more. It reads a part's
//! headers for its `Content-Transfer-Encoding` and, where the part is
//! multipart, for the `boundary` its `Content-Type` declares, and it splits
//! only on that declared boundary — never on any line that begins with `--`,
//! which a sender can write into the data, since `-` is outside the base64
//! alphabet. Whatever a conforming client would decode, the scan decodes and
//! scans as it scans a stretch. Work stays proportional to the message: each
//! part is decoded once, nesting is bounded by [`PARTS_DEPTH`], and the
//! scan's deadline and unpack budget bound the rest.

use super::stretches::{decode_symbols, is_symbol};
use super::unpack::Work;
use super::{DEPTH, Found, Gap, uu};

/// Multipart nesting and `message/rfc822` are followed this deep.
const PARTS_DEPTH: usize = 8;

/// What a part's `Content-Transfer-Encoding` tells the scan to do.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    /// Decode base64, ignoring anything outside its alphabet.
    Base64,
    /// Decode uuencode (one of its MIME names).
    Uuencode,
    /// Read elsewhere or kept as it is: quoted-printable, 7bit, 8bit, binary,
    /// or none declared.
    Plain,
    /// A value the scan does not decode: the part is a gap.
    Unknown,
}

/// Whether a body held a uuencode block, and whether it ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Uu {
    /// No block began in the body.
    None,
    /// A block began and ended.
    Whole,
    /// A block began and was cut short or went wrong.
    Cut,
}

impl Work {
    /// Scan every MIME part of the message, decoded as its headers declare,
    /// and the uuencode blocks in any body.
    pub(super) fn scanned_parts(&mut self, message: &[u8]) -> Option<Found> {
        self.walk_part(message, PARTS_DEPTH)
    }

    /// One part: a header block, then either the parts of a multipart, a
    /// nested message, or a leaf body decoded by its encoding.
    fn walk_part(&mut self, data: &[u8], depth: usize) -> Option<Found> {
        if self.late() {
            return None;
        }
        let (headers, body) = split_headers(data);
        if depth > 0 {
            if let Some(boundary) = multipart_boundary(headers) {
                for part in Segments::new(body, &boundary) {
                    if let Some(found) = self.walk_part(part, depth - 1) {
                        return Some(found);
                    }
                    if self.gap == Some(Gap::Deadline) {
                        return None;
                    }
                }
                return None;
            }
            if content_type_is(headers, b"message/rfc822") {
                return self.walk_part(body, depth - 1);
            }
        }
        self.scanned_leaf(headers, body)
    }

    /// A leaf part: its uuencode blocks, then the body decoded by every
    /// encoding its headers declare.
    fn scanned_leaf(&mut self, headers: &[u8], body: &[u8]) -> Option<Found> {
        let uu = match self.scanned_uu(body) {
            Ok(found) => return Some(found),
            Err(uu) => uu,
        };
        if uu == Uu::Cut {
            self.gap.get_or_insert(Gap::Encoding);
        }
        let encodings = encodings(headers);
        for encoding in &encodings {
            // Only base64 a sender broke up with characters outside the
            // alphabet is decoded here; plain base64 the stretch pass already
            // reads, and decoding it again would spend the budget twice.
            if *encoding == Encoding::Base64 && has_foreign_bytes(body) {
                let symbols = body.iter().filter(|byte| is_symbol(**byte)).count();
                if let Some(found) = self.scanned(&decode_symbols(body, symbols), DEPTH) {
                    return Some(found);
                }
            }
        }
        // A part the scan could not read: an unknown encoding, headers that
        // disagree and left nothing found, or a part that declared uuencode
        // and held no block.
        let unreadable = encodings.contains(&Encoding::Unknown)
            || encodings.len() > 1
            || (encodings.contains(&Encoding::Uuencode) && uu == Uu::None);
        if unreadable {
            self.gap.get_or_insert(Gap::Encoding);
        }
        None
    }

    /// Decode and scan the uuencode blocks in `body`. `Ok` is the first
    /// document found; `Err` says whether a block was there and whether it
    /// ended.
    fn scanned_uu(&mut self, body: &[u8]) -> Result<Found, Uu> {
        let mut at = 0;
        let mut seen = Uu::None;
        while let Some(begin) = uu::next_begin(body, at) {
            match uu::decode(&body[begin..]) {
                Some((decoded, whole, consumed)) => {
                    at = begin + consumed;
                    if let Some(found) = self.scanned(&decoded, DEPTH) {
                        return Ok(found);
                    }
                    if !whole {
                        return Err(Uu::Cut);
                    }
                    seen = Uu::Whole;
                }
                None => at = after(body, line_end(body, begin)),
            }
        }
        Err(seen)
    }
}

/// The header block and the body: everything before the first blank line,
/// and everything after it. A message with no blank line is all headers.
fn split_headers(data: &[u8]) -> (&[u8], &[u8]) {
    let mut at = 0;
    while at < data.len() {
        if data[at..].starts_with(b"\r\n\r\n") {
            return (&data[..at], &data[at + 4..]);
        }
        if data[at..].starts_with(b"\n\n") {
            return (&data[..at], &data[at + 2..]);
        }
        at += 1;
    }
    (data, &[])
}

/// Every value of the header `name` (lower case), each unfolded and with its
/// continuation lines joined.
fn header_values(headers: &[u8], name: &[u8]) -> Vec<Vec<u8>> {
    let mut values = Vec::new();
    let mut at = 0;
    while at < headers.len() {
        let end = line_end(headers, at);
        let line = trim_cr(&headers[at..end]);
        let mut next = after(headers, end);
        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            at = next; // A stray continuation line: it starts no header.
            continue;
        }
        let mut logical = line.to_vec();
        while next < headers.len() && matches!(headers[next], b' ' | b'\t') {
            let cont = line_end(headers, next);
            logical.push(b' ');
            logical.extend_from_slice(trim_cr(&headers[next..cont]));
            next = after(headers, cont);
        }
        if let Some(colon) = logical.iter().position(|byte| *byte == b':')
            && logical[..colon].trim_ascii().eq_ignore_ascii_case(name)
        {
            values.push(logical[colon + 1..].to_vec());
        }
        at = next;
    }
    values
}

/// Every transfer encoding the part's headers declare, in order and with
/// duplicates of one value removed.
fn encodings(headers: &[u8]) -> Vec<Encoding> {
    let mut found: Vec<Encoding> = Vec::new();
    for value in header_values(headers, b"content-transfer-encoding") {
        let token = first_token(&without_comments(&value)).to_ascii_lowercase();
        let encoding = match token.as_slice() {
            b"base64" => Encoding::Base64,
            b"x-uuencode" | b"uuencode" | b"x-uue" | b"uue" => Encoding::Uuencode,
            b"" | b"7bit" | b"8bit" | b"binary" | b"quoted-printable" => Encoding::Plain,
            _ => Encoding::Unknown,
        };
        if !found.contains(&encoding) {
            found.push(encoding);
        }
    }
    found
}

/// The boundary a multipart part declares, if its `Content-Type` is one.
fn multipart_boundary(headers: &[u8]) -> Option<Vec<u8>> {
    let content_type = header_values(headers, b"content-type").into_iter().next()?;
    let media = media_type(&content_type);
    if !media.starts_with(b"multipart/") {
        return None;
    }
    for parameter in content_type.split(|byte| *byte == b';').skip(1) {
        let parameter = parameter.trim_ascii();
        if let Some(equals) = parameter.iter().position(|byte| *byte == b'=')
            && parameter[..equals]
                .trim_ascii()
                .eq_ignore_ascii_case(b"boundary")
        {
            return Some(unquote(parameter[equals + 1..].trim_ascii()));
        }
    }
    None
}

/// Whether the part's `Content-Type` media type is `target` (lower case).
fn content_type_is(headers: &[u8], target: &[u8]) -> bool {
    header_values(headers, b"content-type")
        .into_iter()
        .next()
        .is_some_and(|content_type| media_type(&content_type) == target)
}

/// The media type of a `Content-Type` value, lower-cased, without parameters.
fn media_type(content_type: &[u8]) -> Vec<u8> {
    content_type
        .split(|byte| *byte == b';')
        .next()
        .unwrap_or(&[])
        .trim_ascii()
        .to_ascii_lowercase()
}

/// A value with its `(...)` comments removed; a comment may nest.
fn without_comments(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut depth = 0u32;
    for &byte in value {
        match byte {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(byte),
            _ => {}
        }
    }
    out
}

/// The first token of a value: the run of token characters after any white
/// space.
fn first_token(value: &[u8]) -> &[u8] {
    let value = value.trim_ascii_start();
    let end = value
        .iter()
        .position(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'-'))
        .unwrap_or(value.len());
    &value[..end]
}

/// A value with one layer of surrounding quotes removed.
fn unquote(value: &[u8]) -> Vec<u8> {
    if value.len() >= 2 && value[0] == b'"' && value[value.len() - 1] == b'"' {
        value[1..value.len() - 1].to_vec()
    } else {
        value.to_vec()
    }
}

pub(super) fn line_end(data: &[u8], from: usize) -> usize {
    data[from..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(data.len(), |at| from + at)
}

pub(super) fn after(data: &[u8], line_end: usize) -> usize {
    (line_end + 1).min(data.len())
}

pub(super) fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// The parts of a multipart body, between the lines that are its declared
/// boundary's delimiter. The preamble before the first delimiter and the
/// epilogue after the close are left out, as a mail program leaves them.
struct Segments<'a> {
    body: &'a [u8],
    boundary: &'a [u8],
    at: usize,
    opened: bool,
    done: bool,
}

impl<'a> Segments<'a> {
    fn new(body: &'a [u8], boundary: &'a [u8]) -> Self {
        Segments {
            body,
            boundary,
            at: 0,
            opened: false,
            done: false,
        }
    }

    /// Whether a line is this boundary's delimiter, and whether it closes.
    fn delimiter(&self, line: &[u8]) -> Option<bool> {
        let rest = trim_cr(line)
            .strip_prefix(b"--")?
            .strip_prefix(self.boundary)?;
        match rest.trim_ascii_end() {
            b"" => Some(false),
            b"--" => Some(true),
            _ => None,
        }
    }

    /// The next delimiter line at or after `from`: where it starts, where the
    /// line after it starts, and whether it closes.
    fn next_delimiter(&self, from: usize) -> Option<(usize, usize, bool)> {
        let mut at = from;
        while at < self.body.len() {
            let end = line_end(self.body, at);
            if let Some(closing) = self.delimiter(&self.body[at..end]) {
                return Some((at, after(self.body, end), closing));
            }
            at = after(self.body, end);
        }
        None
    }
}

impl<'a> Iterator for Segments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.done {
            return None;
        }
        if !self.opened {
            let (_, after_open, closing) = self.next_delimiter(self.at)?;
            self.at = after_open;
            self.opened = true;
            if closing {
                self.done = true;
                return None;
            }
        }
        let start = self.at;
        if let Some((delimiter, after_delimiter, closing)) = self.next_delimiter(self.at) {
            self.at = after_delimiter;
            self.done = closing;
            Some(&self.body[start..delimiter])
        } else {
            self.done = true;
            Some(&self.body[start..])
        }
    }
}

/// Whether a base64 body holds a byte that is neither a symbol, padding, nor
/// white space: the sign that a sender broke it up so the stretch pass, which
/// reads only lines of symbols and white space, would not have read it.
fn has_foreign_bytes(body: &[u8]) -> bool {
    body.iter()
        .any(|byte| !(is_symbol(*byte) || *byte == b'=' || byte.is_ascii_whitespace()))
}
