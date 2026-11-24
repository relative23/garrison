//! The two readers that do not fit the whole-message base64 and
//! quoted-printable passes, both free of a message's structure:
//!
//! - uuencode, wherever a `begin <mode> <name>` block stands in the message
//!   (a part declaring it is read the same way, since the block is in its
//!   body). A block begun and not ended leaves a gap.
//! - the one thing a header may still decide, and only to make the answer
//!   stricter: a `Content-Transfer-Encoding` line, at any line's start, whose
//!   value the scan does not decode means the message was not scanned
//!   completely, and so does the first line of a `yEnc` or a `BinHex` block. No
//!   boundary and no part structure is read.
//!

use super::unpack::Work;
use super::{Found, Gap, uu};

impl Work {
    /// Decode and scan every uuencode block in the message. A block that
    /// was not read whole leaves [`Gap::Encoding`]; the first document found
    /// ends the search.
    pub(super) fn scanned_uuencoded(&mut self, message: &[u8]) -> Option<Found> {
        let declared = content_transfer_encodings(message)
            .iter()
            .any(|value| is_uuencode(value));
        let mut at = 0;
        while let Some(begin) = uu::next_begin(message, at, declared) {
            // No block gives more than the message is long.
            let block = uu::decode(&message[begin..], declared, message.len());
            at = begin + block.length;
            if !self.may_decode(block.bytes.len()) {
                return None;
            }
            if let Some(found) = self.scanned_deep(&block.bytes) {
                return Some(found);
            }
            if !block.whole {
                self.gap.get_or_insert(Gap::Encoding);
            }
        }
        None
    }

    /// If any `Content-Transfer-Encoding` line declares a value the scan does
    /// not decode, or a block begins in an encoding it does not decode, the
    /// message was not scanned completely.
    pub(super) fn flag_undecodable_encoding(&mut self, message: &[u8]) {
        let declared = content_transfer_encodings(message)
            .iter()
            .any(|value| !decodable(value));
        let begun = UNREAD.iter().any(|opening| {
            memchr::memmem::find_iter(message, opening)
                .any(|at| at == 0 || matches!(message[at - 1], b'\n' | b'\r'))
        });
        if declared || begun {
            self.gap.get_or_insert(Gap::Encoding);
        }
    }
}

/// What opens a block in an encoding the scan does not decode, at a line's
/// start: `yEnc` and `BinHex` 4.0. A mail program may take either from a body
/// that no header describes.
const UNREAD: [&[u8]; 2] = [b"=ybegin ", b"(This file must be converted with BinHex"];

/// The token of a transfer-encoding value, in lower case.
fn token(value: &[u8]) -> Vec<u8> {
    first_token(&without_comments(value)).to_ascii_lowercase()
}

/// Whether a transfer-encoding value declares uuencode, in any of the four
/// spellings mail programs take.
fn is_uuencode(value: &[u8]) -> bool {
    matches!(
        token(value).as_slice(),
        b"x-uuencode" | b"uuencode" | b"x-uue" | b"uue"
    )
}

/// Whether a transfer-encoding value is one the scan decodes (base64 and
/// quoted-printable over the whole message, uuencode by its block, and the
/// encodings that keep the bytes as they are). An empty value is none
/// declared, which is 7bit.
fn decodable(value: &[u8]) -> bool {
    is_uuencode(value)
        || matches!(
            token(value).as_slice(),
            b"" | b"7bit" | b"8bit" | b"binary" | b"base64" | b"quoted-printable"
        )
}

/// Every `Content-Transfer-Encoding` value in the message, at any line's
/// start, unfolded and with its continuation lines joined. The whole message
/// is read: a value declared anywhere, in any part, counts.
fn content_transfer_encodings(message: &[u8]) -> Vec<Vec<u8>> {
    let name = b"content-transfer-encoding";
    let mut values = Vec::new();
    // The lines that begin with the name, found by its first `-`.
    for dash in memchr::memchr_iter(b'-', message) {
        let Some(at) = dash.checked_sub(7) else {
            continue;
        };
        let begins = message
            .get(at..at + name.len())
            .is_some_and(|found| found.eq_ignore_ascii_case(name));
        if !begins || (at > 0 && !matches!(message[at - 1], b'\n' | b'\r')) {
            continue;
        }
        let end = line_end(message, at);
        let mut next = after(message, end);
        let mut logical = trim_cr(&message[at..end]).to_vec();
        while next < message.len() && matches!(message[next], b' ' | b'\t') {
            let cont = line_end(message, next);
            logical.push(b' ');
            logical.extend_from_slice(trim_cr(&message[next..cont]));
            next = after(message, cont);
        }
        if let Some(colon) = logical.iter().position(|byte| *byte == b':')
            && logical[..colon].trim_ascii().eq_ignore_ascii_case(name)
        {
            values.push(logical[colon + 1..].to_vec());
        }
    }
    values
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

pub(super) fn line_end(data: &[u8], from: usize) -> usize {
    memchr::memchr(b'\n', &data[from..]).map_or(data.len(), |at| from + at)
}

pub(super) fn after(data: &[u8], line_end: usize) -> usize {
    (line_end + 1).min(data.len())
}

pub(super) fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}
