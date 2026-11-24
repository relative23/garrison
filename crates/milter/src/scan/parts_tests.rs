//! The MIME part reader against a sender who writes the headers on purpose to
//! mislead it, and against ordinary mail that must stay clean. A document is
//! found whichever way its encoding header is written; a part the scan cannot
//! decode is Incomplete, never a silent clean; and prose that merely looks
//! like an encoding is left alone.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::tests::plain_document;
use super::*;
use crate::sample::document;

/// The base64 of `data` with a `!` (outside the alphabet) after every
/// twentieth symbol: a conforming decoder ignores it (RFC 2045 section 6.8).
fn base64_junk(data: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(data);
    let mut body = Vec::new();
    for (index, byte) in encoded.bytes().enumerate() {
        body.push(byte);
        if index % 20 == 19 {
            body.push(b'!');
        }
    }
    body
}

/// A uuencoded begin/end block of `data`.
fn uuencode(data: &[u8]) -> Vec<u8> {
    let character = |value: u8| {
        let raw = (value & 0x3f) + 0x20;
        if raw == 0x20 { 0x60 } else { raw }
    };
    let mut out = b"begin 644 a.docm\r\n".to_vec();
    for line in data.chunks(45) {
        out.push(character(u8::try_from(line.len()).unwrap_or(0)));
        for group in line.chunks(3) {
            let first = group[0];
            let second = group.get(1).copied().unwrap_or(0);
            let third = group.get(2).copied().unwrap_or(0);
            out.push(character(first >> 2));
            out.push(character(((first << 4) | (second >> 4)) & 0x3f));
            out.push(character(((second << 2) | (third >> 6)) & 0x3f));
            out.push(character(third & 0x3f));
        }
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"`\r\nend\r\n");
    out
}

/// yEnc, which no mail program the project knows decodes: a named limit.
fn yencode(data: &[u8]) -> Vec<u8> {
    let mut out = format!("=ybegin line=128 size={} name=a.docm\r\n", data.len()).into_bytes();
    let mut column = 0;
    for &byte in data {
        let encoded = byte.wrapping_add(42);
        if matches!(encoded, 0x00 | 0x0a | 0x0d | 0x3d) {
            out.push(b'=');
            out.push(encoded.wrapping_add(64));
            column += 2;
        } else {
            out.push(encoded);
            column += 1;
        }
        if column >= 128 {
            out.extend_from_slice(b"\r\n");
            column = 0;
        }
    }
    out.extend_from_slice(format!("\r\n=yend size={}\r\n", data.len()).as_bytes());
    out
}

#[test]
fn a_document_is_read_however_its_encoding_header_is_written() {
    let bodies = [
        // Another case.
        b"Subject: x\r\nCONTENT-transfer-Encoding: BASE64\r\n\r\n".to_vec(),
        // Folded onto a continuation line.
        b"Subject: x\r\nContent-Transfer-Encoding:\r\n base64\r\n\r\n".to_vec(),
        // Followed by a comment.
        b"Subject: x\r\nContent-Transfer-Encoding: base64 (RFC 2045)\r\n\r\n".to_vec(),
    ];
    for mut message in bodies {
        message.extend_from_slice(&base64_junk(&document()));
        assert_eq!(macros(&message), Outcome::Macros(Found::Zipped));
    }
}

#[test]
fn two_disagreeing_encodings_do_not_hide_a_document() {
    // The scan reads the body every way it can regardless of the headers, so
    // two headers that disagree hide nothing: the base64 stream holds the
    // document whichever header a client believed.
    let mut hiding =
        b"Content-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
    hiding.extend_from_slice(&base64_junk(&document()));
    assert_eq!(macros(&hiding), Outcome::Macros(Found::Zipped));
    // Both values are ones the scan decodes, so a clean body stays clean: the
    // disagreement alone does not make it incomplete.
    let mut clean =
        b"Content-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: 7bit\r\n\r\n".to_vec();
    clean.extend_from_slice(&base64_junk(&plain_document()));
    assert_eq!(macros(&clean), Outcome::Clean);
}

#[test]
fn a_part_in_an_encoding_the_scan_cannot_read_is_incomplete() {
    // A clean body under a transfer encoding the scan does not decode: it
    // cannot be read, so the message is not a clean one.
    let mut unknown = b"Content-Transfer-Encoding: x-custom\r\n\r\n".to_vec();
    unknown.extend_from_slice(&base64_junk(&plain_document()));
    assert_eq!(macros(&unknown), Outcome::Incomplete(Gap::Encoding));
    // The scan reads base64 wherever it stands, so a macro document is found
    // even under an unknown encoding: structure never makes the answer more
    // lenient, only stricter.
    let mut macro_doc = b"Content-Transfer-Encoding: x-custom\r\n\r\n".to_vec();
    macro_doc.extend_from_slice(&base64_junk(&document()));
    assert_eq!(macros(&macro_doc), Outcome::Macros(Found::Zipped));
    // The encodings that keep the bytes as they are do not make a clean
    // message incomplete.
    for cte in ["7bit", "8bit", "binary", "base64", "quoted-printable"] {
        let mut message = format!("Content-Transfer-Encoding: {cte}\r\n\r\n").into_bytes();
        message.extend_from_slice(&STANDARD.encode(plain_document()).into_bytes());
        assert_eq!(macros(&message), Outcome::Clean, "{cte}");
    }
}

#[test]
fn a_uuencode_block_cut_short_is_incomplete() {
    // Ninety bytes that are not a document, uuencoded, with the end cut off.
    let filler: Vec<u8> = (0..90u8).collect();
    let whole = uuencode(&filler);
    let cut_at = whole
        .windows(3)
        .position(|window| window == b"`\r\n")
        .unwrap();
    let mut message = b"Content-Type: text/plain\r\n\r\n".to_vec();
    message.extend_from_slice(&whole[..cut_at]);
    assert_eq!(macros(&message), Outcome::Incomplete(Gap::Encoding));
    // The same block whole is clean: it holds no macro.
    let mut ok = b"Content-Type: text/plain\r\n\r\n".to_vec();
    ok.extend_from_slice(&whole);
    assert_eq!(macros(&ok), Outcome::Clean);
}

#[test]
fn prose_that_resembles_an_encoding_stays_clean() {
    // "begin" at a line's start, but no octal mode and no uuencode line
    // after it; words that look a little like base64; punctuation throughout.
    let prose = b"Subject: Trip\r\nContent-Type: text/plain\r\n\r\n\
        begin the trip tomorrow, please.\r\n\
        begin 644 notes\r\n\
        Dear team, this is a short update, nothing attached.\r\n\
        VGhpcyBsb29rcyBhIGxpdHRsZQ, but has punctuation.\r\n\
        Regards.\r\n";
    assert_eq!(macros(prose), Outcome::Clean);
}

#[test]
fn a_block_in_an_encoding_the_scan_does_not_read_is_incomplete() {
    // A mail program takes a yEnc block from a body no header describes, and
    // may take a BinHex one: the scan decodes neither, so it did not read
    // the message completely, whatever the block holds.
    for body in [document(), plain_document()] {
        let mut yenc = b"Subject: x\r\n\r\n".to_vec();
        yenc.extend_from_slice(&yencode(&body));
        assert_eq!(macros(&yenc), Outcome::Incomplete(Gap::Encoding));
    }
    let binhex = b"Subject: x\r\n\r\n(This file must be converted with BinHex 4.0)\r\n\r\n\
        :$f*TEQKPH#jdH(3!9%9B9&4iG(3!N!3`!!!!!$!!!!!!:\r\n";
    assert_eq!(macros(binhex), Outcome::Incomplete(Gap::Encoding));
    // Text that speaks of them holds no block.
    let prose = b"Subject: x\r\n\r\nA yEnc block starts with =ybegin line=128, and a\r\n\
        BinHex file says (This file must be converted with BinHex 4.0) first.\r\n";
    assert_eq!(macros(prose), Outcome::Clean);
}
