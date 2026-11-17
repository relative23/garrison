//! Every transfer encoding a conforming mail client would decode is a way
//! the scan reads the attachment. A document with macros answers `Macros`
//! (or `Incomplete`) however it is wrapped, never `Clean`; a document
//! without macros stays `Clean` in the same wrappings, so a fix against
//! evasion does not turn ordinary mail into "unscanned".
//!
//! What a conforming decoder reconstructs was measured with Python's `email`,
//! `quopri` and `base64` on this host (evidence under
//! `private/evidence/.../lane-milter/`). Encodings a conforming encoder would
//! not write for a MIME part, which only some lenient clients reconstruct,
//! are a documented limit and are checked apart, so the limit cannot drift
//! into a silent `Clean` unnoticed.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::tests::{compound, plain_document};
use super::*;
use crate::sample::document;

/// A macro document in its two shapes: a zip with `vbaProject.bin`, and a
/// compound file with a `_VBA_PROJECT` storage.
fn macro_documents() -> Vec<(&'static str, Vec<u8>, Found)> {
    vec![
        ("zip", document(), Found::Zipped),
        (
            "compound",
            compound(&["WordDocument", "Macros", "VBA", "_VBA_PROJECT"]),
            Found::Compound,
        ),
    ]
}

/// The same two shapes without a macro project.
fn clean_documents() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("zip", plain_document()),
        (
            "compound",
            compound(&["WordDocument", "SummaryInformation"]),
        ),
    ]
}

/// `=XX` for one byte, in upper or lower hexadecimal case.
fn push_escaped(body: &mut Vec<u8>, byte: u8, lower: bool) {
    let digits: &[u8; 16] = if lower {
        b"0123456789abcdef"
    } else {
        b"0123456789ABCDEF"
    };
    body.push(b'=');
    body.push(digits[usize::from(byte >> 4)]);
    body.push(digits[usize::from(byte & 0x0f)]);
}

/// A header before a body, so the wrapping looks like a part of a message.
fn with_header(cte: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!("Subject: x\r\nContent-Transfer-Encoding: {cte}\r\n\r\n").into_bytes();
    out.extend_from_slice(body);
    out.extend_from_slice(b"\r\n");
    out
}

/// A document as it stands, no transfer encoding at all.
fn raw(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

/// base64 as a mail program writes it: 76-column lines.
fn base64_standard(data: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(data);
    let mut body = Vec::new();
    for chunk in encoded.as_bytes().chunks(76) {
        body.extend_from_slice(chunk);
        body.extend_from_slice(b"\r\n");
    }
    with_header("base64", &body)
}

/// base64 with ASCII white space between the symbols of a line. RFC 2045
/// section 6.8 says a decoder ignores it, and one does (measured).
fn base64_interior_whitespace(data: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(data);
    let mut spaced = Vec::new();
    for (index, byte) in encoded.bytes().enumerate() {
        spaced.push(byte);
        if index % 8 == 7 {
            spaced.push(if index % 16 == 7 { b' ' } else { b'\t' });
        }
    }
    let mut body = Vec::new();
    for chunk in spaced.chunks(60) {
        body.extend_from_slice(chunk);
        body.extend_from_slice(b"\r\n");
    }
    with_header("base64", &body)
}

/// base64 whose lines are of unequal length, with a blank line in the
/// middle. A decoder reads over both (measured).
fn base64_uneven(data: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(data);
    let third = encoded.len() / 3;
    let mut body = Vec::new();
    body.extend_from_slice(&encoded.as_bytes()[..third]);
    body.extend_from_slice(b"\r\n\r\n");
    body.extend_from_slice(&encoded.as_bytes()[third..third * 2]);
    body.extend_from_slice(b"\n");
    body.extend_from_slice(&encoded.as_bytes()[third * 2..]);
    with_header("base64", &body)
}

/// Quoted-printable as an encoder writes it: `=XX` in upper case with soft
/// line breaks. This is the shape the scan already read.
fn qp_upper_softbreaks(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for (index, &byte) in data.iter().enumerate() {
        push_escaped(&mut body, byte, false);
        if index % 20 == 19 {
            body.extend_from_slice(b"=\r\n");
        }
    }
    with_header("quoted-printable", &body)
}

/// Quoted-printable on one physical line (no soft breaks), lower-case hex,
/// with printable ASCII left literal: the `PK` signature and the entry name
/// are not escaped. A conforming client decodes it to the document (the
/// F-01 shape).
fn qp_singleline_lower(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for &byte in data {
        if (0x21..=0x7e).contains(&byte) && byte != b'=' {
            body.push(byte);
        } else {
            push_escaped(&mut body, byte, true);
        }
    }
    with_header("quoted-printable", &body)
}

/// Quoted-printable where only the bytes a client must decode are escaped;
/// printable ASCII and spaces stay literal.
fn qp_partial(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for &byte in data {
        if ((0x21..=0x7e).contains(&byte) && byte != b'=') || byte == b' ' {
            body.push(byte);
        } else {
            push_escaped(&mut body, byte, false);
        }
    }
    with_header("quoted-printable", &body)
}

/// Quoted-printable soft breaks that carry transport padding: `=` then
/// spaces and tabs then the line's end, which RFC 2045 section 6.7 rule 3
/// strips before the soft break.
fn qp_transport_padding(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for (index, &byte) in data.iter().enumerate() {
        push_escaped(&mut body, byte, false);
        if index % 20 == 19 {
            body.extend_from_slice(b"=  \t \r\n");
        }
    }
    with_header("quoted-printable", &body)
}

/// An attachment that is itself a message with a base64 part. A
/// `message/rfc822` part is not re-encoded, so the inner base64 stands
/// literally in the outer bytes the filter scans.
fn rfc822_inner_base64(data: &[u8]) -> Vec<u8> {
    let mut out = b"Subject: fwd\r\nContent-Type: message/rfc822\r\n\r\n".to_vec();
    out.extend_from_slice(b"Subject: inner\r\nContent-Transfer-Encoding: base64\r\n\r\n");
    let encoded = STANDARD.encode(data);
    for chunk in encoded.as_bytes().chunks(76) {
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out
}

type Wrapping = (&'static str, fn(&[u8]) -> Vec<u8>);

/// Every wrapping a conforming client reconstructs to the original document.
const WRAPPINGS: &[Wrapping] = &[
    ("raw", raw),
    ("base64", base64_standard),
    ("base64 interior white space", base64_interior_whitespace),
    ("base64 uneven lines and a blank line", base64_uneven),
    (
        "quoted-printable upper case with soft breaks",
        qp_upper_softbreaks,
    ),
    ("quoted-printable one line lower case", qp_singleline_lower),
    ("quoted-printable partial", qp_partial),
    ("quoted-printable transport padding", qp_transport_padding),
    (
        "message/rfc822 with an inner base64 part",
        rfc822_inner_base64,
    ),
];

#[test]
fn a_macro_document_is_found_in_every_encoding_a_client_decodes() {
    for (document_name, data, found) in macro_documents() {
        for (wrapping, wrap) in WRAPPINGS {
            assert_eq!(
                macros(&wrap(&data)),
                Outcome::Macros(found),
                "macro {document_name} wrapped as {wrapping}"
            );
        }
    }
}

#[test]
fn a_clean_document_stays_clean_in_every_encoding() {
    for (document_name, data) in clean_documents() {
        for (wrapping, wrap) in WRAPPINGS {
            assert_eq!(
                macros(&wrap(&data)),
                Outcome::Clean,
                "clean {document_name} wrapped as {wrapping}"
            );
        }
    }
}

/// The table is not passing by accident: in every wrapping but the raw one,
/// a plain mark search of the bytes as they stand finds nothing (no valid
/// zip header, no compound-file signature in the clear), so the document is
/// found only because the scan decodes the wrapping first.
#[test]
fn the_wrappings_hide_the_document_from_a_plain_mark_search() {
    for (_, data, _) in macro_documents() {
        for (wrapping, wrap) in WRAPPINGS {
            if *wrapping == "raw" {
                continue;
            }
            assert!(
                marks::plain(&wrap(&data)).is_none(),
                "{wrapping} left the document to a plain mark search"
            );
        }
    }
}

/// A uuencoded body, built as the tool does: a length character before each
/// line, then groups of three bytes to four printable characters.
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

/// Encodings a conforming encoder would not write for a MIME part. Only a
/// lenient decoder reconstructs them, and a milter that does not parse MIME
/// cannot tell such a body from ordinary text without reading the part's
/// declared encoding. They are a named limit (configuration.md and the known
/// limits in security.md); a macro document so wrapped passes as clean, as
/// one in a password-protected archive does. This test holds that limit so a
/// change to it is noticed.
#[test]
fn encodings_outside_the_mime_set_are_a_documented_limit() {
    // base64 interrupted by a character outside its alphabet.
    let encoded = STANDARD.encode(document());
    let mut junk = Vec::new();
    for (index, byte) in encoded.bytes().enumerate() {
        junk.push(byte);
        if index % 20 == 19 {
            junk.push(b'!');
        }
    }
    assert_eq!(macros(&with_header("base64", &junk)), Outcome::Clean);
    // A uuencoded attachment (uuencode is not one of MIME's transfer
    // encodings).
    assert_eq!(
        macros(&with_header("x-uuencode", &uuencode(&document()))),
        Outcome::Clean
    );
}
