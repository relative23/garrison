//! Whether the scan finds a document must not depend on where it believes a
//! part begins or ends, how deep it is, or how its headers are written. Each
//! macro case below hides the document from the raw, stretch-free sight by
//! breaking the base64 with a character outside its alphabet, then wraps it
//! in a structure the scan does not parse; the four-phase base64 pass finds
//! it all the same. The clean cases are ordinary mail that must stay clean.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::tests::{compound, plain_document};
use super::*;
use crate::sample::document;

/// The base64 of `data` with a `!` after every twentieth symbol, so the raw
/// and stretch-free sight and quoted-printable passes cannot read it; only
/// decoding the base64 stream does.
fn junk(data: &[u8]) -> Vec<u8> {
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

/// A macro document behind each structure trick is found; the same trick
/// around a clean document stays clean.
fn macro_zip() -> Vec<u8> {
    document()
}

fn macro_compound() -> Vec<u8> {
    compound(&["WordDocument", "Macros", "VBA", "_VBA_PROJECT"])
}

#[test]
fn a_quoted_boundary_with_a_special_character_does_not_hide_the_document() {
    // milter1-R1: boundary="a;b"; a structural parser that split on ';' would
    // mis-read the boundary and never split the parts.
    let mut message = b"Content-Type: multipart/mixed; boundary=\"a;b\"\r\n\r\n--a;b\r\n\
          Content-Transfer-Encoding: base64\r\n\r\n"
        .to_vec();
    message.extend_from_slice(&junk(&macro_zip()));
    message.extend_from_slice(b"\r\n--a;b--\r\n");
    assert_eq!(macros(&message), Outcome::Macros(Found::Zipped));
}

#[test]
fn an_rfc_2231_boundary_does_not_hide_the_document() {
    // milter1-R2: a split (boundary*0/*1) and an extended (boundary*=) value.
    for header in [
        b"Content-Type: multipart/mixed; boundary*0=\"aa\"; boundary*1=\"bb\"\r\n".as_slice(),
        b"Content-Type: multipart/mixed; boundary*=us-ascii''abc\r\n",
    ] {
        let mut message = header.to_vec();
        message.extend_from_slice(b"\r\n--aabb\r\nContent-Transfer-Encoding: base64\r\n\r\n");
        message.extend_from_slice(&junk(&macro_compound()));
        message.extend_from_slice(b"\r\n--aabb--\r\n");
        assert_eq!(macros(&message), Outcome::Macros(Found::Compound));
    }
}

#[test]
fn nesting_past_any_depth_does_not_hide_the_document() {
    // milter1-R3: nine multiparts, the innermost part junk-base64.
    let mut inner = b"Content-Transfer-Encoding: base64\r\n\r\n".to_vec();
    inner.extend_from_slice(&junk(&macro_zip()));
    for level in 0..9 {
        let boundary = format!("b{level}");
        let mut outer = format!(
            "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\n"
        )
        .into_bytes();
        outer.extend_from_slice(&inner);
        outer.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        inner = outer;
    }
    assert_eq!(macros(&inner), Outcome::Macros(Found::Zipped));
}

#[test]
fn boundary_like_and_header_like_lines_in_the_data_do_not_matter() {
    // A line in the data that looks like a boundary, and lines that look like
    // a part's headers and blank line: none is read, the document is found.
    let mut message = b"Content-Type: multipart/mixed; boundary=\"real\"\r\n\r\n".to_vec();
    message.extend_from_slice(b"--notreal\r\nContent-Type: text/plain\r\n\r\n");
    message.extend_from_slice(b"--real\r\nContent-Transfer-Encoding: base64\r\n\r\n");
    message.extend_from_slice(&junk(&macro_zip()));
    message.extend_from_slice(b"\r\n--real--\r\n");
    assert_eq!(macros(&message), Outcome::Macros(Found::Zipped));
}

#[test]
fn odd_separators_and_a_padded_blank_line_do_not_hide_the_document() {
    let body = junk(&macro_zip());
    // A "blank" line that holds a space before the body.
    let mut padded = b"Content-Transfer-Encoding: base64 \r\n \r\n".to_vec();
    padded.extend_from_slice(&body);
    assert_eq!(macros(&padded), Outcome::Macros(Found::Zipped));
    // LF-only and CR-only line ends between the base64 lines.
    for separator in [b"\n".as_slice(), b"\r".as_slice()] {
        let mut message = b"Content-Transfer-Encoding: base64\n\n".to_vec();
        for chunk in body.chunks(40) {
            message.extend_from_slice(chunk);
            message.extend_from_slice(separator);
        }
        assert_eq!(
            macros(&message),
            Outcome::Macros(Found::Zipped),
            "{separator:?}"
        );
    }
}

#[test]
fn two_content_type_headers_and_no_boundary_do_not_hide_the_document() {
    let mut two = b"Content-Type: text/plain\r\nContent-Type: multipart/mixed; boundary=b\r\n\
                    Content-Transfer-Encoding: base64\r\n\r\n"
        .to_vec();
    two.extend_from_slice(&junk(&macro_zip()));
    assert_eq!(macros(&two), Outcome::Macros(Found::Zipped));
    // multipart declared with no boundary parameter at all.
    let mut none =
        b"Content-Type: multipart/mixed\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
    none.extend_from_slice(&junk(&macro_zip()));
    assert_eq!(macros(&none), Outcome::Macros(Found::Zipped));
}

#[test]
fn the_document_in_a_preamble_or_an_epilogue_is_found() {
    // A conforming client ignores the preamble and epilogue; the scan reads
    // the base64 wherever it stands, which is stricter, never more lenient.
    let body = junk(&macro_zip());
    let mut preamble = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n".to_vec();
    preamble.extend_from_slice(&body);
    preamble.extend_from_slice(b"\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n");
    assert_eq!(macros(&preamble), Outcome::Macros(Found::Zipped));
    let mut epilogue =
        b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n"
            .to_vec();
    epilogue.extend_from_slice(&body);
    assert_eq!(macros(&epilogue), Outcome::Macros(Found::Zipped));
}

#[test]
fn a_compound_file_is_found_at_any_offset() {
    // Noise before the signature: the mark search reads it anywhere.
    let noise: Vec<u8> = (0..5_000u32)
        .flat_map(|value| value.wrapping_mul(2_654_435_761).to_le_bytes())
        .collect();
    let mut data = noise;
    data.extend_from_slice(&macro_compound());
    assert_eq!(macros(&data), Outcome::Macros(Found::Compound));
}

#[test]
fn a_clean_document_behind_the_structure_tricks_stays_clean() {
    let body = junk(&plain_document());
    let mut quoted = b"Content-Type: multipart/mixed; boundary=\"a;b\"\r\n\r\n--a;b\r\n\
                       Content-Transfer-Encoding: base64\r\n\r\n"
        .to_vec();
    quoted.extend_from_slice(&body);
    quoted.extend_from_slice(b"\r\n--a;b--\r\n");
    assert_eq!(macros(&quoted), Outcome::Clean);
}

#[test]
fn ordinary_mail_stays_clean() {
    // A long English text, with the letters "PK" and the word "begin".
    let prose = b"Subject: Plans for the quarter\r\nContent-Type: text/plain\r\n\r\n\
        Dear team,\r\n\r\nLet us begin with the good news. The PK gauge in the north plant \
        held through the heat wave, and the backlog is down by a third since April. \
        I have attached nothing to this note; the figures are in the shared folder. \
        Please read them before we begin the review on Thursday, and bring questions. \
        Thank you all for the steady work through a difficult month.\r\n\r\nWarm regards,\r\nA.\r\n";
    assert_eq!(macros(prose), Outcome::Clean);
    // A forwarded message, a calendar part and a delivery status notification,
    // all 7bit, each in its own multipart.
    let forwarded = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
        Content-Type: message/rfc822\r\n\r\nFrom: x@example.net\r\nSubject: Fwd\r\n\
        Content-Type: text/plain\r\n\r\nThe meeting moved to noon. See you then.\r\n--b--\r\n";
    assert_eq!(macros(forwarded), Outcome::Clean);
    let calendar = b"Content-Type: text/calendar\r\n\r\nBEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
        BEGIN:VEVENT\r\nSUMMARY:Review\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    assert_eq!(macros(calendar), Outcome::Clean);
    let dsn =
        b"Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mail.example.net\r\n\
        \r\nFinal-Recipient: rfc822; nobody@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n";
    assert_eq!(macros(dsn), Outcome::Clean);
}

#[test]
fn an_s_mime_signature_part_stays_clean() {
    // A base64 blob under a signature CTE that is not a document: decoding it
    // on every phase finds no macro, and base64 is a decodable encoding, so
    // there is no gap.
    let blob: Vec<u8> = (0..4_000u32)
        .flat_map(|value| value.wrapping_mul(2_246_822_519).to_le_bytes())
        .collect();
    let mut message = b"Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n\
          Content-Transfer-Encoding: base64\r\n\r\n"
        .to_vec();
    for chunk in STANDARD.encode(&blob).as_bytes().chunks(76) {
        message.extend_from_slice(chunk);
        message.extend_from_slice(b"\r\n");
    }
    assert_eq!(macros(&message), Outcome::Clean);
}

#[test]
fn base64_without_an_encoding_header_is_decoded_all_the_same() {
    // A client would not decode base64 that no header declares, so missing it
    // is no bypass; but the scan decodes the stream regardless, which is
    // stricter. A clean such body stays clean.
    let mut clean = b"Subject: x\r\n\r\n".to_vec();
    for chunk in STANDARD.encode(plain_document()).as_bytes().chunks(76) {
        clean.extend_from_slice(chunk);
        clean.extend_from_slice(b"\r\n");
    }
    assert_eq!(macros(&clean), Outcome::Clean);
}
