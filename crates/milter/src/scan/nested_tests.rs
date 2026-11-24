//! A body wrapped again in a transfer encoding is followed, to the depth zip
//! archives are, and no further. A message file attached as base64 whose own
//! attachment is base64 is two decodes to the reader and a real way documents
//! travel. The scan reads a decoded stream as a message again only where the
//! stream itself names an encoding (a `Content-Transfer-Encoding` header or a
//! `begin` line), so ordinary mail, whose decoded base64 is noise, is not.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::tests::{compound, plain_document};
use super::*;
use crate::sample::{archive, document};

fn macro_compound() -> Vec<u8> {
    compound(&["WordDocument", "Macros", "VBA", "_VBA_PROJECT"])
}

/// A message whose one part is `body` in base64.
fn base64_part(body: &[u8]) -> Vec<u8> {
    let mut message = b"Subject: x\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
    for chunk in STANDARD.encode(body).as_bytes().chunks(76) {
        message.extend_from_slice(chunk);
        message.extend_from_slice(b"\r\n");
    }
    message
}

/// `body` wrapped as a base64 part `levels` times over.
fn nest(body: &[u8], levels: usize) -> Vec<u8> {
    let mut message = body.to_vec();
    for _ in 0..levels {
        message = base64_part(&message);
    }
    message
}

/// A message whose one part is `body` in quoted-printable.
fn qp_part(body: &[u8]) -> Vec<u8> {
    let mut message = b"Subject: x\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n".to_vec();
    for (index, &byte) in body.iter().enumerate() {
        message.push(b'=');
        message.push(b"0123456789ABCDEF"[usize::from(byte >> 4)]);
        message.push(b"0123456789ABCDEF"[usize::from(byte & 0x0f)]);
        if index % 20 == 19 {
            message.extend_from_slice(b"=\r\n");
        }
    }
    message
}

/// A message whose one part is `body` as a uuencode block.
fn uu_part(body: &[u8]) -> Vec<u8> {
    let character = |value: u8| {
        let raw = (value & 0x3f) + 0x20;
        if raw == 0x20 { 0x60 } else { raw }
    };
    let mut out =
        b"Subject: x\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 a.docm\r\n".to_vec();
    for line in body.chunks(45) {
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

#[test]
fn a_message_file_attached_as_base64_is_opened_to_its_macro() {
    assert_eq!(
        macros(&nest(&document(), 2)),
        Outcome::Macros(Found::Zipped)
    );
    assert_eq!(
        macros(&nest(&macro_compound(), 2)),
        Outcome::Macros(Found::Compound)
    );
    assert_eq!(macros(&nest(&plain_document(), 2)), Outcome::Clean);
}

#[test]
fn nesting_is_followed_to_the_depth_and_no_further() {
    assert_eq!(
        macros(&nest(&document(), 3)),
        Outcome::Macros(Found::Zipped)
    );
    assert_eq!(macros(&nest(&plain_document(), 3)), Outcome::Clean);
    // One level deeper than the scan follows: a document may be there, so the
    // message is not clean.
    assert_eq!(
        macros(&nest(&document(), 4)),
        Outcome::Incomplete(Gap::Encoding)
    );
}

#[test]
fn a_message_file_in_a_zip_is_opened() {
    // Deflated, so the inner base64 is not in the clear: it is found only
    // because the unpacked entry is read as a message of its own.
    let zip = archive(&[("fwd.eml", &base64_part(&document()), true)]);
    assert_eq!(macros(&zip), Outcome::Macros(Found::Zipped));
    let clean = archive(&[("fwd.eml", &base64_part(&plain_document()), true)]);
    assert_eq!(macros(&clean), Outcome::Clean);
}

#[test]
fn encodings_mixed_across_levels_are_followed() {
    // quoted-printable inside base64.
    assert_eq!(
        macros(&base64_part(&qp_part(&document()))),
        Outcome::Macros(Found::Zipped)
    );
    // base64 inside quoted-printable.
    assert_eq!(
        macros(&qp_part(&base64_part(&document()))),
        Outcome::Macros(Found::Zipped)
    );
    // uuencode inside base64.
    assert_eq!(
        macros(&base64_part(&uu_part(&document()))),
        Outcome::Macros(Found::Zipped)
    );
}

#[test]
fn junk_in_the_inner_base64_does_not_hide_the_document() {
    let mut inner = b"Subject: x\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
    for (index, byte) in STANDARD.encode(document()).bytes().enumerate() {
        inner.push(byte);
        if index % 20 == 19 {
            inner.push(b'!');
        }
    }
    assert_eq!(macros(&base64_part(&inner)), Outcome::Macros(Found::Zipped));
}

/// A message as a mail program writes it, with `attachment` as a base64 part.
fn forwarded(attachment: &[u8], name: &str) -> Vec<u8> {
    let mut message = format!(
        "From: a@example.net\r\nSubject: Fwd: report\r\nMIME-Version: 1.0\r\n\
         DKIM-Signature: v=1; a=rsa-sha256; d=example.net; s=20230601; bh=AbCd0123=\r\n\
         Content-Type: multipart/mixed; boundary=\"b0\"\r\n\r\n--b0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\nSee the attachment.\r\n--b0\r\n\
         Content-Type: application/octet-stream; name=\"{name}\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n"
    )
    .into_bytes();
    for chunk in STANDARD.encode(attachment).as_bytes().chunks(76) {
        message.extend_from_slice(chunk);
        message.extend_from_slice(b"\r\n");
    }
    message.extend_from_slice(b"--b0--\r\n");
    message
}

#[test]
fn a_message_every_reading_gives_alike_is_read_once() {
    // Each way to read base64 gives the inner message, and so does the
    // message with its quoted-printable undone: read once, it fits the
    // budget, and the forwarded letter is clean.
    let inner = forwarded(&plain_document(), "letter.docx");
    assert_eq!(macros(&forwarded(&inner, "fwd.eml")), Outcome::Clean);
    let with_macros = forwarded(&document(), "invoice.docm");
    assert_eq!(
        macros(&forwarded(&with_macros, "fwd.eml")),
        Outcome::Macros(Found::Zipped)
    );
}
