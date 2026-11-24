//! The scan reads an encoding as the mail programs do that read it most
//! freely, not only as its standard says: a sender writes for the program
//! that will open the message. Each case here is one such reading, taken
//! from a mail program's own decoder, with a document that has macros and
//! one that has none.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::tests::{compound, plain_document};
use super::*;
use crate::sample::document;

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

fn clean_documents() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("zip", plain_document()),
        (
            "compound",
            compound(&["WordDocument", "SummaryInformation"]),
        ),
    ]
}

/// A part with `text` as its body, in lines of 76 characters.
fn part(encoding: &str, text: &[u8]) -> Vec<u8> {
    let mut message =
        format!("Subject: x\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n").into_bytes();
    for line in text.chunks(76) {
        message.extend_from_slice(line);
        message.extend_from_slice(b"\r\n");
    }
    message
}

/// `body` in base64, `size` bytes at a time, each chunk padded by itself.
fn padded_chunks(body: &[u8], size: usize) -> Vec<u8> {
    let mut text = Vec::new();
    for chunk in body.chunks(size) {
        text.extend_from_slice(STANDARD.encode(chunk).as_bytes());
    }
    part("base64", &text)
}

// A mail program that reads base64 four characters at a time, `=` among
// them, decodes a padded group and goes on with the next; a writer that
// encodes a file piece by piece makes such a body.
#[test]
fn base64_in_padded_chunks_is_read_as_a_mail_program_reads_it() {
    for size in [1, 2, 4, 5, 7, 57, 100, 1000] {
        for (name, body, found) in macro_documents() {
            assert_eq!(
                macros(&padded_chunks(&body, size)),
                Outcome::Macros(found),
                "{name} in chunks of {size}"
            );
        }
    }
    // Pieces as a writer makes them. In pieces of a byte or two every other
    // `=` stands before two symbols, which reads as quoted-printable too,
    // and what that reading makes of a clean document is not held here.
    for size in [57, 100, 1000] {
        for (name, body) in clean_documents() {
            assert_eq!(
                macros(&padded_chunks(&body, size)),
                Outcome::Clean,
                "{name} in chunks of {size}"
            );
        }
    }
}

/// `inner`, a message, as the quoted-printable part of another: one in
/// `every` of its body's letters and digits is written `=XX`, or has a
/// `=20` put before it where `space` is set.
fn quoted_sparsely(inner: &[u8], every: usize, space: bool) -> Vec<u8> {
    let body = inner
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(0, |at| at + 4);
    let mut out = b"Subject: forwarded\r\nContent-Type: message/rfc822\r\n\
        Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        .to_vec();
    out.extend_from_slice(&inner[..body]);
    let mut seen = 0;
    for &byte in &inner[body..] {
        if byte.is_ascii_alphanumeric() {
            seen += 1;
        }
        match byte {
            b'=' => out.extend_from_slice(b"=3D"),
            _ if byte.is_ascii_alphanumeric() && seen % every == 0 && space => {
                out.extend_from_slice(b"=20");
                out.push(byte);
            }
            _ if byte.is_ascii_alphanumeric() && seen % every == 0 => {
                out.extend_from_slice(format!("={byte:02X}").as_bytes());
            }
            _ => out.push(byte),
        }
    }
    out
}

// A mail program undoes the quoted-printable of a message it was sent as a
// part, and then decodes that message's base64. One `=XX` in the base64 is
// two symbols until it is undone, so the base64 reads only after that.
#[test]
fn a_few_triplets_in_a_quoted_printable_wrapper_do_not_hide_the_base64() {
    for every in [3, 8, 20, 200, 2000] {
        for space in [false, true] {
            for (name, body, found) in macro_documents() {
                let inner = part("base64", STANDARD.encode(&body).as_bytes());
                assert_eq!(
                    macros(&quoted_sparsely(&inner, every, space)),
                    Outcome::Macros(found),
                    "{name}, one in {every}, space {space}"
                );
            }
            for (name, body) in clean_documents() {
                let inner = part("base64", STANDARD.encode(&body).as_bytes());
                assert_eq!(
                    macros(&quoted_sparsely(&inner, every, space)),
                    Outcome::Clean,
                    "{name}, one in {every}, space {space}"
                );
            }
        }
    }
}

// A triplet in the header block stands in no body, so it has nothing read
// again: the selector of a signature (`s=20…`) is in nearly every message.
#[test]
fn a_triplet_among_the_headers_has_nothing_read_again() {
    let message = b"DKIM-Signature: v=1; s=20230601; bh=AbCd;\r\n t=1763373600\r\n\
        Subject: x\r\n\r\nA line of text.\r\n";
    assert_eq!(unquoted(message).1, 0);
    let body = b"Subject: x\r\n\r\nwidth=3D600\r\n";
    assert_eq!(unquoted(body).1, 1);
    // What ends the header block for some reader ends it here.
    for early in [
        &b"Subject: x\r\n \r\ns=20\r\n"[..],
        b"Subject: x\ns=20\n",
        b"Subject: x\rno header s=20\r",
        b"s=20\r\n",
        b" s=20: x\r\n",
        b"Sub ject: s=20\r\n",
    ] {
        assert_eq!(unquoted(early).1, 1, "{}", String::from_utf8_lossy(early));
    }
}
