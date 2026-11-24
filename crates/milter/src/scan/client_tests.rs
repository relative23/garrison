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

/// How a uuencode block is written.
struct Uu<'a> {
    /// The headers before it, without the empty line.
    headers: &'a str,
    begin: &'a str,
    /// The values 1 to 26 as the lower-case letters `(c - 0x20) & 0x3f`
    /// gives them too.
    alias: bool,
    /// Bytes to a line; the format's own writers take 45.
    line: usize,
    end: bool,
    line_end: &'a str,
}

const USUAL: Uu<'static> = Uu {
    headers: "Subject: x",
    begin: "begin 644 a.docm",
    alias: false,
    line: 45,
    end: true,
    line_end: "\r\n",
};
const DECLARED: &str = "Subject: x\r\nContent-Transfer-Encoding: x-uuencode";

fn uuencoded(body: &[u8], how: &Uu<'_>) -> Vec<u8> {
    let character = |value: u8| match value & 0x3f {
        0 => 0x60,
        value @ 1..=26 if how.alias => 0x60 + value,
        value => value + 0x20,
    };
    let mut out = Vec::new();
    for text in [how.headers, "", how.begin] {
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(how.line_end.as_bytes());
    }
    for line in body.chunks(how.line) {
        out.push(u8::try_from(line.len()).unwrap_or(0) + 0x20);
        for group in line.chunks(3) {
            let first = group[0];
            let second = group.get(1).copied().unwrap_or(0);
            let third = group.get(2).copied().unwrap_or(0);
            out.push(character(first >> 2));
            out.push(character((first << 4) | (second >> 4)));
            out.push(character((second << 2) | (third >> 6)));
            out.push(character(third));
        }
        out.extend_from_slice(how.line_end.as_bytes());
    }
    if how.end {
        out.extend_from_slice(format!("`{0}end{0}", how.line_end).as_bytes());
    }
    out
}

// A mail program's uuencode reader takes each character as
// `(c - 0x20) & 0x3f` without asking what it is, a line of up to 63 bytes,
// and a line's end of any kind; under a declared uuencode it takes any line
// that starts with `begin ` for a block's first.
#[test]
fn uuencode_is_read_as_a_mail_program_reads_it() {
    let ways = [
        ("the usual", USUAL),
        (
            "aliased",
            Uu {
                alias: true,
                ..USUAL
            },
        ),
        (
            "aliased, not ended",
            Uu {
                alias: true,
                end: false,
                ..USUAL
            },
        ),
        ("lines of 60", Uu { line: 60, ..USUAL }),
        (
            "CR alone",
            Uu {
                line_end: "\r",
                ..USUAL
            },
        ),
        (
            "LF alone",
            Uu {
                line_end: "\n",
                ..USUAL
            },
        ),
        (
            "declared, a mode of six digits",
            Uu {
                headers: DECLARED,
                begin: "begin 100644 a.docm",
                ..USUAL
            },
        ),
        (
            "declared, two spaces",
            Uu {
                headers: DECLARED,
                begin: "begin  644 a.docm",
                ..USUAL
            },
        ),
        (
            "declared, no mode",
            Uu {
                headers: DECLARED,
                begin: "begin a.docm",
                ..USUAL
            },
        ),
        (
            "declared, aliased",
            Uu {
                headers: DECLARED,
                alias: true,
                ..USUAL
            },
        ),
        (
            "no name",
            Uu {
                begin: "begin 644 ",
                ..USUAL
            },
        ),
    ];
    for (way, how) in &ways {
        for (name, body, found) in macro_documents() {
            assert_eq!(
                macros(&uuencoded(&body, how)),
                Outcome::Macros(found),
                "{name}, {way}"
            );
        }
        for (name, body) in clean_documents() {
            assert_eq!(
                macros(&uuencoded(&body, how)),
                Outcome::Clean,
                "{name}, {way}"
            );
        }
    }
}

#[test]
fn a_uuencode_block_that_was_not_read_whole_leaves_a_gap() {
    // A block as a writer of the format makes it, without its `end`, was
    // cut: what it lacks was not read.
    let cut = Uu {
        end: false,
        ..USUAL
    };
    for (name, body) in clean_documents() {
        assert_eq!(
            macros(&uuencoded(&body, &cut)),
            Outcome::Incomplete(Gap::Encoding),
            "{name}"
        );
    }
    // A line of one character stands for up to 63 zeros: a block that gives
    // more than the message is long is not read to its end.
    let mut zeros = b"Subject: x\r\n\r\nbegin 644 a\r\n".to_vec();
    zeros.extend(std::iter::repeat_n(&b"_\r\n"[..], 1000).flatten());
    assert_eq!(macros(&zeros), Outcome::Incomplete(Gap::Encoding));
}

#[test]
fn text_that_says_begin_is_no_uuencode_block() {
    for text in [
        "Subject: x\r\n\r\nWe begin 2 weeks earlier\r\nif possible, please send it\r\n",
        "Subject: x\r\n\r\nbegin 2 weeks earlier\r\nif possible, please send it\r\n",
        "Subject: x\r\n\r\nbegin the work\r\nas soon as you can\r\n",
        "Subject: x\r\n\r\nbegin 644 notes.txt\r\nThis line is no data: its length would be 52.\r\n",
    ] {
        assert_eq!(macros(text.as_bytes()), Outcome::Clean, "{text}");
    }
    // Under a declared uuencode a mail program decodes what follows `begin `
    // whatever it is, and so does the scan: it holds nothing.
    let declared = format!("{DECLARED}\r\n\r\nbegin the work\r\nThis line is no data.\r\n");
    assert_eq!(macros(declared.as_bytes()), Outcome::Clean);
}
