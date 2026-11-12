//! Whether a message carries an Office document with macros.
//!
//! The scan does not trust the message's structure. A sender who wants a
//! document past a filter writes the MIME around it wrongly on purpose, in a
//! way mail programs forgive. So nothing here follows boundaries or part
//! headers: every stretch of base64 in the message is decoded, the message is
//! also read as it stands and with its quoted-printable undone, and each of
//! these is searched for what a document with macros cannot be without.
//!
//! - An old Word or Excel file (`.doc`, `.xls`) is a compound file, and its
//!   macros live in a storage whose directory names `_VBA_PROJECT`.
//! - A new one (`.docm`, `.xlsm`, `.pptm`, also when it is named `.docx`) is
//!   a zip archive whose macros are the file `vbaProject.bin`; the names of
//!   an archive's files are never compressed. By the format's specification
//!   that file is itself a compound file with a `_VBA_PROJECT`, so it is
//!   found under another name too.
//! - Word's "single file web page" carries them as an `ActiveMime` part.
//!
//! Text that only speaks of these names is no document: an archive's names
//! count where its headers have them, and `ActiveMime` where a file begins
//! with it.
//!
//! An archive inside the message is opened, and archives inside it, so far
//! as [`DEPTH`] goes. What the scan cannot see is said in the crate's
//! documentation: encrypted archives, Excel 4.0 macro sheets in old `.xls`
//! files and the macros of an old `.ppt` file among it.

use std::io::Read;

use base64::Engine;
use base64::engine::general_purpose::GeneralPurpose;
use base64::engine::{DecodePaddingMode, GeneralPurposeConfig};
use flate2::read::DeflateDecoder;

/// A compound file's first bytes.
const OLE: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
/// `_VBA_PROJECT` as a compound file's directory writes it: UTF-16LE.
const VBA_STORAGE: &[u8] = b"_\0V\0B\0A\0_\0P\0R\0O\0J\0E\0C\0T\0";
const ZIP_ENTRY: &[u8] = b"PK\x03\x04";
/// An entry of the directory at an archive's end, which is what Office reads.
const ZIP_LISTED: &[u8] = b"PK\x01\x02";
const ACTIVE_MIME: &[u8] = b"ActiveMime";
/// The names inside a zip archive that are macros, in lower case.
const ZIP_MACROS: [&[u8]; 2] = [b"vbaproject.bin", b"xl/macrosheets/"];
/// A stretch of base64 shorter than this holds no document.
const SHORTEST: usize = 64;
/// Archives inside archives are opened this deep.
pub const DEPTH: usize = 3;
/// One file of an archive is unpacked up to this size, all of a message's
/// together up to four times as much.
const UNPACKED: usize = 16 * 1024 * 1024;

/// base64 as mail programs read it: padding or none, and stray bits at the end.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// What kind of document with macros was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    /// An old Office file with a VBA project.
    Compound,
    /// A new Office file with `vbaProject.bin` or macro sheets.
    Zipped,
    /// A web page of Word's with an `ActiveMime` part.
    ActiveMime,
}

impl Found {
    /// The kind in words, for the log.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Found::Compound => "an Office document (compound file) with a VBA project",
            Found::Zipped => "an Office document (Open XML) with macros",
            Found::ActiveMime => "a web page with an ActiveMime part",
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_lowercase(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn number(data: &[u8], at: usize, bytes: usize) -> Option<usize> {
    let field = data.get(at..at + bytes)?;
    Some(
        field
            .iter()
            .rev()
            .fold(0, |sum, byte| (sum << 8) | usize::from(*byte)),
    )
}

/// Whether a zip header in `data` names a file that is macros: the header
/// before a file or the directory's entry for it, wherever one stands. A
/// name that is cut off counts as far as it goes.
fn names_macros(data: &[u8]) -> bool {
    let mut at = 0;
    while let Some(offset) = data[at..].windows(2).position(|window| window == b"PK") {
        let header = at + offset;
        at = header + 2;
        // Where the name's length stands, and where the name begins.
        let (length, name) = match data.get(header..header + 4) {
            Some(ZIP_ENTRY) => (26, 30),
            Some(ZIP_LISTED) => (28, 46),
            _ => continue,
        };
        let Some(length) = number(data, header + length, 2) else {
            continue;
        };
        let start = (header + name).min(data.len());
        let name = &data[start..(start + length).min(data.len())];
        if ZIP_MACROS
            .iter()
            .any(|macros| contains_lowercase(name, macros))
        {
            return true;
        }
    }
    false
}

/// Whether a file begins with `ActiveMime` somewhere in `data`: at its start
/// or a line's, and followed by the bytes of a file, not by a sentence.
fn active_mime(data: &[u8]) -> bool {
    let mut at = 0;
    while let Some(offset) = data[at..]
        .windows(ACTIVE_MIME.len())
        .position(|window| window == ACTIVE_MIME)
    {
        let found = at + offset;
        at = found + ACTIVE_MIME.len();
        let begins = found == 0 || data[found - 1] == b'\n';
        let binary = data[at..]
            .iter()
            .take(16)
            .any(|byte| *byte < 0x20 && !matches!(byte, b'\t' | b'\r' | b'\n'));
        if begins && binary {
            return true;
        }
    }
    false
}

/// What `data` shows without unpacking anything.
fn plain(data: &[u8]) -> Option<Found> {
    if contains(data, OLE) && contains(data, VBA_STORAGE) {
        return Some(Found::Compound);
    }
    if names_macros(data) {
        return Some(Found::Zipped);
    }
    active_mime(data).then_some(Found::ActiveMime)
}

/// The scan of one candidate: what it shows, and what the deflated files of
/// an archive in it show. `budget` is what may still be unpacked.
fn scanned(data: &[u8], depth: usize, budget: &mut usize) -> Option<Found> {
    if let Some(found) = plain(data) {
        return Some(found);
    }
    if depth == 0 {
        return None;
    }
    // Every local file header, wherever the archive begins: a file that is
    // stored was searched above, one that is deflated is unpacked.
    let mut at = 0;
    while let Some(offset) = data[at..].windows(4).position(|window| window == ZIP_ENTRY) {
        let header = at + offset;
        at = header + 4;
        let (Some(method), Some(packed), Some(name), Some(extra)) = (
            number(data, header + 8, 2),
            number(data, header + 18, 4),
            number(data, header + 26, 2),
            number(data, header + 28, 2),
        ) else {
            break;
        };
        if method != 8 || *budget == 0 {
            continue;
        }
        let start = header + 30 + name + extra;
        let Some(rest) = data.get(start..) else {
            continue;
        };
        // The header's size is zero where the archive was written as a
        // stream; the deflated data ends itself either way.
        let packed = if packed == 0 {
            rest.len()
        } else {
            packed.min(rest.len())
        };
        let limit = (*budget).min(UNPACKED);
        let mut unpacked = Vec::new();
        let _ = DeflateDecoder::new(&rest[..packed])
            .take(limit as u64)
            .read_to_end(&mut unpacked);
        *budget = budget.saturating_sub(unpacked.len());
        if let Some(found) = scanned(&unpacked, depth - 1, budget) {
            return Some(found);
        }
    }
    None
}

fn is_base64(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

/// Each stretch of lines that are base64 and nothing else, decoded. Empty
/// lines belong to a stretch: a mail program reads over them.
fn stretches(message: &[u8]) -> Vec<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    let mut close = |run: &mut Vec<u8>| {
        if run.len() >= SHORTEST {
            // What does not decode as a whole decodes up to its last whole group.
            let whole = run.len() - run.len() % 4;
            if let Ok(data) = LENIENT
                .decode(&*run)
                .or_else(|_| LENIENT.decode(&run[..whole]))
            {
                decoded.push(data);
            }
        }
        run.clear();
    };
    for line in message.split(|byte| *byte == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() {
            continue;
        }
        if line.iter().all(|byte| is_base64(*byte)) {
            // Padding ends a stretch's data; what follows it is not read.
            run.extend(line.iter().copied().filter(|byte| *byte != b'='));
        } else {
            close(&mut run);
        }
    }
    close(&mut run);
    decoded
}

/// The message with its quoted-printable undone: `=XX` is a byte, `=` at a
/// line's end joins the lines.
fn unquoted(message: &[u8]) -> Vec<u8> {
    let mut plain = Vec::with_capacity(message.len());
    let mut at = 0;
    while at < message.len() {
        let hex = |byte: u8| char::from(byte).to_digit(16);
        match (message[at], message.get(at + 1), message.get(at + 2)) {
            (b'=', Some(b'\r'), Some(b'\n')) => at += 3,
            (b'=', Some(b'\n'), _) => at += 2,
            (b'=', Some(high), Some(low)) if hex(*high).is_some() && hex(*low).is_some() => {
                let value = hex(*high).unwrap_or(0) * 16 + hex(*low).unwrap_or(0);
                plain.push(u8::try_from(value).unwrap_or(b'='));
                at += 3;
            }
            (byte, _, _) => {
                plain.push(byte);
                at += 1;
            }
        }
    }
    plain
}

/// The first document with macros in `message`, if it carries one.
#[must_use]
pub fn macros(message: &[u8]) -> Option<Found> {
    let mut budget = 4 * UNPACKED;
    if let Some(found) = scanned(message, DEPTH, &mut budget) {
        return Some(found);
    }
    for stretch in stretches(message) {
        if let Some(found) = scanned(&stretch, DEPTH, &mut budget) {
            return Some(found);
        }
    }
    // Quoted-printable is undone last: it is how text travels, and rarely a file.
    if contains(message, b"=\n")
        || contains(message, b"=\r\n")
        || contains(message, b"=50=4B")
        || contains(message, b"=D0=CF")
    {
        return scanned(&unquoted(message), DEPTH, &mut budget);
    }
    None
}

#[cfg(test)]
pub(crate) mod tests;
