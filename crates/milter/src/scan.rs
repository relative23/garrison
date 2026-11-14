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
//!
//! What the scan could have seen but did not look at is another matter, and
//! never passes for a clean message: more packed data than it unpacks, a
//! file packed otherwise than by deflate, or time that ran out end as
//! [`Outcome::Incomplete`], and the filter's operator decides what such a
//! message gets.

use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::GeneralPurpose;
use base64::engine::{DecodePaddingMode, GeneralPurposeConfig};

mod marks;
mod unpack;

use marks::contains;
use unpack::Work;

/// A stretch of base64 shorter than this holds no document.
const SHORTEST: usize = 64;
/// Archives inside archives are opened this deep.
pub const DEPTH: usize = 3;

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

/// Why a scan could not look at all of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gap {
    /// Its archives hold more than the scan unpacks or reads.
    Budget,
    /// One packed file is larger than the scan unpacks of one.
    Truncated,
    /// A file is packed in a way the scan does not read.
    Method,
    /// The scan's time ran out.
    Deadline,
    /// The message is larger than what is scanned at all.
    Size,
}

impl Gap {
    /// The reason in words, for the log. It says nothing of the message.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Gap::Budget => "its archives hold more than the scan unpacks",
            Gap::Truncated => "a packed file in it is larger than the scan unpacks",
            Gap::Method => "an archive in it is packed in a way the scan does not read",
            Gap::Deadline => "the scan's time ran out",
            Gap::Size => "it is larger than the configured max_message_mib",
        }
    }
}

/// What a scan says of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Everything was looked at, and no document with macros is in it.
    Clean,
    /// The first document with macros in it.
    Macros(Found),
    /// No document with macros was seen, but not everything could be looked
    /// at: this is not a clean message.
    Incomplete(Gap),
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

/// What `message` carries, with all the time the scan needs.
#[must_use]
pub fn macros(message: &[u8]) -> Outcome {
    scan(message, None)
}

/// What `message` carries, so far as that is known at `until`: a scan that
/// is not done by then ends as [`Gap::Deadline`].
#[must_use]
pub fn macros_until(message: &[u8], until: Instant) -> Outcome {
    scan(message, Some(until))
}

fn scan(message: &[u8], until: Option<Instant>) -> Outcome {
    let mut work = Work::new(until);
    match (candidates(message, &mut work), work.gap) {
        (Some(found), _) => Outcome::Macros(found),
        (None, Some(gap)) => Outcome::Incomplete(gap),
        (None, None) => Outcome::Clean,
    }
}

/// The first document with macros in what `message` may be read as.
fn candidates(message: &[u8], work: &mut Work) -> Option<Found> {
    if let Some(found) = work.scanned(message, DEPTH) {
        return Some(found);
    }
    for stretch in stretches(message) {
        if let Some(found) = work.scanned(&stretch, DEPTH) {
            return Some(found);
        }
    }
    // Quoted-printable is undone last: it is how text travels, and rarely a file.
    if contains(message, b"=\n")
        || contains(message, b"=\r\n")
        || contains(message, b"=50=4B")
        || contains(message, b"=D0=CF")
    {
        return work.scanned(&unquoted(message), DEPTH);
    }
    None
}

#[cfg(test)]
mod bounds_tests;
#[cfg(test)]
mod incomplete_tests;
#[cfg(test)]
pub(crate) mod tests;
