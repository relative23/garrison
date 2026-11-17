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
//!   macros live in a storage whose directory names `_VBA_PROJECT`, in any
//!   case: the directory finds its names so.
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

mod base64_stream;
mod marks;
mod parts;
mod unpack;
mod uu;

use marks::contains;
use unpack::Work;

/// Archives inside archives are opened this deep.
pub const DEPTH: usize = 3;
/// What a scan holds of unpacked files at the most: one at each depth, in
/// a buffer that may hold twice what was unpacked into it.
pub(crate) const MOST_UNPACKED: usize = DEPTH * 2 * unpack::UNPACKED;

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
    /// A part declares a transfer encoding the scan does not decode, or a
    /// uuencode block that began and did not end.
    Encoding,
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
            Gap::Encoding => "a part is encoded in a way the scan does not read",
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

/// The message with its quoted-printable undone: `=XX` is a byte in either
/// hexadecimal case, and `=` at a line's end joins the lines. A transport
/// may pad an encoded line with space and tab before the break; RFC 2045
/// section 6.7 rule 3 has the decoder strip it, so `=` then white space then
/// the line's end is a soft break as well.
fn unquoted(message: &[u8]) -> Vec<u8> {
    let hex = |byte: u8| char::from(byte).to_digit(16);
    let mut plain = Vec::with_capacity(message.len());
    let mut at = 0;
    while at < message.len() {
        if message[at] == b'=' {
            // A soft line break: `=`, then any space or tab a transport
            // added, then the line's end. None of it reaches the output.
            let mut end = at + 1;
            while matches!(message.get(end), Some(b' ' | b'\t')) {
                end += 1;
            }
            match (message.get(end), message.get(end + 1)) {
                (Some(b'\r'), Some(b'\n')) => {
                    at = end + 2;
                    continue;
                }
                (Some(b'\n'), _) => {
                    at = end + 1;
                    continue;
                }
                _ => {}
            }
            // `=XX`: the high hexadecimal digit then the low, either case.
            if let (Some(high), Some(low)) = (message.get(at + 1), message.get(at + 2))
                && let (Some(high), Some(low)) = (hex(*high), hex(*low))
            {
                plain.push(u8::try_from(high * 16 + low).unwrap_or(b'='));
                at += 3;
                continue;
            }
        }
        plain.push(message[at]);
        at += 1;
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
    let mut work = Work::new(until, message.len());
    match (candidates(message, &mut work), work.gap) {
        (Some(found), _) => Outcome::Macros(found),
        (None, Some(gap)) => Outcome::Incomplete(gap),
        (None, None) => Outcome::Clean,
    }
}

/// The first document with macros in what `message` may be read as. No pass
/// reads where a part begins or ends, how deep it is, or how its headers are
/// written: structure may make an answer more exact, never more lenient.
fn candidates(message: &[u8], work: &mut Work) -> Option<Found> {
    // The message as it stands: a document in the clear, any encoding's bytes
    // that happen to be literal, the archives in them, and a message file in
    // an archive, which `scanned` reads as a message of its own.
    if let Some(found) = work.scanned(message, DEPTH) {
        return Some(found);
    }
    // The message's transfer encodings, undone over the whole of it.
    if let Some(found) = work.decode_encodings(message) {
        return Some(found);
    }
    // The one thing a header can still decide, and only to make the answer
    // stricter: a part that declares a transfer encoding the scan does not
    // decode is a message not scanned completely, not a clean one.
    work.flag_undecodable_encoding(message);
    None
}

impl Work {
    /// Undo the message's transfer encodings over the whole of it, reading no
    /// structure: the base64 on each of the four grids a run of symbols can
    /// sit on (so a base64 body anywhere comes out whole in one phase,
    /// whatever junk, boundary or header surrounds it), the quoted-printable,
    /// and the uuencode blocks. Each decoded stream is scanned for a document
    /// and, where it is itself a message with a nested encoding, read again.
    fn decode_encodings(&mut self, data: &[u8]) -> Option<Found> {
        let symbols = base64_stream::count(data);
        for phase in 0..base64_stream::PHASES {
            if self.late() {
                return None;
            }
            let stream = base64_stream::decode_phase(data, phase, symbols);
            if !self.may_decode(stream.len()) {
                return None;
            }
            if let Some(found) = self.scanned_deep(&stream) {
                return Some(found);
            }
        }
        if contains(data, b"=") {
            let undone = unquoted(data);
            if !self.may_decode(undone.len()) {
                return None;
            }
            if let Some(found) = self.scanned(&undone, DEPTH) {
                return Some(found);
            }
            // Read the result as a nested message only where undoing
            // quoted-printable truly decoded a body (it shrank by a quarter or
            // more, as `=XX` triplets become one byte). A message that only
            // carries a base64 body has little to undo, so its result is the
            // message itself; reading that again would read its own headers,
            // level after level.
            if undone.len() * 4 < data.len() * 3
                && let Some(found) = self.nested(&undone)
            {
                return Some(found);
            }
        }
        self.scanned_uuencoded(data)
    }

    /// Scan a decoded stream for a document (marks and archives), and, where
    /// it is itself a message with a nested transfer encoding, read that too.
    pub(super) fn scanned_deep(&mut self, stream: &[u8]) -> Option<Found> {
        if let Some(found) = self.scanned(stream, DEPTH) {
            return Some(found);
        }
        self.nested(stream)
    }

    /// Follow a nested transfer encoding, but only where `data` itself says it
    /// is there: a client decodes a body a second time only because the inner
    /// message's headers name a `Content-Transfer-Encoding` or a uuencode
    /// block begins. Noise does not hold that name by chance, so ordinary mail
    /// is not read again. Below the depth the scan follows, such a message is
    /// incomplete, never clean.
    pub(super) fn nested(&mut self, data: &[u8]) -> Option<Found> {
        if !declares_encoding(data) {
            return None;
        }
        if self.encodings == 0 {
            self.gap.get_or_insert(Gap::Encoding);
            return None;
        }
        self.encodings -= 1;
        let found = self.decode_encodings(data);
        self.encodings += 1;
        found
    }
}

/// Whether `data` is a message that names a transfer encoding of its own: the
/// header name in the clear (the only way a client would read it, any case),
/// or a uuencode block's `begin` line.
fn declares_encoding(data: &[u8]) -> bool {
    const NAME: &[u8] = b"content-transfer-encoding";
    data.windows(NAME.len())
        .any(|window| window[0].eq_ignore_ascii_case(&NAME[0]) && window.eq_ignore_ascii_case(NAME))
        || uu::next_begin(data, 0).is_some()
}

#[cfg(test)]
mod bounds_tests;
#[cfg(test)]
mod encoding_tests;
#[cfg(test)]
mod incomplete_tests;
#[cfg(test)]
mod nested_tests;
#[cfg(test)]
mod parts_tests;
#[cfg(test)]
mod structure_tests;
#[cfg(test)]
pub(crate) mod tests;
